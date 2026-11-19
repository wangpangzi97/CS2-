// Package radarsrv 是 CS2 雷达的解码会话层。
//
// 职责：把「握手公钥 + 挖到的 X25519 私钥 + 原始 UDP 包」变成「玩家坐标画面」。
// 具体链路：
//
//	共享密钥推导（X25519，确定）
//	  → 加解密方案搜索（KDF/AEAD/nonce/偏移 候选枚举 + 自动打分）
//	  → netmessage 流解析
//	  → 槽位跟踪 → Snapshot
//
// Production uses this package only in cmd/radarserver behind SecureHandler.
// The collector does not link it; legacy Handler/raw diagnostic routes are not
// production entry points. Raw packet/key/plaintext diagnostic persistence is
// retired for ordinary diagnostics. A separate default-off restricted-replay job
// can save bounded complete s2c game messages only with private operator consent.
package radarsrv

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"sort"
	"strings"
	"sync"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/cs2snp"
	"local/cs2-radar/internal/entitycodec"
	"local/cs2-radar/internal/handshake"
	"local/cs2-radar/internal/mapdata"
	"local/cs2-radar/internal/perfstat"
	"local/cs2-radar/internal/restrictedreplay"
	"local/cs2-radar/internal/uplink"
)

// Config 是解码会话的参数。零值不可用，请用 DefaultConfig() 起步。
type Config struct {
	// Nil by default; a separately consented one-session forensic job, not ordinary diagnostics.
	RestrictedReplay *restrictedreplay.Capture
	// MaxFrames 是每个方向最多保留多少帧用于探测。
	MaxFrames int
	// MinFrames 是触发方案搜索所需的最少帧数。
	MinFrames int
	// MaxOffset 是密文在载荷中的起始偏移搜索上界。
	MaxOffset int
	// PlayerTTL 是目标多久没更新就从画面消失。
	PlayerTTL time.Duration
	// MaxSlots 是最多跟踪多少个目标。
	MaxSlots int
	// MaxSessions 是最多保留多少个会话；超出时淘汰最久未更新的。
	//
	// 会话表必须有上限：每个会话最多留 MaxFrames 帧（默认 2000 × ~1KB），
	// 会话名由客户端给，不设上限就是一条内存放大路径。
	MaxSessions int
	// DebugSlots is retained for source compatibility and is ignored (no raw-position logs).
	DebugSlots bool

	// MapName 是**手动指定**的地图名（de_dust2 / dust2 / 炙热沙城 都认）。
	//
	// 存在的理由：`svc_ServerInfo` 还没解出来，`map_name` 拿不到。这时如果
	// 用户明确知道自己打的是哪张图，让它直接生效，比等协议解析现实得多。
	// 优先级：ServerInfo（未来）> MapName（手动）> 坐标反推。
	MapName string
	// MapImageDir 是外部底图目录，按 `<map_id>/overview.png` 放官方贴图。
	//
	// 目录为空或文件不存在时退回内嵌的「数据轮廓图」，并且 Snapshot 里
	// 会如实写 `image_kind=data-outline` + 「不是官方贴图」。
	MapImageDir string
	// MapRegistry 允许调用方注入现成的注册表（测试用）。
	// 为 nil 时 NewStore 自己建一个。
	MapRegistry *mapdata.Registry
}

// DefaultConfig 是命令行默认值对应的配置。
func DefaultConfig() Config {
	return Config{
		MaxFrames: 2000,
		MinFrames: 8,
		// 密文起点要搜到 7 以上：真实 netchan 帧头是
		// [0]类型 + [1..4]连接ID + [5..6]包序号，密文从第 7 字节开始。
		// 原来只搜 0..4，等于把正确答案排除在候选空间之外。
		MaxOffset:   8,
		PlayerTTL:   10 * time.Second,
		MaxSlots:    64,
		MaxSessions: 64,
	}
}

// Session 是一个会话的解码状态。
type Session struct {
	replay                                               *restrictedreplay.Capture
	pipeline                                             numericPipeline
	pixelView                                            *pixelState // private per-session drawing identifiers; never raw Snapshot JSON
	perfIngest, perfProcess, perfCycleWait, perfSnapshot perfstat.Timer
	entityTTL                                            time.Duration
	entityDecoder                                        *entitycodec.Decoder
	entityLogAt                                          time.Time
	entityLogStage                                       uint8
	pendingEntityMetadata                                []entityMetadata
	pendingEntityBytes                                   int
	pendingEntityFault                                   string
	pendingEntitySignon                                  bool
	cycleMu                                              sync.Mutex
	mu                                                   sync.Mutex

	id         string
	serverPub  []byte
	clientPriv []byte
	// gns 是 SteamNetworkingSockets 直连握手的全部密钥材料。
	// 齐了就直接走 GNS 的 HKDF 派生（确定解），不再枚举候选。
	gns *cs2crypto.GNSHandshake

	c2s [][]byte
	s2c [][]byte

	// 每个方向已经从缓冲区头部丢掉的帧数。
	//
	// 帧缓冲有上限（Config.MaxFrames），超出时丢最旧的。而 nonce 用的是
	// **发送方包计数器**，不是缓冲区下标；丢了 k 帧之后，缓冲区第 0 帧对应的
	// 计数器是 k。这两个计数器就是用来把"缓冲区下标"还原成"绝对帧序号"的。
	c2sDropped int
	s2cDropped int

	// GNS 派生是"近 200 组变体 × 最多 64 帧 GCM"的固定开销（约 3~4 ms）。
	// 每次 Process 都跑一遍纯属浪费，用时间戳节流；失败现场只 dump 一次，
	// 否则每来一批包就落一个新 json。
	lastGNS     time.Time
	gnsDiagDone bool

	// plainWant / plainBuf / plainDone 是「明文落地」三件套。
	//
	// 为什么需要：2026-10-19 已确认 GCM 解密 100% 正确（派生 IV 与内存 IV
	// 12 字节逐字节相等，帧帧认证通过），但解出来的明文**既不是字节对齐的
	// cmd/size 流、也不是位打包（LSB/MSB 都试过）的 cmd/size 流、也不是单个
	// 或长度前缀的 protobuf**，说明 CS2 在 netchan 之前还有一层封装。
	//
	// 这一层只靠 8 帧推不出来：手上那 8 帧来自同一条广播，前缀完全一样，
	// 没有变化量可对比。所以要攒几十帧**连续**明文落地，拿回去离线比对
	// 前缀里哪几个字节随包递增、哪几个字节是长度。
	plainWant bool
	plainBuf  []string
	plainDone bool
	plainDir  string

	// plainBin / plainBinTotal 是「全量明文二进制落盘」。
	//
	// 🔴 2026-10-19 16:07 现场暴露的问题：那一局解出 3251 帧，
	// 但 `plainDumpTarget = 128` 只落了**前 128 条**，离线手上只有
	// 142 KB。而内层封装至少要看到「signon 结束 → 进局」的完整过渡
	// （实测 24526 字节处熵从 6.8 跳到 7.1），142 KB 里那一段虽然覆盖了，
	// 但后面进局后的真实实体消息一条都没有 —— 没法确认封装是不是两套。
	//
	// 所以另开一路：s2c 明文**全部**收，按 `[u32le len][bytes]` 落二进制。
	// 不用 hex json 是因为 3251 帧 hex 后约 7.5 MB，而二进制只要 3.7 MB。
	plainBin      [][]byte
	plainBinTotal int
	plainBinFiles int
	// gnsDropHist 是「拿到握手材料那一刻」缓冲区里各收方 connID 的分布。
	//
	// 存在的理由：帧缓冲区在材料到达时会被清成只剩本连接的帧，如果清完
	// 所剩无几，就再也看不出被丢掉的是什么了（09:07 那次就是 dump 到
	// 清空后的 1 帧，什么也证明不了）。统计值在清空之前抓，保真。
	gnsDropHist map[string]int

	// gnsSendIV / gnsRecvIV 是从目标进程 conn 对象里直接读出来的两把 IV。
	//
	// 它们的作用不是"拿来解帧"，而是**给 KDF 定标**：
	// `FinishCryptoHandshake` 里是 `add qword [rsi+0x19f0], rax` —— 就地累加，
	// 所以只有低 8 字节随包前移，**高 4 字节整局不变**。
	// 于是「派生出的 SendIV 高 4 字节 == gnsSendIV 高 4 字节」是一个 32 位精确
	// 判据，能在 1152 个变体里一次定死正确的那一组，完全不用等帧能不能解开。
	//
	// KDF 已经卡了十几轮，缺的就是这种"不依赖帧"的判据。
	gnsSendIV []byte
	gnsRecvIV []byte

	// snpMu 保护下面这一整组 SNP 解码状态。
	//
	// decode() 的既有结构是「锁内领帧 → 锁外处理」，所以处理阶段本身是并发的。
	// 而 SNP 分帧器/流拼接器/消息切分器都是有状态的，必须串行。
	snpMu sync.Mutex

	// snp 是 SNP 线格式的分帧器（每方向一个，通道与相对偏移都按方向独立）。
	snpS2C *cs2snp.Parser
	snpC2S *cs2snp.Parser
	// 🔴 每个方向必须有**独立**的可靠流与消息切分器。
	//
	// SNP 的流位置、通道、消息号全部按方向独立。早期实现只用一个
	// relStream/msgSplit，并且在方向切换时整体 Reset —— 只要 s2c/c2s 的帧交替
	// 解出来，可靠流就会被反复清空，netchan 永远攒不起来。
	// 现场表现正是 `netchan=332 已切=0` 从头到尾一动不动。
	relStreamS2C *cs2snp.Stream
	relStreamC2S *cs2snp.Stream
	// msgSplit 从可靠流里剥掉「可靠消息头」，交出消息数据。
	msgSplitS2C *cs2snp.MsgSplit
	msgSplitC2S *cs2snp.MsgSplit

	// 🔴 加解密方案必须**按方向各存一套**。
	//
	// GNS 的一次派生同时给出两个方向：
	//   - s2c（客户端收到的包）用 RecvKey / RecvIV 解；
	//   - c2s（客户端发出的包）用 SendKey / SendIV 解。
	//
	// 早期实现只挑一个方向装一套方案，而且方案一装上就再也不重跑
	// （`runProbe` 见到 scheme 非空直接 return）。于是探测时哪边帧多就永久
	// 只解哪边 —— 13:24 那次现场日志从头到尾只有 `方向=c2s`，s2c 一条没解，
	// 服务端下发的实体数据全部丢掉。这就是「雷达无效果」在这一层的真因。
	schemeS2C *cs2crypto.Scheme
	schemeC2S *cs2crypto.Scheme
	// stS2C / stC2S 是每个方向自己的 SNP 诊断计数与增量游标。
	//
	// 两个方向的包号、流位置、消息号完全独立，混在一起统计只会得到
	// 「包数翻倍、坏帧率被稀释」这种没意义的数字。
	stS2C dirStats
	stC2S dirStats

	// netchan 是 s2c 可靠消息数据按流序拼接出来的 CS2 netchan 字节流。
	// 只收 s2c：雷达要的是服务端下发的实体数据，c2s 混进来只会污染流。
	netchan []byte
	// netchanParsed 记录 netchan 里已经成功解析并喂给解码器的字节数。
	netchanParsed int
	netchanDump   bool
	netchanProbed bool
	netchanWarned bool
	relDump       bool

	// 🔴 msgFramed 是**带边界**的可靠消息转储：每条消息 `u32le 长度 + 载荷`。
	//
	// netchan 只是把载荷首尾相接，边界信息（SNP 消息链本来就有的）被丢掉了。
	// 而内层封装的定案恰恰依赖「每条消息从哪开始、多长」—— 253 KB 的拼接流
	// 里找 `01` 只能靠猜，有了边界就能逐条对齐统计。
	msgFramed  []byte
	msgCount   int
	msgHeadLog bool
	// msgDumpAt 是「上一次落盘时的 msgCount」。
	//
	// 🔴 原来这里是一个 bool，`msgCount >= 64` 时落一次盘。2026-10-19 14:14 现场
	// 因此只拿到前 147 条 —— 而那 147 条**全是 signon**：120 条 99 字节心跳
	// （96 字节恒定，只有末 3 字节的 tick 在涨）+ 12 条 17~30 KB 的预缓存字符串表
	// （`animation/anims/world/knife/...`、`_glock/idle` 这类），一条实体数据都没有。
	// 结果「雷达没目标」被当成解码器的错，实际上是**样本里本来就没有实体**。
	// 现在改成每 msgDumpEvery 条落一次盘并清空缓冲，整局都能拿到。
	msgDumpAt int
	// 消息分类统计：键 = flags<<8 | 载荷首字节。
	msgKinds map[uint16]int
	// gnsMsgCmds / gnsMsgTotal / gnsMsgPb 是位级解析的统计（硬规则 223）。
	//
	// 2026-10-19 16:30 现场定案之后，netmessage 是靠 ReadUBitVar + ReadVarInt32
	// 从每条可靠消息里解出来的。这三个数用来回答一个问题：
	// **「解出来的 cmd 是否收敛」** —— 收敛说明分帧对了，发散说明还在错位区。
	gnsMsgCmds map[uint32]int
	// gnsMsgBytes 是「cmd → 累计 body 字节数」，用来按**字节量**排 cmd。
	//
	// 按条数排的话完美平台 UI（cmd=207）永远霸榜，实体快照被挤到十名之外，
	// 于是「这局有没有实体消息」这个问题永远看不见答案。
	gnsMsgBytes map[uint32]int
	gnsMsgTotal int
	gnsMsgPb    int
	// gnsMsgUnparsed 是「首字节不是 0x01、走不了位级解析」的载荷条数。
	gnsMsgUnparsed int
	// gnsPlatHTML / gnsPlatHTMLBytes 是完美平台 HTML 注入（eventid=226）的
	// 条数与字节数。它占 s2c 载荷约 90%，已从解码路径上跳过（硬规则 245）。
	gnsPlatHTML      int
	gnsPlatHTMLBytes int
	// gnsEventIDs 是**真实**游戏事件按 eventid 的条数（已剔除平台 HTML）。
	// 下一轮要认 player_death / player_team 就从这里下手 —— 队伍信息只能从
	// 游戏事件拿，因为本版本没有 svc_PacketEntities。
	gnsEventIDs map[uint64]int
	// msgBitpacked 是「载荷不是 protobuf」的消息数（实体 delta 这类位打包块）。
	// 它和 msgCount 的比例直接说明内层还剩多少活要干。
	msgBitpacked int
	// gnsStreamSkips / gnsStreamSkipBytes 是「可靠流空洞等不到补齐、被强制跳过」
	// 的次数与字节数（见 cs2snp.Stream.SkipStale）。
	//
	// 这两个数非零就说明**抓包漏了包**：SNP 自己会重传，等 5 秒还补不上，
	// 只能是我们的抓包链路把它丢了（白名单、缓冲溢出、网卡）。
	gnsStreamSkips     int
	gnsStreamSkipBytes int64
	// msgHeads 缓存前 msgHeadMax 条消息的 (长度, 头 16 字节)，用于一次性打日志。
	msgHeads []msgHead

	// gnsPos 是「声源实体索引 → 最新声音原点」，来自 cmd=208。
	//
	// 🔴 硬规则 290（2026-10-20 12:00）：cmd=208 是 `svc_SosStartSoundEvent`，
	// 这里存的是**声音事件的原点**，不是人物位置。原点通常就是发声者当时所在处，
	// 但三个缺陷让它不能当主数据源：不连续、身份不成立（门/投掷物/掠过音都能发）、
	// 位置语义不同（脚下 vs 上身会差 36 单位，同一实体同一瞬间出现两条）。
	// ⇒ 只进 Snapshot.Sounds，**绝不进 Snapshot.Players**。
	gnsPos      map[uint32]gnsPosEntry
	gnsPosTotal int
	// gnsPosEnts 是「声源实体索引 → 累计采样条数」。
	//
	// 🔴 为什么必须单独记：`解出 N 条 / 当前实体 M 个` 这个除法没有意义。
	// 08:14 那局 cmd=208 一共出现 **22 个不同实体索引**，但任意 6 秒窗口内
	// 只有 5 个是新鲜的（TTL 之外的已被剔除）。拿累计条数除以瞬时活跃数，
	// 会算出「平均采样 95.2 条/实体」这种数字，看起来像每个实体刷得很勤，
	// 实际是「22 个实体轮流刷新」。改成从这张表取「累计实体数 + 中位采样」。
	gnsPosEnts map[uint32]int
	// gnsPosSeenAt 是「实体索引 → 第一次被采样到的时间」。
	//
	// 🔴 算采样速率时必须除以**这个实体自己的观察窗口**，不能用会话总时长：
	// 10:14 局中途有两个人加入，用累计条数排名时他们的条数天然低、和道具撞在一起，
	// 最大断崖被磨平到 1.7 倍，过滤整个失效（画面上 48 个点）。
	// 换成「条数 ÷ 自己的观察时长」就能分开了。详见硬规则 282。
	gnsPosSeenAt map[uint32]time.Time
	// gnsPosTail 是「blob 尾部 4 字节 → 条数」。
	//
	// 语义未定（不是类哈希 —— 同一个实体会换值），但取值只有 5~6 种，
	// 是下一轮区分「玩家 / 道具」的第一手线索。只统计，不影响解码。
	gnsPosTail map[uint32]int
	// gnsPlayers 是玩家名单（cmd=60）：userid → SteamID64 + 3 个标志位。
	gnsPlayers map[uint32]gnsPlayerEntry
	// signonDump 是可靠流最前面那一段的累积缓冲（硬规则 251）。
	//
	// signon（svc_GameEventList / sendtable / 字符串表）只出现在连接起点，
	// 而三份现有落盘产物都覆盖不到它。攒满 signonDumpBytes 立刻落盘，
	// 之后 signonDone=true，这个会话不再占用内存。
	signonDump []byte
	signonDone bool
	// gnsPosMsgs 是成功解出声音事件的 cmd=208 条数（用来算「命中率」）。
	gnsPosMsgs int
	// gnsPosSeen 是**收到**的 cmd=208 条数（含解析失败）。
	//
	// 只有「收到」和「解出」两个数分开记，才能区分两种完全不同的故障：
	// 收到 0 条 ⇒ 这局根本没有声音事件（不在对局内 / cmd 号变了）；
	// 收到 N 条但解出 0 条 ⇒ 消息结构变了（blob 标记不在 0a 0c 了）。
	gnsPosSeen int
	// gnsPosFirst 是第一条声音事件的时间，用来算**真实刷新率**（条/秒）。
	//
	// 🔴 22:53 那局只看到「解出 N 条」这一个累计值，算不出速率，
	// 于是「1.7 Hz/实体」和「64 Hz/实体」两种结论都说得通，没法判断画面会不会卡。
	gnsPosFirst time.Time
	// gnsStatAt 是 logGNSDecodeStats 的节流时间戳（每 3 秒一次）。
	gnsStatAt time.Time
	// noPrivLogged 保证「没有客户端私钥」那句话只打一次。
	noPrivLogged bool

	// mapReg 是地图注册表（由 Store 注入，只读共享）。
	mapReg *mapdata.Registry
	// mapName 是**已确定**的地图名：ServerInfo.map_name 或用户手选。
	// 一旦有值就压过坐标反推（mapInferred）。
	mapName string
	// mapNameSrc 是 mapName 的来源（"serverinfo" / "manual"）。
	mapNameSrc string
	// mapInferred 是**用现场坐标反推**出来的地图 ID，粘住不反复改。
	//
	// 判据见 inferMapLocked：至少 mapInferMinPoints 个当前声音原点，
	// 且 ≥ mapInferHitRatio 落在同一张图的标定范围内，且与次优图拉开差距。
	// 它只在没有确定来源时才参与，并且前端会明确标注「反推」。
	mapInferred string
	// mapInferIn / mapInferTot 是反推的累计票数（诊断用，打日志）。
	mapInferIn  int
	mapInferTot int
	mapLogged   bool

	// unrelDump 攒不可靠消息（`u32le 长度 + 载荷`）。
	//
	// 🔴 2026-10-19 16:52 现场：SNP 帧层解出 3042 条不可靠消息（长度 11~3001，
	// 中位 569），但原来只 `st.unrels += len(unrels)` 数了个数就扔了。
	// CS2 的 svc_PacketEntities 走的就是不可靠通道，扔掉等于把实体流扔掉。
	unrelDump  []byte
	unrelCount int
	unrelSaved bool
	// unrelHead 缓存前 64 条不可靠消息的首字节与长度，用于一次性打日志。
	unrelHead []msgHead

	// gnsUnrel 是不可靠通道（0x02）的位链解码统计。
	//
	// 🔴 2026-10-20 10:28 那局才把格式解开（硬规则 283）：
	// `[0x02][seq][tick][0 填充][位打包 netmessage 链]`，起点 11 命中 98.0%。
	// 解出来 cmd=55 是 CSVCMsg_PacketEntities，5190 条、累计 50778 次实体更新、
	// 1.65 MB entity_data —— 比可靠通道 cmd=208 的 687 条密两个量级。
	gnsUnrel      gnsUnrelStats
	unrelS2C      *cs2snp.UnrelReassembler
	serverMapName string

	gnsSchemaMessages     int
	gnsFullEntityMessages int

	decoder   *cs2proto.HeuristicDecoder
	decoded   uint64
	encrypted uint64

	updated time.Time
}

// dirStats 是**单个方向**的 SNP 解码状态。
type dirStats struct {
	pkts    int
	segs    int
	unrels  int
	bad     int
	badType byte
	msgs    int
	// fedFrames 是该方向已喂过的帧数（绝对帧序号），保证每帧只喂一次。
	fedFrames int
	// firstPos 是该方向见到的第一个可靠段流位置，用于判断样本是否从连接起点开始。
	firstPos int64
	firstSet bool
	lastLog  time.Time
	// lastProbe 是该方向上一次跑方案探测的时间（节流用）。
	lastProbe time.Time
	// probeTop 是该方向最后一次探测的候选排名，供 /probe 接口排查。
	probeTop  []cs2crypto.Result
	badWarned bool
	posWarned bool
}

// statsFor 返回某个方向的诊断状态。dir 只认 "c2s"，其余都当 s2c。
func (sess *Session) statsFor(dir string) *dirStats {
	if dir == "c2s" {
		return &sess.stC2S
	}
	return &sess.stS2C
}

// schemeFor 返回某个方向已定的方案，没有则 nil。
func (sess *Session) schemeFor(dir string) *cs2crypto.Scheme {
	if dir == "c2s" {
		return sess.schemeC2S
	}
	return sess.schemeS2C
}

// setSchemeLocked 装上某个方向的方案。调用方必须已持有 sess.mu。
func (sess *Session) setSchemeLocked(dir string, sch *cs2crypto.Scheme) {
	if sch == nil {
		return
	}
	if dir == "c2s" {
		sess.schemeC2S = sch
		return
	}
	sess.schemeS2C = sch
}

// anyScheme 返回一个"代表性"方案，只用于展示（优先 s2c）。
func (sess *Session) anyScheme() *cs2crypto.Scheme {
	if sess.schemeS2C != nil {
		return sess.schemeS2C
	}
	return sess.schemeC2S
}

// primaryScheme 返回已装的方案及其方向（优先 s2c），供展示与测试使用。
func (sess *Session) primaryScheme() (*cs2crypto.Scheme, string) {
	if sess.schemeS2C != nil {
		return sess.schemeS2C, "s2c"
	}
	if sess.schemeC2S != nil {
		return sess.schemeC2S, "c2s"
	}
	return nil, ""
}

// ID 返回会话标识。
func (sess *Session) ID() string { return sess.id }

// Store 是会话表。
type Store struct {
	cfg Config

	mu       sync.Mutex
	sessions map[string]*Session
	packets  uint64
	batches  uint64

	// mapReg 是所有会话共享的地图注册表（只读，创建后不再改）。
	mapReg *mapdata.Registry
}

// NewStore 创建会话表。
func NewStore(cfg Config) *Store {
	if cfg.MaxSlots <= 0 {
		cfg.MaxSlots = 64
	}
	if cfg.PlayerTTL <= 0 {
		cfg.PlayerTTL = 10 * time.Second
	}
	if cfg.MaxFrames <= 0 {
		cfg.MaxFrames = 2000
	}
	if cfg.MinFrames <= 0 {
		cfg.MinFrames = 8
	}
	// 会话表必须有上限：会话名由客户端给，不设上限就是一条内存放大路径。
	// 这里兜底默认，避免调用方构造 Config 时漏填导致无限增长。
	if cfg.MaxSessions <= 0 {
		cfg.MaxSessions = 64
	}
	// 地图注册表：内嵌资产是编译期就打进 exe 的，正常情况下不会失败。
	// 🔴 失败**不能**让整个服务起不来 —— 没有底图只是画面差，不是致命错误。
	reg := cfg.MapRegistry
	if reg == nil {
		if r, err := mapdata.NewRegistry(); err == nil {
			reg = r
		} else {
			log.Printf("[map] ⚠ 加载内嵌地图资产失败：%v（雷达页会显示「无底图」）", err)
		}
	}
	if reg != nil {
		reg.SetExternalDir(cfg.MapImageDir)
	}
	return &Store{cfg: cfg, sessions: map[string]*Session{}, mapReg: reg}
}

// MapRegistry 返回地图注册表（可能为 nil）。
func (s *Store) MapRegistry() *mapdata.Registry { return s.mapReg }

// MapIDs 返回所有已知地图 ID，供前端手动选图。
func (s *Store) MapIDs() []string {
	if s.mapReg == nil {
		return nil
	}
	return s.mapReg.IDs()
}

// SetMapName 手动指定某个会话的地图名。
//
// 传空串表示「清掉手动指定，回到自动判断」。返回值是解析后的状态说明。
func (s *Store) SetMapName(session, name string) (string, string) {
	name = strings.TrimSpace(name)
	canonical := ""
	if name != "" {
		if len(name) > 128 || s.mapReg == nil {
			return gnsInvalidMap()
		}
		def, _, _ := s.mapReg.Resolve(name)
		if def == nil {
			return gnsInvalidMap()
		}
		canonical = def.ID
	}
	sess := s.Get(session)
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.mapName != canonical {
		sess.pixelView = nil
	}
	sess.mapName = canonical
	sess.mapNameSrc = ""
	sess.mapInferred = ""
	sess.mapInferIn = 0
	sess.mapInferTot = 0
	sess.mapLogged = false
	if canonical == "" {
		return "unknown", ""
	}
	sess.mapNameSrc = "manual"
	_, state, msg := s.mapReg.Resolve(canonical)
	return string(state), msg
}

// Get 取会话，不存在则创建。
func (s *Store) Get(id string) *Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		sess = &Session{
			entityTTL:    s.cfg.PlayerTTL,
			id:           id,
			decoder:      cs2proto.NewHeuristicDecoderWithTTL(s.cfg.MaxSlots, s.cfg.PlayerTTL),
			snpS2C:       cs2snp.NewParser(),
			snpC2S:       cs2snp.NewParser(),
			relStreamS2C: cs2snp.NewStream(),
			relStreamC2S: cs2snp.NewStream(),
			msgSplitS2C:  cs2snp.NewMsgSplit(),
			msgSplitC2S:  cs2snp.NewMsgSplit(),
			mapReg:       s.mapReg,
		}
		// 命令行/配置里指定的地图名，作为新会话的初始值。
		if s.cfg.MapName != "" {
			sess.mapName = s.cfg.MapName
			sess.mapNameSrc = "manual"
			if s.mapReg != nil {
				if def, _, _ := s.mapReg.Resolve(s.cfg.MapName); def != nil {
					sess.mapName = def.ID
				}
			}
		}
		// DebugSlots is deprecated: production never logs raw positions.
		// updated 必须在淘汰之前写：否则新会话带着零值时间戳进表，
		// 会被 evictLocked 当成"最久未更新"而立刻淘汰掉自己。
		sess.updated = time.Now()
		s.sessions[id] = sess
		s.evictLocked()
	}
	sess.updated = time.Now()
	return sess
}

// evictLocked 在会话数超上限时淘汰最久未更新的会话。调用方须持有 s.mu。
func (s *Store) evictLocked() {
	if s.cfg.MaxSessions <= 0 || len(s.sessions) <= s.cfg.MaxSessions {
		return
	}
	oldestID := ""
	var oldest time.Time
	first := true
	for id, sess := range s.sessions {
		sess.mu.Lock()
		u := sess.updated
		sess.mu.Unlock()
		if first || u.Before(oldest) {
			oldest, oldestID, first = u, id, false
		}
	}
	if oldestID != "" {
		delete(s.sessions, oldestID)
		log.Printf("session capacity reached: limit=%d, evicted=1", s.cfg.MaxSessions)
	}
}

// frameConnIDHist 统计两个缓冲区里各「收方 connID」出现多少次。
//
// 只统计像 GNS 数据包的帧（flags 0x80..0x83），其余归到 "other"。
// 用途是把「缓冲区里到底是谁的流量」这件事变成可读的数字 ——
// 只有 1 帧对得上时，看分布就知道是端口白名单漏了游戏流量，
// 还是 connID 判据本身错了。
func frameConnIDHist(bufs ...[][]byte) map[string]int {
	hist := map[string]int{}
	for _, buf := range bufs {
		for _, f := range buf {
			if _, ok := cs2crypto.GNSChunkOffset(f); !ok {
				hist["other"]++
				continue
			}
			id, _ := cs2crypto.GNSFrameToConnID(f)
			hist[fmt.Sprintf("%x", id)]++
		}
	}
	return hist
}

// histText 把 connID 直方图渲染成「xxxx×123 yyyy×45 …」，按次数降序，最多 6 项。
func histText(hist map[string]int) string {
	type kv struct {
		k string
		n int
	}
	list := make([]kv, 0, len(hist))
	for k, n := range hist {
		list = append(list, kv{k, n})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].k < list[j].k
	})
	out := ""
	for i, e := range list {
		if i >= 6 {
			out += " …"
			break
		}
		if i > 0 {
			out += " "
		}
		out += fmt.Sprintf("%s×%d", e.k, e.n)
	}
	return out
}

// keepGNSFrames 只留下收方 connID 等于 want 的 GNS 数据帧。
func keepGNSFrames(frames [][]byte, want []byte) [][]byte {
	out := make([][]byte, 0, len(frames))
	for _, f := range frames {
		if _, ok := cs2crypto.GNSChunkOffset(f); !ok {
			continue
		}
		if !cs2crypto.GNSFrameForConn(f, want) {
			continue
		}
		out = append(out, f)
	}
	return out
}

// Ingest 吸收一批数据（来自 HTTP 上行，或本机直接投递）。
//
// 返回真正被接受的包数。已经能按明文解析成 netmessage 流的包会被跳过
// （那不是密文帧）。
func (s *Store) Ingest(b *uplink.Batch) (int, error) {
	if b.Session == "" {
		return 0, fmt.Errorf("missing session")
	}
	sess := s.Get(b.Session)
	waiting := time.Now()
	sess.cycleMu.Lock()
	sess.perfCycleWait.Observe(time.Since(waiting))
	started := time.Now()
	defer func() { sess.perfIngest.Observe(time.Since(started)) }()
	defer sess.cycleMu.Unlock()

	sess.mu.Lock()
	if b.ServerPub != "" {
		if raw, err := base64.StdEncoding.DecodeString(b.ServerPub); err == nil {
			sess.serverPub = raw
		}
	}
	if b.Key != "" {
		if raw, err := base64.StdEncoding.DecodeString(b.Key); err == nil {
			sess.clientPriv = raw
		}
	}
	if b.GNS.Complete() {
		if h := gnsFromMaterial(b.GNS); h != nil {
			if sess.gns != nil && (!bytes.Equal(sess.gns.ClientConnID, h.ClientConnID) || !bytes.Equal(sess.gns.ServerConnID, h.ServerConnID)) {
				sess.resetGNSGenerationLocked()
				if b.Key == "" {
					sess.clientPriv = nil
				}
			}

			// 第一次拿到材料时，把缓冲区里已经攒下的无关包清掉。
			// 材料通常晚于第一批数据到达，那时缓冲里混的是 Steam 客户端流量，
			// 不清就得等它被新帧挤出去，而第一次派生尝试会白跑。
			if sess.gns == nil {
				// 🔴 清之前先把「被丢掉的是谁」记下来。
				// 09:07 那次现场 `frames=1419` 但清完只剩 1 帧，dump 出来
				// 的却是清空后的结果 —— 等于把唯一的证据销毁了，
				// 只能靠猜。这次先统计再清。
				sess.gnsDropHist = frameConnIDHist(sess.c2s, sess.s2c)
				sess.c2s = keepGNSFrames(sess.c2s, h.ServerConnID)
				sess.s2c = keepGNSFrames(sess.s2c, h.ClientConnID)
			}
			sess.gns = h
		}
	}
	// 从内存读到的两把 IV：不解帧，专门给 KDF 定标。
	//
	// 只在 connID 对得上时才收 —— 换图/重连时旧连接的 IV 会残留，
	// 拿它去比对只会把正确的变体判掉。
	if b.GNSIVs.Complete() {
		if h := sess.gns; h != nil &&
			b.GNSIVs.ClientConnID == fmt.Sprintf("%x", h.ClientConnID) &&
			b.GNSIVs.ServerConnID == fmt.Sprintf("%x", h.ServerConnID) {
			if iv1, err := base64.StdEncoding.DecodeString(b.GNSIVs.SendIV); err == nil {
				if iv2, err := base64.StdEncoding.DecodeString(b.GNSIVs.RecvIV); err == nil &&
					len(iv1) == 12 && len(iv2) == 12 {
					// 只在值变化时打日志。
					//
					// 采集端每个批次都会带一次 GNSIVs（上行要幂等，丢了要能补），
					// 而 Ingest 每批都跑 —— 原来无条件打印，10:02 那次现场
					// 这一行刷了 101 遍，把真正有用的信息全淹了。
					changed := !bytes.Equal(sess.gnsSendIV, iv1) || !bytes.Equal(sess.gnsRecvIV, iv2)
					sess.gnsSendIV = iv1
					sess.gnsRecvIV = iv2
					if changed {
						gnsLogf("[%s] 已装载内存 IV：SendIV=%x RecvIV=%x（KDF 变体改用高 4 字节比对）",
							sess.id, iv1, iv2)
					}
				}
			}
		}
	}
	// 从目标进程内存直接读到的会话密钥：这是实测认证过的，优先级最高。
	// 一旦设上，tryGNS 会立刻短路返回（它看到 Candidate.GNSIV 非空就不再派生）。
	if b.GNSKeys.Complete() {
		if key, err := base64.StdEncoding.DecodeString(b.GNSKeys.Key); err == nil {
			if iv, err := base64.StdEncoding.DecodeString(b.GNSKeys.IV); err == nil {
				if sch, err := cs2crypto.SchemeFromGNS(key, iv); err == nil {
					sess.setSchemeLocked(b.GNSKeys.Dir, sch)
					sess.plainWant = false
					gnsLogf("[%s] 已装载内存直读的会话密钥：方向 %s｜IV %x｜密钥 %d 字节",
						sess.id, b.GNSKeys.Dir, iv, len(key))
				} else {
					gnsLogf("[%s] 内存密钥装载失败：%v", sess.id, err)
				}
			}
		}
		// 🔴 第二个方向也要装。两个方向是**两把不同的密钥**，只装一边
		// 就只能解一边 —— 现场 13:24 全程只有 `方向=c2s`，s2c 的实体数据全丢。
		if b.GNSKeys.HasAlt() {
			altKey, e1 := base64.StdEncoding.DecodeString(b.GNSKeys.AltKey)
			altIV, e2 := base64.StdEncoding.DecodeString(b.GNSKeys.AltIV)
			if e1 == nil && e2 == nil {
				if sch, err := cs2crypto.SchemeFromGNS(altKey, altIV); err == nil {
					sess.setSchemeLocked(b.GNSKeys.AltDir, sch)
					sess.plainWant = false
					gnsLogf("[%s] 已装载内存直读的会话密钥（第二方向）：方向 %s｜IV %x｜密钥 %d 字节",
						sess.id, b.GNSKeys.AltDir, altIV, len(altKey))
				} else {
					gnsLogf("[%s] 内存密钥（第二方向）装载失败：%v", sess.id, err)
				}
			}
		}
	}
	added := 0
	for _, p := range b.Packets {
		raw, err := base64.StdEncoding.DecodeString(p.Data)
		if err != nil || len(raw) == 0 {
			continue
		}
		// 拿到 GNS 握手材料之后，只留**属于本连接**的数据包。
		//
		// 缓冲区是有上限的（MaxFrames），而同一进程名下还有别的 UDP 流
		// （Steam 客户端 CM/语音等，09:01 那次光一个端口就 3 万多个包）。
		// 不筛的话真正的游戏帧会被挤出去，而且挑判据帧时会挑到一堆无关包。
		// 握手包（0x20~0x25）没有 connID 头，按 flags 直接放过 —— 它们不参与解密。
		knownGNS := sess.gns != nil && len(raw) >= 5 && raw[0]&0x80 != 0
		if knownGNS {
			want := sess.gns.ClientConnID
			if p.Dir == "c2s" {
				want = sess.gns.ServerConnID
			}
			if !cs2crypto.GNSFrameForConn(raw, want) {
				continue
			}
		} else if _, ok := cs2proto.Score(raw, cs2proto.MaxCmd); ok {
			// A known-connection encrypted GNS frame can coincidentally also
			// satisfy the plaintext shape heuristic. It must reach GCM instead
			// of being discarded here. Connection filtering above and the
			// existing authenticated decrypt below remain mandatory.
			continue
		}
		if p.Dir == "c2s" {
			sess.c2s, sess.c2sDropped = appendCapped(sess.c2s, raw, s.cfg.MaxFrames, sess.c2sDropped)
		} else {
			sess.s2c, sess.s2cDropped = appendCapped(sess.s2c, raw, s.cfg.MaxFrames, sess.s2cDropped)
		}
		added++
	}
	sess.mu.Unlock()

	s.mu.Lock()
	s.batches++
	s.packets += uint64(added)
	s.mu.Unlock()

	return added, nil
}

// Process 对某个会话跑一次「方案搜索 + 增量解码」。
// Ingest 之后调用；本机模式可以同步调，服务端模式通常丢进 goroutine。
func (s *Store) Process(id string) {
	sess := s.Get(id)
	waiting := time.Now()
	sess.cycleMu.Lock()
	sess.perfCycleWait.Observe(time.Since(waiting))
	started := time.Now()
	defer func() { sess.perfProcess.Observe(time.Since(started)) }()
	defer sess.cycleMu.Unlock()
	// GNS 是确定解：材料齐了就直接派生，不再枚举候选空间。
	// 材料齐了但派生失败时也**不**回落到候选搜索 —— 后者既解不出来
	// （密钥/IV 都来自同一条派生链，链错了两边都错），又白烧 CPU。
	if !sess.tryGNS() && !sess.hasGNS() {
		sess.runProbe(s.cfg.MinFrames, s.cfg.MaxOffset)
	}
	sess.decode()
}

// hasGNS 报告这个会话是否已经拿到 GNS 握手材料。
func (sess *Session) hasGNS() bool {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	return sess.gns != nil
}

// gnsFromMaterial 把上行材料还原成 cs2crypto.GNSHandshake。
func gnsFromMaterial(m *uplink.GNSMaterial) *cs2crypto.GNSHandshake {
	dec := func(s string) []byte {
		if s == "" {
			return nil
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil
		}
		return b
	}
	h := &cs2crypto.GNSHandshake{
		ClientConnID: dec(m.ClientConnID),
		ServerConnID: dec(m.ServerConnID),
		ClientPub:    dec(m.ClientPub),
		ServerPub:    dec(m.ServerPub),
		ClientNonce:  dec(m.ClientNonce),
		ServerNonce:  dec(m.ServerNonce),
		ClientCert:   dec(m.ClientCert),
		ServerCert:   dec(m.ServerCert),
		ClientCrypt:  dec(m.ClientCrypt),
		ServerCrypt:  dec(m.ServerCrypt),
	}
	if err := h.Valid(); err != nil {
		return nil
	}
	return h
}

// tryGNS 用 GNS 握手材料 + 客户端私钥派生会话密钥，并用真实帧验证。
//
// 验证是必须的：派生公式错了会静默产出一把"看起来正常"的密钥，
// 只有 GCM 认证能戳穿它。要求至少 3 帧可解 —— 错误密钥通过单帧认证的
// 概率是 2^-128，3 帧几乎不可能。
//
// 派生参数不是"赌一种写法"：`GNSVariants()` 会枚举 label / 四段握手字节顺序 /
// salt 顺序 / 计数器位置 / 槽位映射（不到 200 组，每组 4 次 HMAC ≈ 2µs），
// 用真实帧的 GCM 认证判胜负。第一组是开源实现的规范写法，它中不了才往下试。
func (sess *Session) tryGNS() bool {
	sess.mu.Lock()
	// 🔴 只有**两个方向都装好 GNS 方案**才算完成。
	//
	// 原来这里判 `anyScheme() != nil` 就 return true。而内存直读私钥那条路
	// 只会装**一个**方向（`GNSKeys.Dir`，现场是 c2s），于是 s2c 永远补不上 ——
	// 13:24 那次日志从头到尾只有 `方向=c2s`，s2c 的实体数据一条没解。
	//
	// 所以：只要还有方向缺方案，就继续往下派生（一次派生同时给 Send/Recv 两把）。
	// 但如果是 runProbe 装上的**非 GNS** 假方案，也必须允许 GNS 覆盖它。
	needS2C := sess.schemeS2C == nil || sess.schemeS2C.Candidate.GNSIV == nil
	needC2S := sess.schemeC2S == nil || sess.schemeC2S.Candidate.GNSIV == nil
	if !needS2C && !needC2S {
		sess.mu.Unlock()
		return true
	}
	h := sess.gns
	// 没有握手材料就没法派生另一个方向。只要已经有一个方向能用，就算完成 ——
	// 内存直读私钥那条路本来就只给一边（它没有握手材料）。
	if h == nil && (sess.schemeS2C != nil || sess.schemeC2S != nil) {
		sess.mu.Unlock()
		return true
	}
	priv := append([]byte(nil), sess.clientPriv...)
	// 节流：失败时不要每次 Process 都重跑近 200 组变体。
	// 但也不能只试一次 —— 缓冲区里的帧会越来越多，早失败晚成功是常态。
	if time.Since(sess.lastGNS) < 2*time.Second {
		sess.mu.Unlock()
		return false
	}
	sess.lastGNS = time.Now()
	s2cFrames := make([][]byte, len(sess.s2c))
	copy(s2cFrames, sess.s2c)
	c2sFrames := make([][]byte, len(sess.c2s))
	copy(c2sFrames, sess.c2s)
	memSend := append([]byte(nil), sess.gnsSendIV...)
	memRecv := append([]byte(nil), sess.gnsRecvIV...)
	sess.mu.Unlock()

	if h == nil {
		return false
	}
	if len(priv) == 0 {
		// 🔴 只打一次。原来每次 tryGNS 都打，22:53/07:20 那两局日志里
		// 这句话重复了上百遍，把真正有用的行全淹了。
		//
		// 而且必须说清「这意味着什么」：`[dec] has_key=false` 只是个数，
		// 用户看到满屏 `已解帧=0` 会以为雷达坏了。
		if !sess.noPrivLogged {
			sess.noPrivLogged = true
			gnsLogf("[%s] GNS 握手材料已齐，但没有客户端私钥 —— **这一局解不出任何一帧，也不会有目标**。"+
				" 私钥只在一次握手往返里活着，要靠「冻结游戏 + 只读搜索」去捞（默认已开）。"+
				" 如果日志前面有「检测到反作弊在场」，就是安全闸门主动挡住了那次搜索 —— 不是故障。",
				sess.id)
		}
		return false
	}
	if len(priv) != 32 {
		gnsLogf("[%s] GNS 材料齐了但私钥长度是 %d（要 32），跳过派生", sess.id, len(priv))
		return false
	}

	// 只拿**属于本连接**的 GNS 加密数据包做判据。
	//
	// 两个条件缺一不可：
	//  ① flags ∈ {0x80..0x83}（`GNSChunkOffset` 管）；
	//  ② 帧头第 1~4 字节的**收方 connID** 等于本次连接对应的一端。
	//
	// 09:01 那次现场就是漏了 ②：CS2 进程名下还有 Steam 客户端的其它 UDP 流
	// （日志里 56729 端口 31827 个包，游戏服 17011/53663 才 3300 个），
	// 挑出来的 64 帧 connID 全是 `000400cc` / `000700c9` 这种，
	// 和本次的 `ba2554e3`/`ba10bf93` 毫无关系 —— 768 组变体当然全灭。
	//
	// 另外从**尾部**取：缓冲区满时丢的是最旧的，尾部才是刚发生的数据。
	pick := func(frames [][]byte, want []byte) [][]byte {
		out := make([][]byte, 0, 64)
		for i := len(frames) - 1; i >= 0; i-- {
			f := frames[i]
			// 🔴 这里原来还有一道 `GNSChunkOffset` 闸门（flags ∈ 0x80..0x83
			// 且按开源源码算偏移）。采集端上一轮已经把它删了，这一侧漏改，
			// 于是两边判据不一致：采集端收下 397/400，解码端只挑出个位数。
			// flags 的真实分布已经量过（0x82 占 394/400），高位确实存在，
			// 但偏移硬算没有依据 —— 交给 GNSOffsets 候选集去试，别在这里拒。
			if len(cs2crypto.GNSOffsets(f)) == 0 {
				continue
			}
			if !cs2crypto.GNSFrameForConn(f, want) {
				continue
			}
			out = append(out, f)
			if len(out) >= 64 {
				break
			}
		}
		return out
	}
	// 两个方向各自挑出「属于本连接的 GNS 数据包」。
	//
	// 两个都要留着：一次派生就同时给出 Send/Recv 两把密钥，装方案时
	// 每个方向都要拿自己的帧去验，不能只验主方向。
	s2cPick := pick(s2cFrames, h.ClientConnID)
	c2sPick := pick(c2sFrames, h.ServerConnID)
	dir, cands := "s2c", s2cPick
	if len(c2sPick) > len(s2cPick) {
		dir, cands = "c2s", c2sPick
	}
	if len(cands) < 3 {
		gnsLogf("[%s] GNS 材料齐了，但属于本连接的 GNS 数据包只有 %d 个（需要 ≥3）"+
			"｜s2c 收方=%x 命中 %d｜c2s 收方=%x 命中 %d｜缓冲 s2c=%d c2s=%d",
			sess.id, len(cands),
			h.ClientConnID, len(s2cPick), h.ServerConnID, len(c2sPick),
			len(s2cFrames), len(c2sFrames))
		// 材料到达那一刻的 connID 分布：能直接回答「是端口白名单漏了游戏流量，
		// 还是 connID 判据错了」。没有这行只能靠猜。
		sess.mu.Lock()
		hist := sess.gnsDropHist
		sess.mu.Unlock()
		if len(hist) > 0 {
			gnsLogf("[%s] 材料到达时缓冲区的收方 connID 分布：%s（本连接应为 s2c=%x / c2s=%x）",
				sess.id, histText(hist), h.ClientConnID, h.ServerConnID)
		}
		sess.mu.Lock()
		first := !sess.gnsDiagDone
		sess.gnsDiagDone = true
		sess.mu.Unlock()
		if first {
			// 一帧都对不上是最难自查的情况：说明"帧头第 1~4 字节是收方 connID"
			// 这个假设可能有问题，或者游戏流量根本没进缓冲区。
			// 把真实帧头摊开写下来，下一轮就能直接看，不用再赌一次。
			if p := dumpFrameHeads(sess.id, h, s2cFrames, c2sFrames); p != "" {
				gnsLogf("[%s] 已把真实帧头写到 %s（含每个帧的 flags / 收方 connID / 长度）",
					sess.id, p)
			}
		}
		return false
	}

	// 预主密钥只算一次：X25519 标量乘约 50µs，而下面要枚举近 200 个变体。
	// 返回两种写法（SHA256(dh) 在前、裸 dh 兜底），外层各试一遍。
	pms, pmNames, err := cs2crypto.GNSPremasters(priv, h)
	if err != nil {
		gnsLogf("[%s] GNS 派生失败: %v", sess.id, err)
		return false
	}

	var (
		bestName = "无"
		bestOK   int
		bestSch  *cs2crypto.Scheme
		bestKeys *cs2crypto.GNSKeys
	)
	variants := cs2crypto.GNSVariants()
	// 枚举阶段只需要"能判胜负"，16 帧足够（要 3 帧通过，随机通过率 2^-128）。
	// 全都不中时这是最坏路径：384 组 × 16 帧 × 8 个回绕 ≈ 5 万次 GCM ≈ 15ms。
	probe := cands
	if len(probe) > 16 {
		probe = probe[:16]
	}
	// ivHits 记录「派生 IV 的高 4 字节和内存 IV 对上」的变体。
	//
	// 这是本轮新增的判据，理由见 Session.gnsSendIV 的注释：IV 只有低 8 字节
	// 随包前移，高 4 字节整局不变。所以 32 位对上就不是巧合 —— 1152 个变体里
	// 最多命中一两个。
	//
	// 它比「帧能不能解开」强的地方：帧解不开可能是 nonce 错了，而 nonce 错了
	// 时 IV 照样能对上。两个判据分开，就能把「KDF 错」和「nonce 错」区分开 ——
	// 这正是卡了十几轮没分开的东西。
	var ivHits []string
	var ivHitKeys *cs2crypto.GNSKeys
	var ivHitName string
	hasMemIV := len(memSend) == 12 && len(memRecv) == 12

	for pi, pm := range pms {
		for _, v := range variants {
			keys := cs2crypto.GNSDeriveFromPremaster(pm, h, v)
			key, iv := keys.RecvKey, keys.RecvIV
			if dir == "c2s" {
				key, iv = keys.SendKey, keys.SendIV
			}
			if hasMemIV {
				sendOK := cs2crypto.GNSIVTailMatch(keys.SendIV, memSend)
				recvOK := cs2crypto.GNSIVTailMatch(keys.RecvIV, memRecv)
				if sendOK || recvOK {
					tag := "recv"
					if sendOK && recvOK {
						tag = "双向"
					} else if sendOK {
						tag = "send"
					}
					ivHits = append(ivHits, pmNames[pi]+"/"+v.Name+"/"+tag)
					if ivHitKeys == nil {
						ivHitKeys, ivHitName = keys, pmNames[pi]+"/"+v.Name
					}
				}
			}
			sch, err := cs2crypto.SchemeFromGNS(key, iv)
			if err != nil {
				continue
			}
			ok := 0
			for _, f := range probe {
				if _, err := sch.OpenFrame(0, f); err == nil {
					ok++
					if ok >= 3 {
						break
					}
				}
			}
			if ok > bestOK {
				bestOK = ok
				bestName = pmNames[pi] + "/" + v.Name
				bestSch, bestKeys = sch, keys
			}
			if ok >= 3 {
				break
			}
		}
		if bestOK >= 3 {
			break
		}
	}

	// 复核：上面的枚举为了省时间，命中 3 帧就 break，于是 bestOK 被截断在 3，
	// 日志里就永远写「3/64 帧可解」—— 看起来像"只有 3 帧能解"，实际是
	// "数到第 3 帧就停了"。2026-10-19 现场就是被这行字误导了半天：
	// 当时以为密钥只对 3 帧有效，其实是探针提前收工。
	//
	// 这里对胜出的方案跑一遍完整探针，拿到真实命中率，并据此判定可信度：
	// 密钥正确时 16 帧应当全过；只过一半以下说明是巧合（概率 2^-128，
	// 但仍要挡住"探针里混进非加密帧"这种情况）。
	if bestOK >= 3 && bestSch != nil {
		full := 0
		for _, f := range probe {
			if _, err := bestSch.OpenFrame(0, f); err == nil {
				full++
			}
		}
		gnsLogf("[%s] GNS 复核：%d/%d 帧 GCM 认证通过（探针 = 最近 %d 帧里筛出的 %d 帧）",
			sess.id, full, len(probe), len(cands), len(probe))
		if full*2 < len(probe) {
			gnsLogf("[%s] GNS 复核未过半（%d/%d），判为误判，继续找", sess.id, full, len(probe))
			bestOK, bestSch = 0, nil
		} else {
			bestOK = full
		}
	}

	// IV 高 4 字节命中但帧解不开 = KDF 已经对了，错的是 nonce。
	// 这时用「派生出的密钥 + 内存里的 IV（当前 nonce）」组合去试 ——
	// 密钥由 KDF 给（它是对的），nonce 由内存给（它是最新的），两头都取确定的。
	if bestOK < 3 && ivHitKeys != nil {
		gnsLogf("[%s] ★ IV 高 4 字节命中 %d 个变体：%v", sess.id, len(ivHits), ivHits)
		if sch, n := trySchemeWithMemoryIV(ivHitKeys, dir, memSend, memRecv, probe); sch != nil {
			bestOK, bestName, bestSch, bestKeys = n, ivHitName+"+内存IV", sch, ivHitKeys
			gnsLogf("[%s] ★ 用「派生密钥 + 内存 IV」解开了 %d 帧", sess.id, n)
		} else {
			gnsLogf("[%s] ★ KDF 已确认正确，但「派生密钥 + 内存 IV」仍解不开 —— 错在 nonce 规则", sess.id)
		}
	} else if bestOK < 3 && hasMemIV {
		gnsLogf("[%s] IV 高 4 字节在全部变体里都没对上（内存 IV %x/%x）—— KDF 的输入仍然不对",
			sess.id, memSend, memRecv)
	}
	if bestOK < 3 {
		gnsLogf("[%s] GNS 派生完成但帧验证未过（最好的一组「%s」只有 %d/%d 帧可解）",
			sess.id, bestName, bestOK, len(cands))
		sess.mu.Lock()
		first := !sess.gnsDiagDone
		sess.gnsDiagDone = true
		sess.mu.Unlock()
		if first {
			if p := dumpGNSDiag(sess.id, h, priv, cands, bestName, bestOK); p != "" {
				gnsLogf("[%s] 已把复现材料写到 %s（握手 + 私钥 + %d 帧），拿它就能离线调 KDF",
					sess.id, p, len(cands))
			}
		}
		return false
	}

	sess.mu.Lock()
	// 内存直读的密钥是实测认证过的，优先级最高：该方向已有 GNS 方案就不覆盖。
	if cur := sess.schemeFor(dir); cur == nil || cur.Candidate.GNSIV == nil {
		sess.setSchemeLocked(dir, bestSch)
	}
	sess.plainWant = false
	sess.mu.Unlock()
	gnsLogf("[%s] GNS 会话密钥派生成功：%s｜方向 %s｜变体「%s」｜%d/%d 帧可解｜connID %x→%x｜RecvIV %x",
		sess.id, bestSch.Name(), dir, bestName, bestOK, len(probe),
		h.ClientConnID, h.ServerConnID, bestKeys.RecvIV)

	// 🔴 把**另一个方向**也装上。
	//
	// GNS 一次派生同时给出 SendKey/SendIV 与 RecvKey/RecvIV，本来就够两个方向用。
	// 早期只装 `dir` 那一套，于是「哪边帧多就永久只解哪边」—— 13:24 现场
	// 日志从头到尾只有 `方向=c2s`，s2c 的实体数据一条没解，雷达当然没目标。
	//
	// 这里用反方向自己的帧验一下再装：解不开就不写进去，免得把错方案钉死
	// （scheme 非空之后这个方向就不会再重试了）。
	if bestKeys != nil {
		otherDir, otherKey, otherIV, otherFrames := "c2s", bestKeys.SendKey, bestKeys.SendIV, c2sPick
		if dir == "c2s" {
			otherDir, otherKey, otherIV, otherFrames = "s2c", bestKeys.RecvKey, bestKeys.RecvIV, s2cPick
		}
		if sch2, err := cs2crypto.SchemeFromGNS(otherKey, otherIV); err == nil {
			n := 0
			for _, f := range otherFrames {
				if _, e := sch2.OpenFrame(0, f); e == nil {
					n++
				}
			}
			if n >= 3 {
				sess.mu.Lock()
				// 同样不覆盖已有的 GNS 方案（内存直读优先）。
				if cur := sess.schemeFor(otherDir); cur == nil || cur.Candidate.GNSIV == nil {
					sess.setSchemeLocked(otherDir, sch2)
				}
				sess.mu.Unlock()
				gnsLogf("[%s] 反向 %s 也装上了（同一派生的 %s，%d/%d 帧可解）",
					sess.id, otherDir, otherKeyName(otherDir), n, len(otherFrames))
			} else {
				gnsLogf("[%s] 反向 %s 用同一派生只解开 %d/%d 帧，暂不装载",
					sess.id, otherDir, n, len(otherFrames))
			}
		}
	}
	return true
}

// otherKeyName 只用于日志，说明某个方向用的是哪把密钥。
func otherKeyName(dir string) string {
	if dir == "c2s" {
		return "SendKey"
	}
	return "RecvKey"
}

// Sensitive diagnostics are deliberately unavailable in server builds, including
// custom-tag builds. Never export packet bytes, keys, IDs or plaintext.
// Keep these no-op compatibility boundaries for old internal call sites; there
// is no runtime flag or environment variable that re-enables secret dumps.
func gnsLogf(_ string, _ ...any) {}

func dumpGNSDiag(_ string, _ *cs2crypto.GNSHandshake, _ []byte, _ [][]byte, _ string, _ int) string {
	return ""
}

func dumpFrameHeads(_ string, _ *cs2crypto.GNSHandshake, _ [][]byte, _ [][]byte) string {
	return ""
}

// appendCapped 追加一帧；超出上限时丢最旧的，并把"本次丢了几帧"回传，
// 以便调用方累加出"已丢弃总数"（见 Session.c2sDropped 的说明）。
func appendCapped(dst [][]byte, v []byte, max int, dropped int) ([][]byte, int) {
	dst = append(dst, v)
	if max > 0 && len(dst) > max {
		n := len(dst) - max
		dst = dst[n:]
		dropped += n
	}
	return dst, dropped
}

// runProbe 尝试定位加解密方案。
//
// 🔴 必须**按方向各探一次**，不能"挑一个方向、定了就不再管"。
//
// 早期实现是：s2c 帧够就探 s2c，不够就退到 c2s；一旦装上 scheme，
// 下一次进来第一行就 return。于是探测时哪边帧多就永久只解哪边 ——
// 13:24 现场日志从头到尾只有 `方向=c2s`，s2c（服务端下发的实体数据）
// 一条都没解，雷达自然没有目标。这不是密钥问题，是方向覆盖问题。
func (sess *Session) runProbe(minFrames, maxOffset int) {
	sess.mu.Lock()
	if sess.clientPriv == nil || sess.serverPub == nil {
		sess.mu.Unlock()
		return
	}

	type job struct {
		dir    string
		frames [][]byte
		base   int
	}
	var jobs []job
	for _, dir := range [2]string{"s2c", "c2s"} {
		if sess.schemeFor(dir) != nil {
			continue // 这个方向已经有方案了
		}
		st := sess.statsFor(dir)
		if time.Since(st.lastProbe) < 2*time.Second {
			continue // 节流：失败时不要每批包都重跑近 200 组变体
		}
		frames, base := sess.s2c, sess.s2cDropped
		if dir == "c2s" {
			frames, base = sess.c2s, sess.c2sDropped
		}
		if len(frames) < minFrames {
			continue
		}
		st.lastProbe = time.Now()
		cp := make([][]byte, len(frames))
		copy(cp, frames)
		jobs = append(jobs, job{dir: dir, frames: cp, base: base})
	}
	priv := append([]byte(nil), sess.clientPriv...)
	pub := append([]byte(nil), sess.serverPub...)
	sess.mu.Unlock()

	if len(jobs) == 0 {
		return
	}
	shared, err := cs2crypto.SharedSecret(priv, pub)
	if err != nil {
		gnsLogf("shared secret calculation failed")
		return
	}

	for _, j := range jobs {
		results := cs2crypto.ProbeFrom(shared, pub, j.frames, j.base, maxOffset)
		sess.mu.Lock()
		sess.statsFor(j.dir).probeTop = results
		var hit *cs2crypto.Scheme
		if len(results) > 0 && results[0].OK {
			if sch, err := cs2crypto.BuildScheme(shared, pub, results[0].Candidate); err == nil {
				sess.setSchemeLocked(j.dir, sch)
				hit = sch
			}
		}
		sess.mu.Unlock()
		if hit != nil {
			gnsLogf("[%s] 加解密方案命中（%s）: %s （%d/%d 帧可解，%d 条消息）",
				sess.id, j.dir, hit.Name(), results[0].OKFrames, results[0].Frames, results[0].Messages)
		}
	}
}

// decode 用已定方案解密，并把**尚未喂过**的帧喂给解码器。
//
// 必须是增量的：本函数会被每次 ingest 调用一次，而帧缓冲是累积的。
// 若每次从头重喂，槽位已推进到最新位置，位移超过关联半径的目标会
// 在它自己的历史坐标处被重新建槽，画面上多出重复目标。
func (sess *Session) decode() {
	// 两个方向都解。s2c 是雷达要的（服务端下发的实体数据），c2s 留着做诊断
	// 和后续 c2s 消息解码 —— 但**绝不能只解一个方向**。
	sess.decodeDir("s2c")
	sess.decodeDir("c2s")
}

// decodeDir 解密并解析**单个方向**的增量帧。
func (sess *Session) decodeDir(dir string) {
	sess.mu.Lock()
	sch := sess.schemeFor(dir)
	if sch == nil {
		sess.mu.Unlock()
		return
	}
	frames, dropped := sess.s2c, sess.s2cDropped
	if dir == "c2s" {
		frames, dropped = sess.c2s, sess.c2sDropped
	}
	st := sess.statsFor(dir)

	// 游标用的是**绝对帧序号**（= 发送方包计数器），不是缓冲区下标。
	// 缓冲区头部丢过 dropped 帧，所以 缓冲区下标 = 绝对序号 - dropped。
	startAbs := st.fedFrames
	if startAbs < dropped {
		// 游标落在了已被丢弃的区间里：从缓冲区现存的第一帧接着喂。
		// 注意不能回退到 0，否则会把已经喂过的帧重喂一遍（正是"幽灵目标"的成因）。
		startAbs = dropped
	}
	endAbs := dropped + len(frames)
	if startAbs >= endAbs {
		sess.mu.Unlock()
		return // 没有新帧
	}
	off := startAbs - dropped
	fr := make([][]byte, len(frames)-off)
	copy(fr, frames[off:])
	// 在锁内原子领取 [startAbs,endAbs)：并发进来的 decode 会看到游标已推进而直接返回，
	// 不会重复喂同一批帧。
	st.fedFrames = endAbs
	dec := sess.decoder
	sess.mu.Unlock()

	// SNP 分帧器 / 流拼接器 / 消息切分器都是有状态的，必须串行。
	sess.snpMu.Lock()
	defer sess.snpMu.Unlock()

	// 直接构造 Session 字面量的地方（测试、工具）不会填这些字段，这里补齐。
	if sess.snpS2C == nil {
		sess.snpS2C = cs2snp.NewParser()
	}
	if sess.snpC2S == nil {
		sess.snpC2S = cs2snp.NewParser()
	}
	if sess.relStreamS2C == nil {
		sess.relStreamS2C = cs2snp.NewStream()
	}
	if sess.relStreamC2S == nil {
		sess.relStreamC2S = cs2snp.NewStream()
	}
	if sess.msgSplitS2C == nil {
		sess.msgSplitS2C = cs2snp.NewMsgSplit()
	}
	if sess.msgSplitC2S == nil {
		sess.msgSplitC2S = cs2snp.NewMsgSplit()
	}
	parser := sess.snpS2C
	relStream, msgSplit := sess.relStreamS2C, sess.msgSplitS2C
	if dir == "c2s" {
		parser = sess.snpC2S
		relStream, msgSplit = sess.relStreamC2S, sess.msgSplitC2S
	}

	// 🔴 方向切换**不重置**可靠流。
	//
	// 早期这里是 `relStream.Reset() / msgSplit.Reset() / netchan = nil`，
	// 理由是"旧方向的帧序列与新方向没有位置连续性"。但帧序号游标和可靠流是两件事：
	// 可靠流本来就按方向各自独立，只要两个方向用各自的 Stream 就不存在连续性问题。
	// 原来那种写法只要 s2c/c2s 交替解出来，流就被反复清空 —— 现场 `netchan`
	// 永远卡在 332 字节、`已切=0` 不动，就是这么来的。

	okPkts := 0
	for i, f := range fr {
		// nonce 用的是绝对帧序号（发送方包计数器），不是缓冲区下标。
		pt, err := sch.OpenFrame(startAbs+i, f)
		if err != nil {
			if dir == "s2c" {
				sess.pipeline.decryptFailed.Add(1)
			}
			continue
		}
		if dir == "s2c" {
			sess.pipeline.decryptOK.Add(1)
		}
		okPkts++
		st.pkts++

		// 🔴 这里曾经直接 `cs2proto.ParseStream(pt)`，是个方向性错误。
		//
		// GCM 解出来的明文是 **SNP 的帧序列**（stop_waiting / ack / 可靠段 / 不可靠段），
		// 不是 netchan 消息。把 SNP 帧头当 cmd/size 去切，永远切不出东西，
		// 于是 `[dec] 已解帧=0` 就成了必然结果 —— 而这十几轮一直在往"密钥错"上找。
		segs, unrels, pst := parser.Parse(pt)
		st.segs += len(segs)
		st.unrels += len(unrels)
		if pst.Bad != 0 {
			if dir == "s2c" {
				sess.pipeline.snpBad.Add(1)
			}
			st.bad++
			st.badType = pst.BadType
			continue
		}
		// 不可靠消息要留下来（硬规则 226）。
		//
		// 原来这里只数个数就扔了。而 CS2 的实体快照走不可靠通道，
		// 16:40 那一局实测 3042 条、中位 569 字节、最长 3001 —— 是**唯一的**
		// 高码率数据源，绝不能丢。格式还没定，所以先原样落盘。
		if dir == "s2c" {
			for _, u := range unrels {
				sess.pipeline.fragments.Add(1)
				if u.Lane == 0 && u.Offset == 0 {
					sess.traceGNSOuter(u.Data, 1, 0)
				}
				if sess.unrelS2C == nil {
					sess.unrelS2C = cs2snp.NewUnrelReassembler()
				}
				expired, invalid, conflicts := sess.unrelS2C.Expired, sess.unrelS2C.Invalid, sess.unrelS2C.Conflicts
				data, complete := sess.unrelS2C.Feed(u, time.Now())
				sess.pipeline.expired.Add(sess.unrelS2C.Expired - expired)
				sess.pipeline.invalid.Add(sess.unrelS2C.Invalid - invalid)
				sess.pipeline.conflicts.Add(sess.unrelS2C.Conflicts - conflicts)
				if !complete || u.Lane != 0 {
					continue
				}
				sess.pipeline.reassembled.Add(1)
				u.Data = data

				// 解码统计（硬规则 283）：cmd=55 是 svc_PacketEntities，
				// 这是实体表唯一的高码率来源，比 cmd=208 密两个量级。
				sess.noteGNSUnrel(u.Data)
				sess.unrelCount++
			}

		}
		if pst.Bad != 0 {
			st.bad++
			st.badType = pst.BadType
			continue
		}
		for _, sg := range segs {
			// 记下该方向第一个可靠段的位置 —— 这是判断「抓包是不是从连接起点开始」
			// 的唯一硬指标，见 logDir 的告警。
			if !st.firstSet {
				st.firstSet = true
				st.firstPos = sg.Pos
			}
			relStream.Add(sg.Pos, sg.Data)
		}
		// 🔴 空洞兜底：洞等太久 / 堆太多就强行跳过。
		//
		// 22:35 那局的现场：s2c `流位置=149309` 从第 2 条统计起再没动过，
		// `最大空洞` 从 101969 涨到 497159，`待补段` 从 201 涨到 1214 ——
		// 一个包丢了就把整条 s2c 流锁死，整局没有一条实体消息。
		// 这里跳过之后必须重置 MsgSplit：新位置不是消息边界，得让它重新同步。
		if n, ok := relStream.SkipStale(time.Now()); ok {
			msgSplit.Reset()
			sess.gnsStreamSkips++
			sess.gnsStreamSkipBytes += n
			gnsLogf("[snp] 方向=%s 可靠流空洞等不到补齐，强制跳过 %d 字节"+
				"（累计跳过 %d 次 / %d 字节）—— 消息边界会重新同步",
				dir, n, sess.gnsStreamSkips, sess.gnsStreamSkipBytes)
		}
		if b := relStream.Take(); len(b) > 0 {
			for _, m := range msgSplit.Feed(b) {
				st.msgs++
				// 只有 s2c 进 netchan：雷达要的是服务端下发的实体数据。
				if dir == "s2c" {
					sess.msgCount++
					// 🔴 逐条喂解码器，见 feedMsg 的注释。
					if dec != nil {
						sess.feedMsg(dec, dir, m)
					}
				}
			}
		}
	}

	sess.mu.Lock()
	sess.encrypted += uint64(okPkts)
	sess.mu.Unlock()

	sess.logDir(dir)

	// s2c 是实体数据唯一的来源方向，诊断三行只在这一侧打（否则每 3 秒重复两遍）。
	if dir == "s2c" {
		sess.logGNSDecodeStats()
	}
}

// feedMsg 把**一条** SNP 可靠消息喂给解码器。
//
// 🔴 这里曾经把消息载荷首尾相接成 netchan，再用 `varint cmd + varint size` 去切。
// 那是方向性错误，两处都错：
//
//  1. **边界被扔掉**：SNP 消息链（`0mssssss`）本来就给出每条消息的边界，
//     拼接之后就没了。然后再去一堆位打包数据里找 cmd/size —— 永远找不到。
//     现场表现就是 `已切=136` 从头到尾一动不动。
//  2. **长度字段不存在**：现场 230 条消息里有 180 条以 `01 00` 开头
//     （flags + varint 0），说明**每条 SNP 消息就是一条 netchan 消息**，
//     长度由 SNP 层给出，内层根本不需要长度字段。
//
// 现在的做法：`u8 flags` + `varint X` 剥掉，剩下的载荷原样喂给解码器。
// 解码器自己会在载荷里扫 float3，不需要 cmd/size。
func (sess *Session) feedMsg(dec *cs2proto.HeuristicDecoder, dir string, m []byte) {
	if len(m) < 2 {
		return
	}
	flags := m[0]
	off := 1
	if _, n, ok := cs2proto.ReadVarint(m[1:]); ok {
		off += n
	}
	if off >= len(m) {
		return
	}
	payload := m[off:]

	sess.mu.Lock()
	if sess.msgKinds == nil {
		sess.msgKinds = make(map[uint16]int)
	}
	sess.msgKinds[uint16(flags)<<8|uint16(payload[0])]++
	sess.mu.Unlock()

	// 🔴 2026-10-19 16:30 定案：载荷不是「一个 protobuf」，是**位打包的
	// netmessage 链**（硬规则 223）。原来这里直接 `ParsePB(payload)`，
	// 等于要求整条载荷恰好是一个 protobuf —— 现场 322 条里 0 条满足，
	// 于是全部计入「位打包」，`消息=0 玩家=0` 就是这么来的。
	//
	// 现在按位级规则逐条拆开，再逐条喂。判据不变：只有 body 能当完整
	// protobuf 解析的才喂（位打包 body 仍然要等 sendtable）。
	if msgs, _, err := gnsParseNetMsgs(m); err == nil && len(msgs) > 0 {
		sess.mu.Lock()
		if sess.gnsMsgCmds == nil {
			sess.gnsMsgCmds = make(map[uint32]int)
			sess.gnsMsgBytes = make(map[uint32]int)
		}
		for _, nm := range msgs {

			sess.gnsMsgCmds[nm.Cmd]++
			sess.gnsMsgBytes[nm.Cmd] += len(nm.Body)
			sess.gnsMsgTotal++
		}
		sess.mu.Unlock()

		fed := 0
		posN := 0
		posSeen := 0
		platN := 0
		platB := 0
		var evIDs map[uint64]int
		now := time.Now()
		for _, nm := range msgs {
			if nm.Cmd == 42 || nm.Cmd == 44 || nm.Cmd == 45 {
				sess.mu.Lock()
				sess.noteEntityMetadataLocked(nm.Cmd, nm.Body)
				sess.mu.Unlock()
			}
			if nm.Cmd == 55 && sess.entityDecoder != nil {
				sess.pipeline.reliableEntities.Add(1)
				_ = sess.entityDecoder.PacketEntities(nm.Body, now)
			}
			if nm.Cmd == 41 || nm.Cmd == 55 {
				if gnsWalkPB(nm.Body, nil) == nil {
					sess.mu.Lock()
					if nm.Cmd == 41 {
						sess.gnsSchemaMessages++
					} else if pe := gnsDecodePacketEnts(nm.Body); pe != nil && !pe.IsDelta {
						sess.gnsFullEntityMessages++
					}
					sess.mu.Unlock()
				}
				continue
			}
			if nm.Cmd == 40 {
				sess.mu.Lock()
				sess.noteGNSServerInfoLocked(nm.Body)
				sess.mu.Unlock()
				continue
			}
			if nm.Cmd == 60 {
				if gnsWalkPB(nm.Body, nil) == nil {
					sess.mu.Lock()
					sess.noteGNSPlayers(gnsParsePlayerList(nm.Body))
					sess.mu.Unlock()
				}
				continue
			}
			// 🔴 硬规则 245：先摘掉完美平台的 HTML 注入。
			//
			// cmd=207 是 svc_GameEvent 通道，其中 eventid=226 是平台塞进来的
			// HTML（`<font>…<img src='http://pwacdn.wmpvp.com/...'>`）。
			// 07:55 现场实测它在 cmd=207 里占 94.4%、在整条 s2c 载荷里约 90%。
			// 继续喂给 protobuf 解码器只是白烧 CPU，还会把字节排名占满。
			if nm.Cmd == gnsCmdGameEvent {
				if id, ok := gnsGameEventID(nm.Body); ok {

					if evIDs == nil {
						evIDs = make(map[uint64]int, 8)
					}
					evIDs[uint64(id)]++
				}
			}
			// 🔴 cmd=208 = `svc_SosStartSoundEvent`（硬规则 290），走专用解析。
			//
			// 它不能靠启发式扫 float3 —— 那会同时扫出 tag2 的位域和 blob 尾部的
			// 垃圾浮点。这里按 protobuf 字段号精确取 field3（source_entity_index）
			// 和 field5 的 packed_params blob，再按定案的布局取原点。
			// 产物只进声音层（Snapshot.Sounds），不进 players。
			if nm.Cmd == gnsCmdEntityPos {
				posSeen++
				if ent, p, tail, ok := gnsParsePosMsg(nm.Body); ok {
					sess.mu.Lock()
					sess.noteGNSPlayerPos(ent, p, now)
					sess.noteGNSPosTail(tail)
					sess.mu.Unlock()
					posN++
					continue
				}
			}
			// 🔴 硬规则 250：cmd=60 是**玩家名单**（userid → SteamID64）。
			//
			// 它不提供位置也不提供队伍，但它是唯一能回答「这局到底几个人」的消息。
			// 08:14 那局 cmd=208 有 22 个实体索引、cmd=60 只有 7 个人 ——
			// 没有这个对照，雷达上多出来的目标会被误当成敌人。
			if nm.Cmd == gnsCmdPlayerList {
				if list := gnsParsePlayerList(nm.Body); len(list) > 0 {
					sess.mu.Lock()
					sess.noteGNSPlayers(list)
					sess.mu.Unlock()
					continue
				}
			}
			if ents, e := handshake.ParsePB(nm.Body); e != nil || len(ents) == 0 {
				continue
			}
			// Parsed protobuf is not a decoded player; do not float-scan event/table blobs.
			fed++
		}
		sess.mu.Lock()
		sess.gnsMsgPb += fed
		sess.gnsPosMsgs += posN
		sess.gnsPosSeen += posSeen
		sess.gnsPlatHTML += platN
		sess.gnsPlatHTMLBytes += platB
		if len(evIDs) > 0 {
			if sess.gnsEventIDs == nil {
				sess.gnsEventIDs = make(map[uint64]int, 16)
			}
			for k, v := range evIDs {
				sess.gnsEventIDs[k] += v
			}
		}
		if posN > 0 && sess.gnsPosFirst.IsZero() {
			sess.gnsPosFirst = now
		}
		sess.decoded += uint64(fed)
		sess.netchanParsed += len(m)
		sess.mu.Unlock()
		return
	}

	if flags == 1 || flags == 3 {
		sess.mu.Lock()
		sess.gnsMsgUnparsed++
		sess.netchanParsed += len(m)
		sess.mu.Unlock()
		return
	}
	// 走不了位级解析的载荷（首字节不是 0x01）：回退到「整条当一个 protobuf」。
	//
	// 这条兜底是给**别的帧类型**用的（现场 6/328 条是 0x03/0xa1/0xfc/0xb0），
	// 也是测试夹具用的格式（`05 00 0a 0c ...`）。不能直接丢掉：
	// 万一某类载荷确实是单个 protobuf，丢掉就等于漏解。
	//
	// ⚠ 但**绝不**回退到「盲扫 12 字节窗口」—— 那会在位打包数据上刷出
	// 几百个假坐标，雷达显示一堆幽灵目标，比什么都不显示更糟。
	if ents, err := handshake.ParsePB(payload); err == nil && len(ents) > 0 {
		msg := cs2proto.Msg{Cmd: uint64(flags), Data: payload, Raw: m}
		if err := dec.Feed(&msg, dir); err == nil {
			sess.mu.Lock()
			sess.decoded++
			sess.netchanParsed += len(m)
			sess.mu.Unlock()
			return
		}
	}

	sess.mu.Lock()
	sess.msgBitpacked++
	sess.gnsMsgUnparsed++
	sess.netchanParsed += len(m)
	sess.mu.Unlock()
}

// feedNetchanLocked 尝试从 netchan 字节流里切出 CS2 的 netmessage 并喂给解码器。
//
// 内层封装（cmd/size 的确切编码）还没定案，所以这里只做"能切就切"：
// 用 cs2proto.ParseStream 切 varint cmd + varint size，失败就原样留着等更多字节。
// 一旦封装定下来，改这里的解析器即可，SNP 三层不受影响。
func (sess *Session) feedNetchanLocked(dec *cs2proto.HeuristicDecoder, dir string) {
	if sess.netchanParsed >= len(sess.netchan) {
		return
	}
	list, _ := cs2proto.ParseStream(sess.netchan[sess.netchanParsed:], cs2proto.MaxCmd)

	// ParseStream 在尾部有半条消息时返回 ErrTruncated，但前面已经切出来的完整消息是可信的。
	// 旧实现只要 err != nil 就整段不动 —— 等于"尾部半条"把已经切好的消息也一起扣住了，
	// 现场表现就是 `已切` 永远停在 0。
	used := 0
	for i := range list {
		used += len(list[i].Raw)
	}
	if used == 0 {
		sess.probeNetchanLocked()
		return
	}
	sess.netchanParsed += used
	for i := range list {
		_ = dec.Feed(&list[i], dir)
	}
	sess.mu.Lock()
	sess.decoded += uint64(len(list))
	sess.mu.Unlock()
}

// probeNetchanLocked 在严格分帧一直切不出消息时做一次取证，只跑一次。
//
// 要分开的是两种完全不同的失败：
//   - **起点不是消息边界**：本地复现包是从流中间开始的（可靠流起点 21493），
//     从 0 起必然切不出东西；这种只要现场从连接起点开始抓就能自愈。
//   - **帧格式不对**：全偏移也扫不出像样的链。那就得回去改解析器。
//
// 以前只有一个 `已切=0`，这两种情况分不开，所以只能靠猜。
func (sess *Session) probeNetchanLocked() {
	if sess.netchanProbed || len(sess.netchan) < 8<<10 {
		return
	}
	sess.netchanProbed = true
	zN, zCov, bN, bCov := cs2proto.ChainProbe(sess.netchan, cs2proto.MaxCmd)
	head := sess.netchan
	if len(head) > 64 {
		head = head[:64]
	}
	gnsLogf("[snp] netchan 分帧取证：长度=%d 从0起=%d条/覆盖%d 全偏移最佳=%d条/覆盖%d 头64=%x",
		len(sess.netchan), zN, zCov, bN, bCov, head)
	if zN == 0 && bN <= 1 {
		gnsLogf("[snp] 判定：netchan 不是 varint cmd+size 封装的，需要改内层解析器")
	} else if zN == 0 {
		gnsLogf("[snp] 判定：流起点不在消息边界上，从连接建立时开始抓就能对齐")
	}
}

// logDir emits rate-limited aggregate counters only.
func (sess *Session) logDir(dir string) {
	// Counters only. No session/device ID, key/scheme, payload, world position,
	// player metadata or filesystem path may enter this operational log.
	st := sess.statsFor(dir)
	now := time.Now()
	if now.Sub(st.lastLog) < 3*time.Second {
		return
	}
	st.lastLog = now
	log.Printf("decoder counters: packets=%d reliable_segments=%d unreliable_messages=%d malformed=%d messages=%d", st.pkts, st.segs, st.unrels, st.bad, st.msgs)
}

// logMsgStats 把消息的长度分布与首字节分布打进日志。
//
// 这两个分布是判断内层封装的直接依据：
//   - 首字节高度集中（比如只有 01/03）⇒ 每条消息有固定标志字节，字节对齐
//   - 首字节发散 ⇒ 位打包，消息之间不是字节边界
func (sess *Session) logMsgStats() {
	lens := map[int]int{}
	first := map[byte]int{}
	n := 0
	off := 0
	for off+4 <= len(sess.msgFramed) {
		l := int(binary.LittleEndian.Uint32(sess.msgFramed[off:]))
		off += 4
		if off+l > len(sess.msgFramed) {
			break
		}
		n++
		lens[l]++
		if l > 0 {
			first[sess.msgFramed[off]]++
		}
		off += l
	}
	if n == 0 {
		return
	}

	type kv struct {
		k, v int
	}
	top := func(m map[int]int, k int) []kv {
		var a []kv
		for kk, vv := range m {
			a = append(a, kv{kk, vv})
		}
		sort.Slice(a, func(i, j int) bool { return a[i].v > a[j].v })
		if len(a) > k {
			a = a[:k]
		}
		return a
	}

	var sb strings.Builder
	for _, e := range top(lens, 6) {
		fmt.Fprintf(&sb, " %d×%d", e.k, e.v)
	}
	var fb strings.Builder
	fm := map[int]int{}
	for b, c := range first {
		fm[int(b)] = c
	}
	for _, e := range top(fm, 6) {
		fmt.Fprintf(&fb, " %02x×%d", e.k, e.v)
	}
	gnsLogf("[msg] 共 %d 条｜长度分布（前6）%s｜首字节分布（前6）%s",
		n, sb.String(), fb.String())

	// 消息分类：flags + 载荷首字节。类型数收敛说明分帧对了；
	// 发散说明还在错位区（中途开抓时前几十条必然是碎片）。
	km := map[int]int{}
	for k, c := range sess.msgKinds {
		km[int(k)] = c
	}
	var kb strings.Builder
	for _, e := range top(km, 8) {
		fmt.Fprintf(&kb, " %02x/%02x×%d", e.k>>8, e.k&0xff, e.v)
	}
	gnsLogf("[msg] 分类（flags/载荷首字节，前8）%s", kb.String())
	gnsLogf("[msg] 载荷类型：protobuf %d 条 / 位打包 %d 条（位打包块要等 sendtable 才能解）",
		n-sess.msgBitpacked, sess.msgBitpacked)

	sess.logGNSDecodeStats()
}

// logGNSGameEvents 把「平台 HTML 注入」和「真实游戏事件」分开报。
//
// 存在的理由见 gnsevent.go 文件头：cmd=207 里 94.4% 的字节是完美平台往游戏里
// 塞的广告 HTML，它会把 `[gnsmsg] 按字节量排` 的第一名永远占住，真实信号看不见。
// 拆开之后这一行才是「这一局到底有哪些游戏事件」的可靠读数 ——
// 下一轮要认 player_death / player_team 就从这里下手。
func (sess *Session) logGNSGameEvents() {
	if sess.gnsPlatHTML == 0 && len(sess.gnsEventIDs) == 0 {
		return
	}
	total := 0
	for _, v := range sess.gnsMsgBytes {
		total += v
	}
	if sess.gnsPlatHTML > 0 {
		pct := 0.0
		if total > 0 {
			pct = float64(sess.gnsPlatHTMLBytes) * 100 / float64(total)
		}
		gnsLogf("[gnsmsg] 平台 HTML 注入（eventid=226）：%d 条 / %.1f MB —— 占 s2c 载荷 %.1f%%，已跳过",
			sess.gnsPlatHTML, float64(sess.gnsPlatHTMLBytes)/(1<<20), pct)
	}
	if len(sess.gnsEventIDs) > 0 {
		type kv struct {
			id uint64
			n  int
		}
		list := make([]kv, 0, len(sess.gnsEventIDs))
		for k, v := range sess.gnsEventIDs {
			list = append(list, kv{k, v})
		}
		sort.Slice(list, func(i, j int) bool { return list[i].n > list[j].n })
		var b strings.Builder
		for i, e := range list {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&b, " %d×%d", e.id, e.n)
		}
		gnsLogf("[gnsmsg] 真实游戏事件（按 eventid，已剔除平台 HTML）：种类=%d｜前8%s",
			len(list), b.String())
	}
}

// logGNSDecodeStats 打「位级分帧 / 吃满率 / 真坐标」三行，**每 3 秒一次**。//
// 🔴 2026-10-19 22:53 那局暴露的问题：这三行原来只挂在 logMsgStats 里，
// 而 logMsgStats 的触发条件是「可靠消息累计满 4000 条」。那局只跑了 70 秒、
// 3297 条，**一条都没打出来** —— 于是 `[gnspos]` 里的「当前实体 N 个」
// （雷达真正画出来的目标数，唯一的产品指标）根本没机会出现在日志里，
// 看起来像「什么都没解出来」，实际上可能一直在出目标。
//
// 现在挂到 logDir 的 3 秒节拍上：数字单调增长就是好的，不增长就说明卡住。
func (sess *Session) logGNSDecodeStats() {
	if sess.gnsStatAt != (time.Time{}) && time.Since(sess.gnsStatAt) < 3*time.Second {
		return
	}
	sess.gnsStatAt = time.Now()

	// 这一行是判断「分帧到底对没对」的主指标：
	//   - cmd 种类少（<20）且集中在少数几个 ⇒ 分帧对了
	//   - cmd 种类上百、每个只出现一两次 ⇒ 还在错位区
	//   - 总条数为 0 ⇒ 载荷首字节不是 0x01，或者消息根本没进来
	if sess.gnsMsgTotal > 0 {
		var cb strings.Builder
		for _, e := range gnsTopCmds(sess.gnsMsgCmds, 10) {
			fmt.Fprintf(&cb, " %d×%d", e.Cmd, e.N)
		}
		gnsLogf("[gnsmsg] 位级分帧：%d 条 netmessage（来自 %d 条可靠消息）｜cmd 种类=%d｜前10%s",
			sess.gnsMsgTotal, sess.msgCount, len(sess.gnsMsgCmds), cb.String())
		gnsLogf("[gnsmsg] body 当 protobuf 喂进解码器 %d 条｜首字节非 0x01 跳过 %d 条",
			sess.gnsMsgPb, sess.gnsMsgUnparsed)
		// 按**字节量**再排一次：实体快照「条数少、每条大」，按条数永远看不见。
		var bb strings.Builder
		for _, e := range gnsTopCmdsByBytes(sess.gnsMsgCmds, sess.gnsMsgBytes, 8) {
			fmt.Fprintf(&bb, " %d×%d(均%d)", e.Cmd, e.N, e.Avg)
		}
		gnsLogf("[gnsmsg] 按字节量排前8%s", bb.String())
		sess.logGNSGameEvents()
		sess.logGNSPlayers()
	} else {
		// 一条都没解出来也要说一句：否则日志里静悄悄，分不清「没数据」
		// 和「有数据但格式不对」。
		gnsLogf("[gnsmsg] 还没有解出任何 netmessage（可靠消息 %d 条，载荷不是 01 开头的 %d 条）",
			sess.msgCount, sess.gnsMsgUnparsed)
	}
	sess.logNetMsgFrames()
	// [gnspos] 单独调，不走 logNetMsgFrames —— 那边开头有
	// `if len(sess.msgFramed) == 0 { return }`，msgFramed 一旦被清空
	// （每 4000 条落盘后清），坐标统计就再也打不出来。
	sess.logGNSPosStats()
	// [unrel] 跟这里共用 3 秒节流 —— 不可靠通道是实体表的高码率来源，
	// 它的统计必须和 [gnspos] 在同一拍上，否则两个数字对不上时间窗。
	sess.logGNSUnrelStats()
	if sess.entityDecoder == nil {
		gnsLogf("[entity] synced=false players=0 map=%s reason=等待ServerInfo", sess.serverMapName)
	} else {
		players, synced, status := sess.entityDecoder.Snapshot(time.Now())
		alive, t, ct := 0, 0, 0
		for _, p := range players {
			if p.Alive {
				alive++
			}
			if p.Team == 2 {
				t++
			}
			if p.Team == 3 {
				ct++
			}
		}
		gnsLogf("[entity] synced=%v players=%d alive=%d T=%d CT=%d map=%s status=%s", synced, len(players), alive, t, ct, sess.serverMapName, status)
	}
}

// logNetMsgFrames 按已定案的 netmessage 帧格式走一遍消息流，打统计。
//
// 🔴 帧格式已于 2026-10-19 用三个**互相独立且语义验证过**的锚点定案：
//
//	netmessage = [u8 cmd][varint size][body]     —— 全程字节对齐
//
//	userinfo   : 流 245   cmd=0x27(39) size=282  体 248..530
//	             （体是 CSVCMsg_CreateStringTable，string_data 是 snappy，
//	               uncompressed_size=253，字段严格吃满 282 字节）
//	VguiScreen : 流 1185  cmd=0x27(39) size=28   体 1187 起
//	SetConVar  : 流 55706 cmd=0x18(24) size=27   体 55708..55735
//	             （体是 CNETMsg_SetConVar，`sv_full_alltalk`=`true`）
//
// 这条日志的作用：现场跑一局，看 cmd 分布里有没有 `svc_PacketEntities`。
// 有 ⇒ 实体数据确实抓到了，卡在 sendtable/位打包解码；
// 没有 ⇒ 抓的位置不对（还在 signon/菜单），要先进到实际对局。
func (sess *Session) logNetMsgFrames() {
	if len(sess.msgFramed) == 0 {
		return
	}
	// 🔴 2026-10-19 16:30 起，这个函数改成**逐条**校验位级解析（硬规则 223）。
	//
	// 原来这里是把可靠消息首尾相接成一条流，再按 `[u8 cmd][varint size]`
	// 扫所有起点找最长链 —— 那是错的：边界本来就有（就是可靠消息自己的边界），
	// 拼起来反而把边界丢了。现场实测那条路最优只覆盖 0.3%~12%。
	//
	// 现在直接按消息边界逐条走，判据是「必须精确吃满（尾部 <16 位）」。
	var full, part, unparsed, total int
	var t03 int
	cmds := map[uint32]int{}
	off := 0
	for off+4 <= len(sess.msgFramed) {
		l := int(binary.LittleEndian.Uint32(sess.msgFramed[off:]))
		off += 4
		if l <= 0 || off+l > len(sess.msgFramed) {
			break
		}
		m := sess.msgFramed[off : off+l]
		off += l
		total++
		// 🔴 0x03 和「坏数据」必须分开计数（硬规则 265）。
		// 08:27 那局 signon 主体全是 0x03（7 条占约 15 万字节），
		// 原来一律记成「不是 netmessage 链」，看起来像解析失败，
		// 实际是被整段跳过 —— 这会让人误判「signon 没抓到」。
		if len(m) > 0 && m[0] == gnsMsgFlagSignon {
			t03++
		}
		msgs, _, err := gnsParseNetMsgs(m)
		if err != nil || len(msgs) == 0 {
			unparsed++
			continue
		}
		end := 0
		for _, nm := range msgs {
			cmds[nm.Cmd]++
			end += nm.HdrBits + len(nm.Body)*8
		}
		// 尾部允许 16 位以内的对齐填充。
		head := 8
		if _, n, ok := readGNSVarint(m[1:]); ok {
			head = 8 + n*8
		}
		body, _, parseErr := gnsReliablePayload(m)
		_ = head
		if parseErr == nil && len(body)*8-end < 16 {
			full++
		} else {
			part++
		}
	}
	gnsLogf("[net] 位级分帧校验：%d 条可靠消息｜精确吃满 %d｜未吃满 %d｜不是 netmessage 链 %d｜0x03 已交统一解析 %d",
		total, full, part, unparsed, t03)
	var cb strings.Builder
	for _, e := range gnsTopCmds(cmds, 10) {
		fmt.Fprintf(&cb, " %d×%d", e.Cmd, e.N)
	}
	gnsLogf("[net] cmd 种类=%d｜前10%s", len(cmds), cb.String())
}

// logGNSPosStats 打一行「声音层」的统计（原硬规则 225，语义已由硬规则 290 纠正）。
//
// 🔴 这一行**不再是**「雷达能不能用」的指标 —— cmd=208 是声音事件，
// 不是人物位置。它现在只回答「声音层有没有数据、覆盖多少个声源」。
// 真正的人物指标要等实体表（svc_PacketEntities delta）接通。
//   - `声源实体` 是当前 TTL 内的声源数（**不是**人数）；
//   - `命中` 是 cmd=208 成功解出声音事件的条数 / 总数，正常应接近 100%；
//   - `Hz/声源` 太低说明声音本身稀疏（1v1 局实测整局 41 条）。
func (sess *Session) logGNSPosStats() {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	if sess.gnsPosMsgs == 0 {
		// 一条都没有时必须明说 —— 否则「没日志」会被误读成「没跑」。
		gnsLogf("[gnspos] 还没解出任何声音事件（cmd=208 收到 %d 条，全部解析失败）", sess.gnsPosSeen)
		return
	}
	live := len(sess.gnsPlayerSnapshot(time.Now()))
	// 🔴 累计实体数 vs 瞬时活跃数：这两个数必须分开看。
	//
	// 08:14 那局 `解出坐标 476 条 / 当前实体 5 个` 被算成「平均采样 95.2 条/实体」，
	// 看起来每个实体刷得飞快，实际是 **22 个实体轮流刷新**、任意 6 秒窗口内
	// 只有 5 个是新鲜的。拿累计数除以瞬时数得出的指标没有任何物理意义，
	// 只会让人误判刷新率。所以改成：累计实体数 + 活跃数 + 每实体中位采样。
	distinct := len(sess.gnsPosEnts)
	med := 0
	if distinct > 0 {
		cnts := make([]int, 0, distinct)
		for _, c := range sess.gnsPosEnts {
			cnts = append(cnts, c)
		}
		sort.Ints(cnts)
		med = cnts[len(cnts)/2]
	}
	hit := 100.0
	if sess.gnsPosSeen > 0 {
		hit = float64(sess.gnsPosMsgs) * 100 / float64(sess.gnsPosSeen)
	}
	// 真实刷新率：条/秒 ÷ 实体数 = 每个实体每秒更新几次。
	// 低于 5 Hz 画面就会明显一跳一跳；64 是服务端 tick，理想值。
	rate, hz := 0.0, 0.0
	if !sess.gnsPosFirst.IsZero() {
		if sec := time.Since(sess.gnsPosFirst).Seconds(); sec > 0.5 {
			rate = float64(sess.gnsPosMsgs) / sec
			if distinct > 0 {
				hz = rate / float64(distinct)
			}
		}
	}
	players := len(sess.gnsPlayers)
	// 🔴 硬规则 290（2026-10-20 12:00）：cmd=208 = `svc_SosStartSoundEvent`，
	// 是**声音开始事件**，不是人物位置。字段级证据：field1 soundevent_guid /
	// field2 soundevent_hash(fixed32) / field3 source_entity_index / field4 seed /
	// field5 packed_params（内含原点）。数据形态证据：packed_params 前 4 字节
	// 只有 1 种（固定 schema 头），后 4 字节 40 种（声音种类哈希长尾）；
	// 且 `ent=366 (246.3,439.5,1652.0)` 与 `ent=78 (246.3,439.5,1616.0)` 同一瞬间
	// XY 完全相同、Z 差 36（脚下 vs 上身）—— pawn 只有一个位置，只能是同一处两个声音。
	// ⇒ 这里的产物进「声音层」，**不进 players**。
	gnsLogf("[gnspos] cmd=208（svc_SosStartSoundEvent）收到 %d 条｜解出声音事件 %d 条（命中 %.1f%%）"+
		"｜累计声源实体 %d 个（活跃 %d）｜每实体中位采样 %d 条"+
		"｜速率 %.1f 条/秒（%.1f Hz/声源）｜来源=gns-208 声音层｜⚠ 这是声音原点，不是人物位置",
		sess.gnsPosSeen, sess.gnsPosMsgs, hit, distinct, live, med, rate, hz)
	// 声源数远大于玩家数时明说 —— 否则「声音层有 22 个圈」会被当成 22 个敌人。
	if players > 0 && distinct > players {
		gnsLogf("[gnspos] ⚠ cmd=208 的 %d 个声源里，cmd=60 只报 %d 个玩家 ⇒ "+
			"多出来的 %d 个是非玩家声源（道具/投掷物/门/掠过音都能发声）"+
			"（按采样密度滤，见下面「道具过滤」那行）。分敌我要等队伍信息（硬规则 246）",
			distinct, players, distinct-players)
	}
	// 实体索引分布 —— 这是「怎么把道具滤掉」的唯一判据来源（硬规则 275）。
	//
	// 🔴 为什么必须打这一行：雷达上 46 个点里只有 7 个人，但**不能靠猜**去过滤。
	// 「玩家实体索引 ≤ 64」是个常见假设，可现场观测到的索引范围是 66..511，
	// 按 64 切很可能把真人一起藏掉 —— 那比多画几个道具糟糕得多。
	// 所以先把这个分布打出来：只要某一档的数量正好等于 cmd=60 的玩家数，
	// 那一档就是玩家；对不上就说明假设是错的，别急着改渲染。
	if distinct > 0 {
		const bucket = 64
		buckets := map[int]int{}
		minIdx, maxIdx := -1, -1
		for ent := range sess.gnsPosEnts {
			i := int(ent)
			buckets[i/bucket]++
			if minIdx < 0 || i < minIdx {
				minIdx = i
			}
			if i > maxIdx {
				maxIdx = i
			}
		}
		keys := make([]int, 0, len(buckets))
		for k := range buckets {
			keys = append(keys, k)
		}
		sort.Ints(keys)
		var b strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&b, " %d-%d:%d", k*bucket, k*bucket+bucket-1, buckets[k])
		}
		gnsLogf("[gnspos] 实体索引分布（按 %d 一档，min=%d max=%d，玩家 %d 个）：%s",
			bucket, minIdx, maxIdx, players, b.String())
		if n := buckets[0]; n > 0 {
			verdict := "对不上"
			if n == players {
				verdict = "**正好等于玩家数 ⇒ 「索引<64 是玩家」成立**"
			}
			gnsLogf("[gnspos] 索引 0-63 的实体 %d 个（玩家 %d 个）：%s", n, players, verdict)
		}
	}
	// 采样密度排名 —— 这是目前**唯一一个不用猜**的玩家/道具区分器。
	//
	// 🔴 为什么值得单独打一行：09:13 那局 `1092 条 ÷ 48 实体` 平均是 22.8 条/实体，
	// 但**中位数只有 3**。均值和中位数差 7 倍，说明采样极度偏斜：
	// 少数实体被高频刷新（真人），大多数几乎不动（道具/武器/移动物件）。
	// 服务端的快照预算是有上限的（实测稳定在 ~7.8 条/秒的绝对量），
	// 它显然把带宽优先给了会动的东西。
	//
	// ⇒ 所以「采样数前 N 名」比「索引范围」可靠得多：
	//   如果前 7 名的采样数断崖式领先第 8 名，那前 7 名就是那 7 个玩家。
	//   这一行打出来就能直接定过滤规则，不用再假设「索引<64 是玩家」。
	const topN = 16
	// 按**速率**排，不是按条数 —— 10:14 局中途有人加入，累计条数排名把断崖磨平到 1.7×，
	// 过滤整个失效。速率（条数 ÷ 自己的观察窗口）才是真正的判据（硬规则 282）。
	type entRate struct {
		idx  uint32
		n    int
		rate float64
	}
	nowLog := time.Now()
	list := make([]entRate, 0, distinct)
	for ent, c := range sess.gnsPosEnts {
		list = append(list, entRate{ent, c, sess.gnsEntityRate(ent, nowLog)})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].rate != list[j].rate {
			return list[i].rate > list[j].rate
		}
		if list[i].n != list[j].n {
			return list[i].n > list[j].n
		}
		return list[i].idx < list[j].idx
	})
	if len(list) > topN {
		list = list[:topN]
	}
	var tb strings.Builder
	for _, e := range list {
		fmt.Fprintf(&tb, " %d:%d@%.2f", e.idx, e.n, e.rate)
	}
	// 标签必须写「cmd=60 报」而不是「玩家」—— 09:39 局它报 9 而现场 8 人（硬规则 278）。
	gnsLogf("[gnspos] 采样速率前 %d 的实体（索引:条数@条/秒，cmd=60 报 %d 人）：%s",
		len(list), players, tb.String())
	// 道具过滤的**实际生效状态**必须打出来。
	//
	// 🔴 为什么不能只在生效时打：雷达上从 43 个点变成 5 个点是**肉眼可见的巨大变化**。
	// 如果只在生效时打一行，用户看到点数变少会以为坏了；如果只在失败时打，
	// 又不知道到底滤没滤。所以两种都打，并且把判据（断崖倍数）一起写出来。
	if keep, why := sess.gnsPlayerLike(time.Now()); why != "" {
		if keep != nil {
			// 🔴 硬规则 290 之后，这个过滤**只影响「人物诊断」这一层**：
			// 画面画的是声音层全量（TTL 内，见 gnsSoundSnapshot），不过滤。
			// 所以这里必须写清「诊断保留」，不能再说「画面上从 N 降到 M」——
			// 那句话会让用户以为画面少画了东西，实际画面压根不画 players。
			gnsLogf("[gnspos] ✅ 道具过滤生效（仅人物诊断，声音层不过滤）：%s（诊断保留 %d/%d 个声源）",
				why, len(keep), distinct)
			// 保留数对了，不等于这些声源就代表这么多真人 —— 还要看有几个是新鲜的。
			//
			// 🔴 09:47 局就是这样：保留 9 个（用户确认现场 9 人，判据完全正确），
			// 但同一时刻只有 6 个在 TTL 内。不打这一行，会以为过滤漏了 3 个人。
			if fresh, stale := sess.gnsKeepFreshness(time.Now(), keep); stale != "" {
				gnsLogf("[gnspos] 过滤后 %d 个声源中 %d 个在 %.0f 秒内活跃发声；"+
					"其余：%s —— 站着不动 / 死亡 / 不在 PVS 时服务端不下发（cmd=208 是声音事件，硬规则 290），"+
					"声音层里这些点按最后已知原点留到 %.0f 秒",
					len(keep), fresh, gnsPosFresh.Seconds(), stale, gnsPosTTL.Seconds())
			}
		} else {
			// 同上：未启用过滤时画面也不受影响（画的是声音层全量），
			// 所以不能说「画面上仍有 N 个点」。
			gnsLogf("[gnspos] ⚪ 道具过滤未启用：%s（诊断保留全部 %d 个声源；声音层不受此影响）",
				why, distinct)
		}
	}
	// blob 尾部标签的取值分布（语义未定，只做画像）。
	if len(sess.gnsPosTail) > 0 {
		type kv struct {
			k uint32
			n int
		}
		arr := make([]kv, 0, len(sess.gnsPosTail))
		for k, n := range sess.gnsPosTail {
			arr = append(arr, kv{k, n})
		}
		sort.Slice(arr, func(i, j int) bool { return arr[i].n > arr[j].n })
		var b strings.Builder
		for i, e := range arr {
			if i >= 8 {
				break
			}
			fmt.Fprintf(&b, " %08x×%d", e.k, e.n)
		}
		gnsLogf("[gnspos] blob 尾部标签（语义未定，%d 种）：%s", len(arr), b.String())
	}
}

// plainDumpTarget 是要攒多少条明文才落一个文件。
//
// 32 条只够看出「前缀哪几个字节随包递增」；要定内层封装得看到足够多的
// 消息边界。
//
// 🔴 2026-10-19 16:07 现场：128 条 × 1151 字节 = 142 KB，只够到 signon 段，
// 进局后的实体消息一条都没有。128 → 512（约 570 KB），一次覆盖到开打之后。
// 更长的留痕交给 gns-plainbin-*.bin（全量二进制，见 savePlainBin）。
const plainDumpTarget = 512

// plainBinEvery 是「攒多少帧明文落一次二进制」。
//
// 4096 帧 × 1151 字节 ≈ 4.6 MB，配一个约 1.9 MB 的干净流，一份约 6.5 MB。
// 一局通常落 1~2 份。
const plainBinEvery = 4096

// plainBinMaxFiles 是一局最多落几份，防止长时间挂机把磁盘写满。
//
// 3 份 ≈ 20 MB，足够覆盖「进服 → 进游戏 → 打起来」三段；
// 再多也不会带来新的封装信息，只会重复。
const plainBinMaxFiles = 3

// msgHeadMax 是日志里要打印的消息头条数。
// 前 16 条足够看出「首字节是不是恒为 01」「第二字节是不是 varint 长度」。
const msgHeadMax = 16

// msgDumpEvery 是「攒多少条消息落一次盘」。
//
// 🔴 2026-10-19 14:14 现场：原来阈值是 64，只拿到前 147 条，而那 147 条全是 signon
// （120 条 99 字节心跳 + 12 条预缓存字符串表），没有一条实体数据。
// 4000 条约 6 MB，一局下来能落十几份，足够覆盖「进服 → 进游戏 → 打起来」全程。
const msgDumpEvery = 4000

// msgHead 是一条可靠消息的头部快照，只用于打日志。
type msgHead struct {
	idx  int
	size int
	head []byte
}

// savePlain discards legacy diagnostic buffers; it never persists plaintext.
func (sess *Session) savePlain(batch []string) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.plainWant, sess.plainDone = false, true
	sess.plainBuf = nil
}

// signonDumpBytes 是「连接起点那一段可靠流」攒多少字节就落一次盘。
//
// 08:12 那局第一条统计时 s2c 已出 146427 字节，那就是 signon 的量级
// （sendtable + 字符串表 + 首个完整快照 + GameEventList）。
// 取 256 KB 留一倍余量：够覆盖整段 signon，又不至于把整局都拖进来。
const signonDumpBytes = 256 << 10

// noteSignonStream is retired: no diagnostic copy of the signon stream.
func (sess *Session) noteSignonStream(b []byte) {
	sess.signonDump = nil
	sess.signonDone = true
}

// savePlainBin is retired: no diagnostic copy of decrypted frames.
func (sess *Session) savePlainBin(pts [][]byte) {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	sess.plainBin = nil
	sess.plainBinTotal = 0
}

// gnsStreamStat 是重建流的统计，只用于打日志。
type gnsStreamStat struct {
	frames int
	hdr    int
	holes  int
}

// gnsRebuildStream 从一批明文帧里重建那条连续流。
//
// 判据：只取**长度等于众数**的帧（小帧是控制消息，头长度不同），
// 从 offset 字段读出绝对位置，按位置排序后剥掉头部拼接。
func gnsRebuildStream(frames [][]byte) ([]byte, gnsStreamStat) {
	var st gnsStreamStat
	if len(frames) == 0 {
		return nil, st
	}
	// 众数长度
	cnt := make(map[int]int, 16)
	for _, f := range frames {
		if len(f) >= 16 {
			cnt[len(f)]++
		}
	}
	modal, best := 0, 0
	for ln, c := range cnt {
		if c > best || (c == best && ln > modal) {
			modal, best = ln, c
		}
	}
	if modal == 0 || best < 3 {
		return nil, st
	}
	st.hdr = 14 // 由现场定案：offset@8..13，载荷从 14 开始

	type piece struct {
		off int
		pay []byte
	}
	var pieces []piece
	for _, f := range frames {
		if len(f) != modal {
			continue
		}
		off := int(binary.LittleEndian.Uint32(f[8:12]))
		pieces = append(pieces, piece{off, f[st.hdr:]})
	}
	sort.Slice(pieces, func(i, j int) bool { return pieces[i].off < pieces[j].off })

	var out bytes.Buffer
	cur := -1
	for _, p := range pieces {
		if cur < 0 {
			out.Write(p.pay)
			cur = p.off + len(p.pay)
			st.frames++
			continue
		}
		if p.off > cur {
			st.holes += p.off - cur
			out.Write(make([]byte, p.off-cur))
		} else if p.off < cur {
			skip := cur - p.off
			if skip >= len(p.pay) {
				continue
			}
			p.pay = p.pay[skip:]
		}
		out.Write(p.pay)
		cur = p.off + len(p.pay)
		st.frames++
	}
	return out.Bytes(), st
}

// Snapshot 产出雷达画面。
//
// 🔴 硬规则 290（2026-10-20 12:00）—— 这里发生了本产品最重要的一次语义纠正：
//
// 过去两轮的逻辑是「cmd=208 有坐标就当真人物，没有就回退启发式浮点扫描」。
// 现在两条都撤掉：
//
//  1. **cmd=208 是 `svc_SosStartSoundEvent`（声音事件），不是人物位置。**
//     字段级逐项对上 `CMsgSosStartSoundEvent`（guid / hash / source_entity_index /
//     seed / packed_params），而且数据形态只在「声音」解释下成立
//     （两个不同 entity 同一瞬间同一 XY、Z 差 36；packed_params 后 4 字节 40 种哈希长尾）。
//     详见 `report/20261020-1200-对第三方静态分析的独立核验.md`。
//  2. **启发式浮点扫描永远不进 players。** 那是「扫一段像 float3 的字节」，
//     有合法 protobuf 外壳也不代表内部是位置；两个人靠近还会串换身份。
//     画一个身份不明的点，比画面空着更糟 —— 因为看的人会当真。
//
// 所以现在：`Players` 只来自实体表（`svc_PacketEntities` 的 delta 还原），
// 匹配profile及完整实体帧后发布人物；尚未同步时Players为空，Status说明原因。
// 声音事件走独立的 `Sounds` 层（前端用空心圈 + 渐隐 + 明确标注「非人物位置」）。
//
// 宁可显示「未同步」，也不要输出身份错误的点。
func (sess *Session) Snapshot() cs2proto.Snapshot {
	started := time.Now()
	defer func() { sess.perfSnapshot.Observe(time.Since(started)) }()
	sess.mu.Lock()
	defer sess.mu.Unlock()
	name := ""
	if sch := sess.anyScheme(); sch != nil {
		name = sch.Name()
	}
	now := time.Now()
	// 声音层：cmd=208 的真实语义。独立列表，绝不混进 players。
	sounds := sess.gnsSoundSnapshot(now)
	status := fmt.Sprintf("实体字段/delta 解码尚未完成（schema消息=%d，完整实体消息=%d）；只显示声音事件，不是人物位置", sess.gnsSchemaMessages, sess.gnsFullEntityMessages)
	// 地图层：ServerInfo优先；没有服务端地图时保留显式手选，不按声音坐标猜图。
	sess.updateMapInferLocked()
	mi := sess.mapInfoLocked()
	sess.logMapOnce(mi)
	var players []cs2proto.Player
	synced := false
	if sess.entityDecoder != nil {
		players, synced, status = sess.entityDecoder.Snapshot(now)
	}

	performance := map[string]any{"ingest": sess.perfIngest.Snapshot(), "process": sess.perfProcess.Snapshot(), "cycle_lock_wait": sess.perfCycleWait.Snapshot(), "snapshot": sess.perfSnapshot.Snapshot()}
	if sess.entityDecoder != nil {
		performance["entity"] = sess.entityDecoder.Performance()
	}
	return cs2proto.Snapshot{
		Performance: performance,
		Session:     sess.id,
		Players:     players,
		Sounds:      sounds,
		Decoded:     sess.decoded,
		Encrypted:   sess.encrypted,
		Scheme:      name,
		UpdatedAt:   now,
		Synced:      synced,
		Status:      status,
		Map:         mi.Def,
		MapState:    string(mi.State),
		MapSource:   mi.Source,
		MapStatus:   mi.Status,
	}
}

// saveUnrel discards legacy raw-message buffers without writing them.
func (sess *Session) saveUnrel() {
	sess.unrelDump = nil
	sess.unrelCount = 0
	sess.unrelHead = nil
}

// ProbeInfo 是方案搜索结果（含落选方案，便于排查）。
type ProbeInfo struct {
	Session   string `json:"session"`
	Direction string `json:"direction"`
	Frames    int    `json:"frames"`
	HasKey    bool   `json:"has_key"`
	HasPub    bool   `json:"has_pub"`
	// HasGNS 表示 GNS 双向握手材料是否齐了（齐了就能直接派生，不靠搜索）。
	HasGNS  bool               `json:"has_gns"`
	Results []cs2crypto.Result `json:"results"`
}

// Probe 返回方案搜索结果。
//
// 两个方向都有各自的候选排名，这里合并成一份：先 s2c 再 c2s，
// 并在 Direction 里写清当前展示的是哪一边。
func (sess *Session) Probe() ProbeInfo {
	sess.mu.Lock()
	defer sess.mu.Unlock()
	dir := "s2c"
	top := append([]cs2crypto.Result(nil), sess.stS2C.probeTop...)
	frames := len(sess.s2c)
	if len(top) == 0 {
		dir = "c2s"
		top = append([]cs2crypto.Result(nil), sess.stC2S.probeTop...)
		frames = len(sess.c2s)
	}
	if len(top) > 20 {
		top = top[:20]
	}
	return ProbeInfo{
		Session:   sess.id,
		Direction: dir,
		Frames:    frames,
		HasKey:    sess.clientPriv != nil,
		HasPub:    sess.serverPub != nil,
		HasGNS:    sess.gns != nil,
		Results:   top,
	}
}

// SetScheme 直接指定会话方案（跳过 KDF 探测）。
//
// 用途：共享密钥→会话密钥的 KDF 未知时，从目标进程内存里直接找到那把
// 能解开真实密文的密钥，再交给解码器。
//
// 不需要重置游标：scheme 为 nil 期间 decode() 在第一行就 return 了，
// fedFrames 还是 0，所以下一次 Process 会把缓冲里的帧全部从头喂一遍。
//
// 🔴 probeDir 必须**强制**写成 s2c：内存里找到的那把密钥是拿 s2c 帧验证出来的。
// 之前写成「只在为空时填 s2c」，结果 runProbe 早先可能已经把 probeDir 定成 c2s，
// 于是 decode() 拿 s2c 的密钥去解 c2s 的帧 —— 必然全失败，而且日志上什么都看不出来。
func (s *Store) SetScheme(id string, sch *cs2crypto.Scheme) {
	if sch == nil {
		return
	}
	sess := s.Get(id)
	sess.mu.Lock()
	// 内存里找到的那把密钥是拿 s2c 帧验证出来的，所以装到 s2c。
	// 反方向留给 tryGNS 用同一派生补上。
	sess.setSchemeLocked("s2c", sch)
	sess.plainWant = false
	sess.mu.Unlock()
}

// Stats 返回会话数与累计包数。
func (s *Store) Stats() (sessions int, packets uint64, batches uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sessions), s.packets, s.batches
}

// SessionIDs 返回当前会话标识列表（已排序）。
func (s *Store) SessionIDs() []string {
	s.mu.Lock()
	ids := make([]string, 0, len(s.sessions))
	for id := range s.sessions {
		ids = append(ids, id)
	}
	s.mu.Unlock()
	sort.Strings(ids)
	return ids
}

// Config 返回生效配置（只读）。
func (s *Store) Config() Config { return s.cfg }

// trySchemeWithMemoryIV 用「KDF 派生出的密钥 + 内存里的当前 IV」解帧。
//
// 为什么这个组合是对的：密钥由 HKDF 给（一旦 IV 高 4 字节对上，就说明
// KDF 的输入和展开都对了），nonce 由内存给（它是「读的那一刻」的当前值，
// 永远是最新的）。两头都取各自最确定的来源，不用去猜它们之间的差值。
//
// 换算方式：内存 IV 是当前 nonce，而 Scheme 里 GNSOpen 会算
// base + seq。所以只要把 base 取成
//
//	base = memIV - seqRef + 修正
//
// 那么对帧序号为 seq 的帧，算出来的 nonce 就是 memIV + (seq - seqRef) + 修正，
// 正好是「以最新帧为参照、往前退修正个包」。修正量取等比档位，
// 兜住「读内存期间又来了几个包」。
//
// probe 是从尾部取的（probe[0] 最新），所以 seqRef 取 probe[0]。
func trySchemeWithMemoryIV(keys *cs2crypto.GNSKeys, dir string,
	memSend, memRecv []byte, probe [][]byte) (*cs2crypto.Scheme, int) {

	if keys == nil || len(probe) == 0 {
		return nil, 0
	}
	key, memIV := keys.RecvKey, memRecv
	if dir == "c2s" {
		key, memIV = keys.SendKey, memSend
	}
	if len(key) != 32 || len(memIV) != 12 {
		return nil, 0
	}
	seqRef, ok := cs2crypto.FrameSeq(probe[0])
	if !ok {
		return nil, 0
	}
	for _, c := range cs2crypto.GNSNonceCorrections {
		base := cs2crypto.GNSIVForSeq(memIV, uint64(-int64(seqRef)+c))
		sch, err := cs2crypto.SchemeFromGNS(key, base)
		if err != nil {
			continue
		}
		n := 0
		for _, f := range probe {
			if _, err := sch.OpenFrame(0, f); err == nil {
				n++
				if n >= 3 {
					return sch, n
				}
			}
		}
	}
	return nil, 0
}
