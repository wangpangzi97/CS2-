package radarsrv

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"math"
	"testing"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/cs2proto"
)

// 这个文件回归的是"幽灵目标"：decode() 若每次从头重喂全部帧，
// 位移超过关联半径（256 单位）的目标会在自己的历史坐标处被重新建槽，
// 画面上多出重复目标。合成数据里 p2 在 60 帧内位移约 303 单位，正好越过阈值。

func uvarint(v uint64) []byte {
	var b []byte
	for v >= 0x80 {
		b = append(b, byte(v)|0x80)
		v >>= 7
	}
	return append(b, byte(v))
}

// snpBuilder 把 netchan 字节流包成**真实的 SNP 包**，让 decode() 走完
// SNP 帧 → 可靠流 → 可靠消息 → netchan 这四层。
//
// 为什么要这一步：GCM 明文是 SNP 的 Data frame，不是 netchan 消息
// （见 internal/cs2snp 的包注释）。直接把 `varint cmd + varint size` 当明文喂进去，
// 首字节 0x05 会被当成 `00 000 101` 的不可靠帧、sss=5 是保留位 → 坏帧。
//
// 每包只发一个可靠段（sss=7 延续到包尾），段里放一条可靠消息。
//
// 🔴 **每个包都必须带 24 位绝对流位置**：线格式规定 `mm` 只在「本包内第一次可靠段
// 或换通道后」表示绝对值，之后才是相对上一段结尾。所以这个状态的生命周期是一个包，
// 不是整个会话（见 cs2snp.Parser.beginPacket）。早期版本只在首包写位置字节，
// 解析器改成按包复位后就会错位。
type snpBuilder struct {
	pos int
}

func newSNPBuilder() *snpBuilder { return &snpBuilder{} }

// relMsgHdr 编码可靠消息头 `0mssssss [size 高位 varint]`。
// m=0（不带 msg_num），size<0x20 时头字节就是长度本身。
func relMsgHdr(n int) []byte {
	if n < 0x20 {
		return []byte{byte(n)}
	}
	return append([]byte{0x20 | byte(n&0x1f)}, uvarint(uint64(n>>5))...)
}

// wrap 把一个 tick 里的多条 netchan 消息各包成一个可靠段，装进**同一个** SNP 包。
//
// 🔴 每条 netchan 消息必须独占一个可靠段 —— 这是硬规则 201：
// 「每条 SNP 可靠消息 = 一条 netchan 消息，头 = u8 flags + varint X，**没有长度字段**」。
// 早期这个夹具把 3 条 `cmd/size/payload` 首尾相接塞进一个可靠段，等于假设
// 「一条 SNP 消息里能拼多条 netchan 消息」。那是把已经定案的边界又扔掉，
// 现场表现就是 `已切` 卡在 136 不动（feedMsg 只认第一条，剩下的当垃圾）。
//
// 段头用 `sss=0`（显式长度）而不是 `sss=7`（到包尾），这样一个包里能放多段；
// 首段带 24 位绝对位置（mm=00），后续段 mm=00 表示"紧跟上一段结尾"。
func (b *snpBuilder) wrap(msgs [][]byte) []byte {
	var out []byte
	for k, m := range msgs {
		msg := append(relMsgHdr(len(m)), m...)
		out = append(out, 0x40) // 010 00 000：可靠段，mm=00，sss=0（跟一字节长度）
		if k == 0 {
			// 只有本包第一段是绝对值，见 cs2snp.Parser.beginPacket。
			out = append(out, byte(b.pos), byte(b.pos>>8), byte(b.pos>>16))
		}
		out = append(out, byte(len(msg)))
		out = append(out, msg...)
		b.pos += len(msg)
	}
	return out
}

// streamAt 复刻 tools/mksession 的合成流：每帧 3 条消息，cmd=5/6/7，各带一个 float32 三元组。
//
// 🔴 返回的是**每条消息一份**，格式按硬规则 201：
//
//	u8 flags + varint X + 载荷
//
// `X` 在真实链路上是 0 或递增序号（现场 180/230 条以 `01 00` 开头），
// 这里统一写 0。载荷必须是**能严格解析完**的 protobuf（handshake.ParsePB 判据），
// 所以用 `0A 0C + 12 字节` 这种单字段消息 —— 单字段也算合法，
// 用 `len(ents) < 2` 当闸门会把这种合法载荷误杀。
func streamAt(tick, players int) [][]byte {
	out := make([][]byte, 0, players)
	for p := 0; p < players; p++ {
		ang := float64(tick)*0.004 + float64(p)*2.1
		x := float32(1200*math.Cos(ang) + float64(p)*37)
		y := float32(900*math.Sin(ang*0.8) + float64(p)*53)
		z := float32(64 + p*8)

		payload := []byte{0x0A, 12}
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(x))
		payload = append(payload, b[:]...)
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(y))
		payload = append(payload, b[:]...)
		binary.LittleEndian.PutUint32(b[:], math.Float32bits(z))
		payload = append(payload, b[:]...)

		msg := []byte{byte(5 + p)} // flags
		msg = append(msg, 0x00)    // varint X
		msg = append(msg, payload...)
		out = append(out, msg)
	}
	return out
}

func newTestSession(t *testing.T, frames int) *Session {
	t.Helper()
	sess, _ := newTestSessionN(t, frames)
	return sess
}

// newTestSessionN 除会话外还交出"继续加密后续帧"的闭包。
//
// 闭包与建会话时共用同一个 snpBuilder，所以追加的帧能接上可靠流位置 ——
// 这是必须的：SNP 的流位置跨包累加，另起一个 builder 会让第二段从 mm=00
// 再吐一次 24 位绝对位置，解析器却已进入"相对上一段"分支，直接错位。
func newTestSessionN(t *testing.T, frames int) (*Session, func(from, to int) [][]byte) {
	t.Helper()
	curve := ecdh.X25519()
	sPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPub := sPriv.PublicKey().Bytes()
	clientPriv := cPriv.Bytes()

	shared, err := cs2crypto.SharedSecret(clientPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	const offset = 2
	sch, err := cs2crypto.SchemeByName("hkdf-sha256/info-empty", "aes-256-gcm", "ctr-le-u64",
		offset, false, shared, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	prefix := []byte{0xAA, 0xBB}
	b := newSNPBuilder()
	seal := func(from, to int) [][]byte {
		out := make([][]byte, 0, to-from)
		for i := from; i < to; i++ {
			f, err := sch.SealFrame(i, prefix, b.wrap(streamAt(i, 3)))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, f)
		}
		return out
	}
	enc := seal(0, frames)

	return &Session{
		id:         "regression",
		clientPriv: clientPriv,
		serverPub:  serverPub,
		s2c:        enc,
		schemeS2C:  sch,
		decoder:    cs2proto.NewHeuristicDecoderWithTTL(64, time.Minute),
	}, seal
}

// TestDecodeIsIncremental 锁死"重复 decode 不得新增目标"。
//
// 真实链路上，采集器发完数据后 Close() 还会发一个空批次，
// 每次 ingest 都会触发一次 decode()，所以重复调用是常态而非异常。
func TestDecodeIsIncremental(t *testing.T) {
	sess := newTestSession(t, 60)

	sess.decode()
	first := sess.decoder.Len()
	if first != 3 {
		t.Fatalf("首次 decode 应解出 3 个目标，实际 %d", first)
	}

	// 模拟后续多次 ingest（含 Close 的空批次）触发的重复 decode。
	sess.decode()
	sess.decode()
	sess.decode()
	after := sess.decoder.Len()

	if after != first {
		t.Fatalf("重复 decode 产生了幽灵目标：首次 %d 个，重复 3 次后 %d 个", first, after)
	}
}

// TestDecodeSurvivesBufferTrim 覆盖"帧缓冲头部被丢弃"后的长会话行为。
//
// 两个必须同时成立的约束：
//  1. 游标不能用缓冲区下标 —— 丢帧后下标不再等于发送方包计数器，nonce 会错位；
//  2. 游标不能因为 len(frames) 触顶而永久卡住 —— 否则解码会静默停止。
func TestDecodeSurvivesBufferTrim(t *testing.T) {
	const maxFrames = 30
	sess, seal := newTestSessionN(t, 0)

	// 逐帧喂入 60 帧（模拟实时链路），每帧都 decode 一次。
	for i := 0; i < 60; i++ {
		f := seal(i, i+1)[0]
		sess.s2c, sess.s2cDropped = appendCapped(sess.s2c, f, maxFrames, sess.s2cDropped)
		sess.decode()
	}

	if sess.s2cDropped != 30 {
		t.Fatalf("缓冲区应已丢弃 30 帧，实际 %d", sess.s2cDropped)
	}
	if len(sess.s2c) != 30 {
		t.Fatalf("缓冲区应保留 30 帧，实际 %d", len(sess.s2c))
	}
	if sess.stS2C.fedFrames != 60 {
		t.Fatalf("绝对游标应推进到 60，实际 %d", sess.stS2C.fedFrames)
	}

	// 槽位必须推进到末帧位置，而不是停在缓冲区触顶那一刻。
	wantX := float32(1200*math.Cos(59*0.004+4.2) + 74)
	found := false
	for _, p := range sess.decoder.Snapshot() {
		if math.Abs(float64(p.Pos.X-wantX)) < 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("丢帧后解码停摆：快照里没有末帧目标（want x≈%.2f）", wantX)
	}
}

// TestStoreEvictsOldestSession 保证会话表不会无上限增长。
// 会话名由客户端给，不设上限就是一条内存放大路径（每会话最多留 2000 帧）。
func TestStoreEvictsOldestSession(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxSessions = 3
	st := NewStore(cfg)

	for _, id := range []string{"a", "b", "c"} {
		st.Get(id)
		time.Sleep(3 * time.Millisecond) // 拉开 updated，保证淘汰顺序确定
	}
	if n := len(st.sessions); n != 3 {
		t.Fatalf("应有 3 个会话，实际 %d", n)
	}

	st.Get("d")
	if n := len(st.sessions); n != 3 {
		t.Fatalf("超上限后应仍为 3 个会话，实际 %d", n)
	}
	if _, ok := st.sessions["a"]; ok {
		t.Fatal("最久未更新的会话 a 应被淘汰")
	}
	if _, ok := st.sessions["d"]; !ok {
		t.Fatal("新会话 d 应保留")
	}
}

// TestDecodeAppendsNewFrames 保证增量游标不会把"新到的帧"漏掉。
func TestDecodeAppendsNewFrames(t *testing.T) {
	sess, seal := newTestSessionN(t, 30)
	sess.decode()
	n1 := sess.decoder.Len()

	// 追加后续 30 帧，再 decode 一次，应把目标推进到末帧位置。
	sess.s2c = append(sess.s2c, seal(30, 60)...)
	sess.decode()

	if n := sess.decoder.Len(); n != n1 {
		t.Fatalf("增量追加不应改变目标数：%d → %d", n1, n)
	}
	if sess.stS2C.fedFrames != 60 {
		t.Fatalf("游标应推进到 60，实际 %d", sess.stS2C.fedFrames)
	}
	// 末帧 p2 的真值（p=2：ang = tick*0.004 + 4.2，x = 1200*cos(ang) + 74）
	wantX := float32(1200*math.Cos(59*0.004+4.2) + 74)
	snap := sess.decoder.Snapshot()
	found := false
	for _, p := range snap {
		if math.Abs(float64(p.Pos.X-wantX)) < 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("快照里没有推进到末帧的目标（want x≈%.2f）", wantX)
	}
}
