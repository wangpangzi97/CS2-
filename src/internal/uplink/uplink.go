// Package uplink supplies batch transport. Production collectors use NewRemote:
// HTTPS only, verified server identity, no redirects, terminal failure on error.
// NewLocal/Deliver remain for in-process fixtures and are not reachable from the
// production collector; they do not implement or embed the radar decoder.
package uplink

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"local/cs2-radar/internal/perfstat"
	"local/cs2-radar/internal/startupdiag"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Packet 是一个原始包（data 用 base64，JSON 友好）。
type Packet struct {
	TsMs int64  `json:"ts_ms"`
	Dir  string `json:"dir"` // c2s / s2c
	Src  string `json:"src"`
	Dst  string `json:"dst"`
	Data string `json:"data"` // base64
}

// Batch 是一次上行请求体。
type Batch struct {
	Session   string   `json:"session"`
	ServerPub string   `json:"server_pub,omitempty"` // base64，握手靶子
	Key       string   `json:"key,omitempty"`        // base64，挖到的 X25519 私钥
	Packets   []Packet `json:"packets"`
	Final     bool     `json:"final,omitempty"`
	// GNS 是 SteamNetworkingSockets 直连握手的全部密钥材料。
	// 有了它 + Key，解码端可以直接按 GNS 的 HKDF 派生会话密钥，
	// 不再需要在候选空间里猜 KDF / nonce / 密文起点。
	GNS *GNSMaterial `json:"gns,omitempty"`
	// GNSKeys 是从目标进程内存里**直接读出来**的会话密钥与基础 IV。
	//
	// 这是 KDF 派生走不通时的旁路：KDF 的输入里有两段无法枚举的原始字节
	// （四段 cert/crypt 的排列与边界），一旦拼错，密钥和 IV 会一起错，
	// 而且错得没有任何可观测迹象。而这两样在目标进程里是常驻的，
	// 读出来就能直接用 —— 不需要冻结，也不需要 hook。
	GNSKeys *GNSKeysMaterial `json:"gns_keys,omitempty"`

	// GNSIVs 是连接对象里那两把 12 字节 IV（base64）。
	//
	// 单独传的理由：IV 是一条**不依赖帧**的精确判据。
	// `FinishCryptoHandshake` 里是 `add qword [rsi+0x19f0], rax` —— 就地累加，
	// 所以只有低 8 字节随包前移，**高 4 字节整局不变**。
	// 于是「HKDF 派生出的 SendIV/RecvIV 的高 4 字节 == 内存 IV 的高 4 字节」
	// 就是一个 32 位精确判据，能在 1152 个变体里一次定死正确的那一组，
	// 完全不用等帧能不能解开。KDF 卡了十几轮，缺的就是这个判据。
	GNSIVs *GNSIVMaterial `json:"gns_ivs,omitempty"`
}

// GNSIVMaterial 是一条连接的两把 IV。
//
// 槽位依据反汇编：`[conn+0x19f0]` 是发送侧、`[conn+0x19fc]` 是接收侧。
// 这里带上两个 connID，解码端才能确认它属于本次握手而不是别的连接。
type GNSIVMaterial struct {
	ClientConnID string `json:"client_conn_id,omitempty"`
	ServerConnID string `json:"server_conn_id,omitempty"`
	SendIV       string `json:"send_iv,omitempty"`
	RecvIV       string `json:"recv_iv,omitempty"`
}

// Complete 表示两把 IV 都在（12 字节 base64 是 16 个字符）。
func (m *GNSIVMaterial) Complete() bool {
	return m != nil && len(m.SendIV) == 16 && len(m.RecvIV) == 16
}

// GNSKeysMaterial 是一条连接的会话密钥 + 基础 IV（base64）。
//
// 🔴 必须能装**两个方向**。
//
// GNS 的两个方向用两把**不同**的密钥（SendKey 上行 / RecvKey 下行），
// 早期这里只带一个方向（`Dir` + `Key` + `IV`），于是服务端只能解一边。
// 现场 13:24 那次日志从头到尾只有 `方向=c2s`，服务端下发的实体数据
// （s2c）一条没解 —— 雷达因此没有任何目标。
//
// Alt* 是第二个方向，字段含义与主字段完全相同；老采集器不填就退化成
// 单方向，不影响兼容。
type GNSKeysMaterial struct {
	ClientConnID string `json:"client_conn_id,omitempty"`
	ServerConnID string `json:"server_conn_id,omitempty"`
	// Dir 是 "c2s" 或 "s2c"：这把密钥用来解哪个方向。
	Dir string `json:"dir,omitempty"`
	Key string `json:"key,omitempty"`
	IV  string `json:"iv,omitempty"`

	// AltDir / AltKey / AltIV 是**另一个方向**的密钥与基础 IV。
	AltDir string `json:"alt_dir,omitempty"`
	AltKey string `json:"alt_key,omitempty"`
	AltIV  string `json:"alt_iv,omitempty"`
}

// HasAlt 表示材料里带了第二个方向。
func (m *GNSKeysMaterial) HasAlt() bool {
	return m != nil && (m.AltDir == "c2s" || m.AltDir == "s2c") &&
		len(m.AltKey) == 44 && len(m.AltIV) == 16
}

// Complete 表示材料齐了。
//
// 顺带卡一下 base64 长度：32 字节密钥是 44 个字符、12 字节 IV 是 16 个。
// 不卡的话，一个被截断的材料也会被判成"完整"，然后解码端才会在
// SchemeFromGNS 里报错 —— 那时候日志已经说"已下发"了，排查会绕远路。
func (m *GNSKeysMaterial) Complete() bool {
	return m != nil && (m.Dir == "c2s" || m.Dir == "s2c") &&
		len(m.Key) == 44 && len(m.IV) == 16
}

// GNSMaterial 是一次握手的原始字节（全部 base64）。
//
// 字段含义见 internal/cs2crypto.GNSHandshake：cert/crypt 必须是**线上原始
// 子消息字节**，不能重新序列化 —— GNS 的 HKDF 把它们原样拼进 context。
type GNSMaterial struct {
	ClientConnID string `json:"client_conn_id,omitempty"`
	ServerConnID string `json:"server_conn_id,omitempty"`
	ClientPub    string `json:"client_eph_pub,omitempty"`
	ServerPub    string `json:"server_eph_pub,omitempty"`
	ClientNonce  string `json:"client_nonce,omitempty"`
	ServerNonce  string `json:"server_nonce,omitempty"`
	ClientCert   string `json:"client_cert,omitempty"`
	ServerCert   string `json:"server_cert,omitempty"`
	ClientCrypt  string `json:"client_crypt,omitempty"`
	ServerCrypt  string `json:"server_crypt,omitempty"`
}

// Complete 表示双向材料是否齐全（齐了才值得往下传）。
func (m *GNSMaterial) Complete() bool {
	return m != nil && m.ClientConnID != "" && m.ServerConnID != "" &&
		m.ClientPub != "" && m.ServerPub != "" &&
		m.ClientNonce != "" && m.ServerNonce != "" &&
		m.ClientCert != "" && m.ServerCert != "" &&
		m.ClientCrypt != "" && m.ServerCrypt != ""
}

// Sink 是「批次出口」的抽象。
//
// 目前两种用法都基于同一个 *Sender，只是出口不同：
//
//	远端模式：Deliver 为空 → 批次 JSON POST 到 URL
//	本机模式：Deliver 非空 → 批次直接交给本进程内的 radarsrv.Store，不经网络
//
// 抽出接口是为了让采集器不必区分两种模式。
type Sink interface {
	SetHandshake(pub []byte)
	SetServerPub(pub []byte)
	SetKey(priv []byte)
	SetGNS(m *GNSMaterial)
	SetGNSKeys(m *GNSKeysMaterial)
	SetGNSIVs(m *GNSIVMaterial)
	Push(p Packet)
	Flush(final bool) error
	Close() error
	Stats() map[string]any
	Mode() string
}

// Sender 是批量上行发送器。
type Sender struct {
	perfQueue, perfDeliver, perfFlushLock perfstat.Timer
	firstQueuedAt                         time.Time
	closed                                atomic.Bool
	flushMu                               sync.Mutex
	droppedPackets                        atomic.Uint64
	URL                                   string
	Session                               string
	MaxPackets                            int
	FlushInterval                         time.Duration

	// Deliver 非空时，批次直接交给它（本机模式），不走 HTTP。
	// 设了它就不需要 URL / Token / CACert。
	Deliver func(*Batch) error

	// Token 非空时随每个请求带上 X-Auth-Token 头；服务端配了 -token 就必须填。
	Token string
	// Authorize is provided by the native device-bound data session. It signs
	// the method, audience, path, token hash, timestamp, nonce and exact body.
	Authorize func(*http.Request, []byte) (*http.Response, error)
	// CACert 指向 PEM 格式 CA/自签证书，用于校验服务端证书。
	CACert string

	hcOnce      sync.Once
	hc          *http.Client
	hcErr       error
	halted      atomic.Bool
	failureOnce sync.Once
	failureCh   chan struct{}
	failureMu   sync.Mutex
	failureErr  error

	mu        sync.Mutex
	buf       []Packet
	clientPub string // 客户端临时公钥（找私钥的靶子，不参与 ECDH）
	serverPub string // 服务器临时公钥（ECDH 的对端）
	key       string
	gns       *GNSMaterial
	gnsKeys   *GNSKeysMaterial
	gnsIVs    *GNSIVMaterial

	stopCh chan struct{}
	doneCh chan struct{}

	// closeOnce 保证 Close 只做一次收尾（停 ticker + 最后一次 Flush）。
	// 没有它的话，重复 Close 会多发一个空批次 —— 调用点普遍是
	// 「defer Close() + 中途显式 Close()」的写法，重复调用是常态。
	closeOnce sync.Once
	closeErr  error

	sentBatches atomic.Uint64
	sentPackets atomic.Uint64
	failed      atomic.Uint64
	lastErr     atomic.Value // string
}

// New is a low-level constructor. The HTTP delivery boundary enforces HTTPS.
// Production code should use NewRemote to validate CA and credentials up front.
func New(url, session string) *Sender {
	s := &Sender{
		URL:           url,
		Session:       session,
		MaxPackets:    256,
		FlushInterval: 100 * time.Millisecond,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		failureCh:     make(chan struct{}),
	}
	go s.loop()
	return s
}

// NewLocal 创建本机模式的发送器：批次直接交给 deliver，不经网络。
//
// 本机模式的两个参数都比远端激进 —— 延迟要低，因为画面就在同一台机器上，
// 没必要攒 2 秒才出一次坐标。
func NewLocal(session string, deliver func(*Batch) error) *Sender {
	s := &Sender{
		Session:       session,
		MaxPackets:    64,
		FlushInterval: 200 * time.Millisecond,
		Deliver:       deliver,
		stopCh:        make(chan struct{}),
		doneCh:        make(chan struct{}),
		failureCh:     make(chan struct{}),
	}
	go s.loop()
	return s
}

// Mode 返回出口模式，用于展示。
func (s *Sender) Mode() string {
	if s.Deliver != nil {
		return "local"
	}
	return "remote"
}

// SetHandshake 记录**客户端**握手公钥（内存里找私钥的靶子）。
//
// 🔴 它**不是** ECDH 的对端。对端是服务器临时公钥，走 SetServerPub。
// 早期版本把这两个混成一个字段，结果是拿「客户端私钥 × 客户端公钥」算共享密钥，
// 数学上必然错 —— 密钥能挖到、包也在流，但一条消息都解不出来。
func (s *Sender) SetHandshake(pub []byte) {
	s.mu.Lock()
	if s.halted.Load() || s.closed.Load() {
		s.mu.Unlock()
		return
	}
	s.clientPub = base64.StdEncoding.EncodeToString(pub)
	s.mu.Unlock()
}

// SetServerPub 记录**服务器**临时公钥（来自 ServerHello 的 f7→f1→f2）。
// 这是 SharedSecret(clientPriv, serverPub) 的第二个参数。
func (s *Sender) SetServerPub(pub []byte) {
	s.mu.Lock()
	if s.halted.Load() || s.closed.Load() {
		s.mu.Unlock()
		return
	}
	s.serverPub = base64.StdEncoding.EncodeToString(pub)
	s.mu.Unlock()
}

// SetKey 记录挖到的客户端私钥。
func (s *Sender) SetKey(priv []byte) {
	s.mu.Lock()
	if s.halted.Load() || s.closed.Load() {
		s.mu.Unlock()
		return
	}
	s.key = base64.StdEncoding.EncodeToString(priv)
	s.mu.Unlock()
}

// SetGNS 记录 GNS 握手材料（双向）。齐了才会被带上批次。
func (s *Sender) SetGNS(m *GNSMaterial) {
	if !m.Complete() {
		return
	}
	s.mu.Lock()
	if s.halted.Load() || s.closed.Load() {
		s.mu.Unlock()
		return
	}
	s.gns = m
	s.mu.Unlock()
}

// SetGNSKeys 记录从内存直接读到的会话密钥 + 基础 IV。
//
// 一旦设上，解码端会优先用它（见 radarsrv.Store.Ingest）—— 它是实测
// 认证过的，比任何派生结果都可靠。
func (s *Sender) SetGNSKeys(m *GNSKeysMaterial) {
	if !m.Complete() {
		return
	}
	s.mu.Lock()
	if s.halted.Load() || s.closed.Load() {
		s.mu.Unlock()
		return
	}
	s.gnsKeys = m
	s.mu.Unlock()
}

// SetGNSIVs 记录连接对象里的两把 IV。
//
// 与 SetGNSKeys 的区别：这个**不需要找到密钥**就能上报，只要 conn 对象
// 定位到了就有。解码端拿它做「KDF 变体 × IV 高 4 字节」的精确比对，
// 不依赖任何一帧能不能解开。
func (s *Sender) SetGNSIVs(m *GNSIVMaterial) {
	if !m.Complete() {
		return
	}
	s.mu.Lock()
	if s.halted.Load() || s.closed.Load() {
		s.mu.Unlock()
		return
	}
	s.gnsIVs = m
	s.mu.Unlock()
}

// Push 追加一个包。
func (s *Sender) Push(p Packet) {
	s.mu.Lock()
	if s.closed.Load() || s.halted.Load() {
		s.mu.Unlock()
		s.droppedPackets.Add(1)
		return
	}
	if len(s.buf) == 0 {
		s.firstQueuedAt = time.Now()
	}
	s.buf = append(s.buf, p)
	full := len(s.buf) >= s.MaxPackets
	s.mu.Unlock()
	if full {
		_ = s.Flush(false)
	}
}

// Flush 立即发送当前缓冲。
func (s *Sender) Flush(final bool) (err error) {
	if s.halted.Load() {
		return s.Err()
	}
	waiting := time.Now()
	s.flushMu.Lock()
	s.perfFlushLock.Observe(time.Since(waiting))
	defer s.flushMu.Unlock()
	defer func() {
		if err != nil && s.Deliver == nil {
			s.fail(err)
		}
	}()
	if s.halted.Load() {
		return s.Err()
	}
	lost := 0
	defer func() {
		if err != nil {
			s.failed.Add(1)
			s.droppedPackets.Add(uint64(lost))
			s.lastErr.Store(err.Error())
		}
	}()
	s.mu.Lock()
	if len(s.buf) == 0 && !final {
		s.mu.Unlock()
		return nil
	}
	b := Batch{
		Session:   s.Session,
		ServerPub: s.serverPub,
		Key:       s.key,
		Packets:   s.buf,
		Final:     final,
		GNS:       s.gns,
		GNSKeys:   s.gnsKeys,
		GNSIVs:    s.gnsIVs,
	}
	if len(b.Packets) > 0 && !s.firstQueuedAt.IsZero() {
		s.perfQueue.Observe(time.Since(s.firstQueuedAt))
	}
	s.firstQueuedAt = time.Time{}
	lost = len(b.Packets)
	s.buf = nil
	s.mu.Unlock()

	delivered := time.Now()
	defer func() { s.perfDeliver.Observe(time.Since(delivered)) }()
	// 本机模式：批次直接交给进程内的解码器，不经网络。
	if s.Deliver != nil {
		if err := s.Deliver(&b); err != nil {
			return err
		}
		s.sentBatches.Add(1)
		s.sentPackets.Add(uint64(len(b.Packets)))
		return nil
	}

	if err := ValidateEndpoint(s.URL); err != nil {
		return err
	}
	if s.Token == "" && s.Authorize == nil {
		return fmt.Errorf("data credential required")
	}
	body, err := json.Marshal(&b)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if s.Token != "" {
		req.Header.Set("X-Auth-Token", s.Token)
	}
	var resp *http.Response
	if s.Authorize != nil {
		resp, err = s.Authorize(req, body)
	} else {
		hc, e := s.client()
		if e != nil {
			return e
		}
		resp, err = hc.Do(req)
	}
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return &startupdiag.HTTPFailure{Status: resp.StatusCode}
	}
	s.sentBatches.Add(1)
	s.sentPackets.Add(uint64(len(b.Packets)))
	return nil
}

func (s *Sender) loop() {
	defer close(s.doneCh)
	t := time.NewTicker(s.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.failureCh:
			return
		case <-t.C:
			_ = s.Flush(false)
		}
	}
}

// Close 停止后台循环并做最后一次发送。
//
// 幂等：重复调用只做一次收尾，第二次起直接返回首次的结果。
// 调用点常见写法是「defer Close() + 中途显式 Close()」，必须容忍。
func (s *Sender) Close() error {
	s.closeOnce.Do(func() {
		s.closed.Store(true)
		close(s.stopCh)
		<-s.doneCh // 等 loop() 退出，避免它与收尾 Flush 并发
		s.closeErr = s.Flush(true)
	})
	return s.closeErr
}

// Stats 返回上行统计。
func (s *Sender) Stats() map[string]any {
	m := map[string]any{
		"batches":         s.sentBatches.Load(),
		"packets":         s.sentPackets.Load(),
		"failed":          s.failed.Load(),
		"dropped_packets": s.droppedPackets.Load(),
	}
	m["performance"] = map[string]any{"queue_oldest": s.perfQueue.Snapshot(), "deliver": s.perfDeliver.Snapshot(), "flush_lock_wait": s.perfFlushLock.Snapshot()}
	if v := s.lastErr.Load(); v != nil {
		m["last_error"] = v
	}
	return m
}
