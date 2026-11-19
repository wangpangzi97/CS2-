// Package keyfind 还原 capture.exe 中 main.(*keySearch) 家族的行为，
// 也就是"进程密钥"（X25519 私钥）的获取算法。
//
// 对应符号（capture.exe）：
//
//	main.verifyPriv              @0x179ea0  判定器：X25519(priv).PublicKey == targetPub
//	main.(*keySearch).probeHint  @0x1799a0
//	main.(*keySearch).scanHints  @0x17af40  标签 hint / udp4
//	main.(*keySearch).anchor     @0x17ab60
//	main.(*keySearch).scanAnchors@0x17b280  标签 adjacent / anchors，WaitGroup+newproc+sort.Slice
//	main.(*keySearch).scanWindows@0x17b6e0  标签 window
//	main.(*keySearch).chase      @0x17a860  标签 pointer，8 字节步长，指针范围 [0x10000,0x7FFFFFFFFFFF]
//	main.(*keySearch).check      @0x17a4e0  提交器：found=1 → sync.Once → close(chan) → callback
//	main.findPrivWithHints       @0x17bbc0  总编排
//	main.(*keySearch).recoverWorker @0x17a100 panic 包装 → "key scan worker failed"
//
// 三个错误文案（原文）：
//
//	handshake public key not found in readable memory
//	public key found, but no candidate private key matched
//	public key search reached the scan deadline
//
// 关键点：这是一个"已知公钥反查私钥"的暴力搜索 —— 只有 X25519 私钥能通过
// 标量乘推出与握手公钥相同的 32 字节，因此验证器等价于一次精确匹配。
package keyfind

import (
	"bytes"
	"crypto/ecdh"
	"errors"
	"fmt"
	"runtime"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"local/cs2-radar/internal/memscan"
)

const (
	// minPointer / maxPointer 是原程序 chase.func1 里校验指针范围的常量。
	minPointer = uintptr(0x10000)
	maxPointer = uintptr(0x7FFFFFFFFFFF)

	// stride 是指针链与窗口扫描的步长（8 字节）。
	stride = 8

	// blockSize 是窗口扫描的单次读取块大小。
	blockSize = 1 << 20

	keyLen = 32
)

var (
	ErrPubKeyNotFound = errors.New("handshake public key not found in readable memory")
	ErrNoCandidate    = errors.New("public key found, but no candidate private key matched")
	ErrDeadline       = errors.New("public key search reached the scan deadline")
	ErrWorkerPanic    = errors.New("key scan worker failed")
)

// Hint 对应 hint 表项（字段 addr / dist / priv / auto）。
//
// 2026-10-18 扩字段（原版 `main.keyHint` 只确证了前四个）：
//
//	Pub       这条 hint 是在哪个公钥下学到的（hex）。用来判断"还适用吗"。
//	Exe       目标进程 exe 的指纹（大小+时间戳），换了游戏版本就整批失效。
//	LearnedAt 学到的时间（RFC3339），仅用于诊断与淘汰。
//	Hits      这条 hint 命中过几次（跨会话累计），用于排序。
//
// 2026-10-19 再加三个"相对偏移"字段，用于跨会话 rebase：
//
//	ModuleOff  addr - 主映像基址。**这是最接近"hint 偏移"的东西** ——
//	           如果私钥落在 cs2.exe 的映像/固定映射区里，这个值跨会话稳定。
//	RegionOff  addr - 所属区域基址。区域会随 ASLR 移动，所以这个值只有在
//	           "区域布局本身稳定"时才有用（例如大小/保护属性都一致的堆块）。
//	RegionSize/RegionProtect/RegionType  用来在下次运行时**重新认出**那个区域。
//
// 用法：`HintCandidates()` 会把这些相对偏移在当前进程里展开成若干个候选地址，
// 逐个 probe（每个 32 字节）。哪个命中就说明哪种偏移是稳的 —— 这就是
// "自己测出 hint 偏移"的办法。
//
// ⚠ Priv **不落盘**。原版有 priv 字段，但把会话私钥写进磁盘是纯风险：
// 它下一次会话就失效，却会在磁盘上留下可被扫描的痕迹。这里永远留空。
type Hint struct {
	Addr uintptr `json:"addr"`
	Dist int     `json:"dist"`
	Priv string  `json:"priv,omitempty"` // 恒为空，见上
	Auto bool    `json:"auto"`

	Pub       string `json:"pub,omitempty"`
	Exe       string `json:"exe,omitempty"`
	LearnedAt string `json:"learned_at,omitempty"`
	Hits      int    `json:"hits,omitempty"`

	// ModuleOff 为 addr - ModuleBase。0 表示"没记录"，负数表示 addr 在主映像之下。
	ModuleOff int64 `json:"module_off,omitempty"`
	// RegionOff 为 addr - RegionBase。
	RegionOff int64 `json:"region_off,omitempty"`
	// 区域的指纹，用于下次认出同一个区域。
	RegionSize    uint64 `json:"region_size,omitempty"`
	RegionProtect uint32 `json:"region_protect,omitempty"`
	RegionType    uint32 `json:"region_type,omitempty"`
	// ModuleBase 是学习时的主映像基址，仅用于诊断输出（换算 RVA 展示给人看）。
	ModuleBase uintptr `json:"module_base,omitempty"`
	// RegionBase 是学习时所属区域的基址，仅用于诊断。
	RegionBase uintptr `json:"region_base,omitempty"`
}

// Search 对应 main.(*keySearch)。
type Search struct {
	Proc      *memscan.Process
	TargetPub []byte
	Deadline  time.Time

	// OnFound 对应 keySearch +0x70 的回调槽。
	OnFound func(priv []byte, tag string, addr uintptr)

	// MaxCandidates 是本重构新增的预算上限（原程序无此字段，靠 hint/anchor 提速）。
	MaxCandidates uint64

	// WindowStride 是窗口扫描的步长，默认 8。
	//
	// 说明：逆向只确证了 chase（指针链）用 8 字节步长；窗口扫描的步长未从二进制中
	// 还原。默认取 8 与指针链一致（Go/C++ 分配器给出的对象起始地址都是 8 字节对齐，
	// 因此实战中够用）；若目标密钥可能落在非 8 对齐位置，把它设为 1。
	WindowStride uintptr

	found  int32
	failed int32
	once   sync.Once
	done   chan struct{}

	err error

	reads      uint64
	bytesRead  uint64
	blocks     uint64
	shortReads uint64
	checks     uint64
	candidates uint64

	mu    sync.Mutex
	hints []Hint
}

// New 构造一个搜索器。
func New(proc *memscan.Process, targetPub []byte, deadline time.Time) *Search {
	return &Search{
		Proc:          proc,
		TargetPub:     targetPub,
		Deadline:      deadline,
		done:          make(chan struct{}),
		MaxCandidates: 4_000_000,
		WindowStride:  stride,
	}
}

// Done 在命中或失败后关闭。
func (s *Search) Done() <-chan struct{} { return s.done }

// Found 返回是否已命中。
func (s *Search) Found() bool { return atomic.LoadInt32(&s.found) == 1 }

// Err 返回失败原因。
func (s *Search) Err() error { return s.err }

// Stats 返回统计。
func (s *Search) Stats() map[string]uint64 {
	return map[string]uint64{
		"reads":      atomic.LoadUint64(&s.reads),
		"bytes":      atomic.LoadUint64(&s.bytesRead),
		"blocks":     atomic.LoadUint64(&s.blocks),
		"shortReads": atomic.LoadUint64(&s.shortReads),
		"checks":     atomic.LoadUint64(&s.checks),
		"candidates": atomic.LoadUint64(&s.candidates),
	}
}

// verifyPriv 逐字还原 main.verifyPriv @0x179ea0：
//
//	if len(priv)!=32 || len(pub)!=32 { return false }
//	k, err := ecdh.X25519().NewPrivateKey(priv); if err!=nil { return false }
//	return bytes.Equal(k.PublicKey().Bytes(), pub)
func (s *Search) verifyPriv(priv []byte) bool {
	if len(priv) != keyLen || len(s.TargetPub) != keyLen {
		return false
	}
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return false
	}
	return bytes.Equal(k.PublicKey().Bytes(), s.TargetPub)
}

// Check 对应 check @0x17a4e0（导出以便单测/动态验证直接调用）。
func (s *Search) Check(cand []byte, tag string, addr uintptr) bool {
	if atomic.LoadInt32(&s.found) == 1 {
		return false
	}
	atomic.AddUint64(&s.checks, 1)
	if !s.verifyPriv(cand) {
		return false
	}
	priv := make([]byte, keyLen)
	copy(priv, cand)
	atomic.StoreInt32(&s.found, 1)
	s.once.Do(func() {
		if s.OnFound != nil {
			s.OnFound(priv, tag, addr)
		}
		close(s.done)
	})
	return true
}

// ProbeHint 对应 probeHint @0x1799a0。
func (s *Search) ProbeHint(h Hint) bool {
	if h.Addr == 0 {
		return false
	}
	buf := make([]byte, keyLen)
	if err := s.readFull(h.Addr, buf); err != nil {
		return false
	}
	return s.Check(buf, "hint/udp4", h.Addr)
}

// AddHint 注册一个提示地址。
func (s *Search) AddHint(h Hint) {
	s.mu.Lock()
	s.hints = append(s.hints, h)
	s.mu.Unlock()
}

// scanHints 对应 scanHints @0x17af40。
func (s *Search) scanHints() bool {
	s.mu.Lock()
	hs := append([]Hint(nil), s.hints...)
	s.mu.Unlock()
	for _, h := range hs {
		if s.ProbeHint(h) {
			return true
		}
	}
	return false
}

// ProbeHintsResult 是 hint 快路径的结果。
//
// 为什么要单独一个结构：快路径的意义在于「读了多少字节」，这个数必须能被
// 报出来 —— 否则用户没法判断这次运行到底有没有走原版那条轻量路径。
// 原版快路径读几十~几百字节；全量扫描读 7.5 GB。两者差 7 个数量级。
type ProbeHintsResult struct {
	Hit  bool
	Priv []byte
	Tag  string
	Addr uintptr
	// Source 说明是哪种候选命中的：as-is / module+off / region+off。
	// 这是"hint 偏移到底稳不稳"的直接答案 —— 见 HintCandidates 的注释。
	Source string
	Tried  int    // 实际尝试过的候选条数
	Bytes  uint64 // 实际读的字节数（每条 32）
}

// ProbeHints 是 probeHint @0x1799a0 的批量形式：逐条读 32 字节验证，命中即停。
//
// 这就是原版的**快路径**：不冻结、不枚举区域、不扫描，只读若干个 32 字节。
// 命中时读量 = Tried*32 字节；全部 miss 也只有几十~几百字节。
//
// 与 scanHints 的区别：那个吃 s.hints（内部注册的），这个吃外部传入的
// （从磁盘加载的持久化 hint 表），并且回传读量供诊断使用。
func (s *Search) ProbeHints(hs []Hint) ProbeHintsResult {
	cands := make([]HintCand, 0, len(hs))
	for _, h := range hs {
		if h.Addr == 0 {
			continue
		}
		cands = append(cands, HintCand{Addr: h.Addr, Source: "as-is"})
	}
	return s.ProbeAddrs(cands)
}

// ProbeAddrs 是快路径的最底层：对一串候选地址逐个读 32 字节验证。
//
// 为什么要单独一层：跨会话 rebase 会把一条 hint 展开成多个候选
// （原地址 / 模块相对 / 区域相对），需要能一起 probe 并知道是哪种命中的。
func (s *Search) ProbeAddrs(cands []HintCand) ProbeHintsResult {
	var res ProbeHintsResult
	for _, c := range cands {
		if c.Addr == 0 {
			continue
		}
		if s.stopped() {
			break
		}
		res.Tried++
		buf := make([]byte, keyLen)
		if err := s.readFull(c.Addr, buf); err != nil {
			continue
		}
		res.Bytes += uint64(keyLen)
		if s.Check(buf, "hint/fast", c.Addr) {
			res.Hit = true
			res.Priv = buf
			res.Tag = "hint/fast"
			res.Addr = c.Addr
			res.Source = c.Source
			break
		}
	}
	return res
}

// Anchor 对应 anchor @0x17ab60：按区域特征给出锚点候选地址。
//
// 原程序用 sort.Slice 按 score 排序后逐个 chase；这里保留同样的形状：
// 优先选择"可写 + 私有 + 体积适中"的区域头部作为锚点。
func (s *Search) Anchor(regions []memscan.Region) []uintptr {
	type scored struct {
		addr  uintptr
		score int
	}
	var list []scored
	for _, r := range regions {
		// 可写区域更可能存放会话密钥
		score := 0
		if r.Protect&0x04 != 0 || r.Protect&0x40 != 0 { // READWRITE / EXECUTE_READWRITE
			score += 10
		}
		if r.Size >= 0x1000 && r.Size <= 64<<20 {
			score += 5
		}
		if score == 0 {
			continue
		}
		list = append(list, scored{addr: r.Base, score: score})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].score > list[j].score })
	out := make([]uintptr, 0, len(list))
	for _, e := range list {
		out = append(out, e.addr)
	}
	return out
}

// Chase 对应 chase @0x17a860 + chase.func1 @0x181180：
// 读 8 字节 → 若指针落在 [0x10000,0x7FFFFFFFFFFF] → 在该地址读 32 字节 → Check(...,"pointer")。
func (s *Search) Chase(addr uintptr, depth int) bool {
	if depth <= 0 {
		return false
	}
	var raw [8]byte
	if err := s.readFull(addr, raw[:]); err != nil {
		return false
	}
	p := uintptr(uint64(raw[0]) | uint64(raw[1])<<8 | uint64(raw[2])<<16 | uint64(raw[3])<<24 |
		uint64(raw[4])<<32 | uint64(raw[5])<<40 | uint64(raw[6])<<48 | uint64(raw[7])<<56)
	if p < minPointer || p > maxPointer {
		return false
	}
	buf := make([]byte, keyLen)
	if err := s.readFull(p, buf); err != nil {
		return false
	}
	if s.Check(buf, "pointer", p) {
		return true
	}
	return false
}

// scanAnchors 对应 scanAnchors @0x17b280（并发 + 排序）。
func (s *Search) scanAnchors(regions []memscan.Region) bool {
	anchors := s.Anchor(regions)
	if len(anchors) == 0 {
		return false
	}
	workers := runtime.NumCPU()
	if workers < 2 {
		workers = 2
	}
	var wg sync.WaitGroup
	ch := make(chan uintptr, len(anchors))
	for _, a := range anchors {
		ch <- a
	}
	close(ch)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for a := range ch {
				if s.stopped() {
					return
				}
				// 锚点本身先当作 32 字节候选试一次，再做指针链
				buf := make([]byte, keyLen)
				if err := s.readFull(a, buf); err == nil {
					if s.Check(buf, "adjacent/anchors", a) {
						return
					}
				}
				if s.Chase(a, 2) {
					return
				}
			}
		}()
	}
	wg.Wait()
	return s.Found()
}

// scanWindows 对应 scanWindows @0x17b6e0：滑窗全量扫描。
//
// 注意：这是纯暴力路径，代价 = 区域字节数/8 次 X25519 标量乘。
// 原程序靠 hint（上次命中地址）与 anchor 让常规路径秒级完成，
// 窗口扫描只是兜底；本重构同样把它放在最后，并受 MaxCandidates 预算约束。
func (s *Search) scanWindows(regions []memscan.Region) bool {
	workers := runtime.NumCPU()
	var wg sync.WaitGroup
	ch := make(chan memscan.Region, len(regions))
	for _, r := range regions {
		ch <- r
	}
	close(ch)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			buf := make([]byte, blockSize)
			for r := range ch {
				if s.stopped() {
					return
				}
				for off := uintptr(0); off < r.Size; off += blockSize {
					if s.stopped() {
						return
					}
					n := blockSize
					if rem := r.Size - off; rem < uintptr(n) {
						n = int(rem)
					}
					got, err := s.Proc.ReadAt(r.Base+off, buf[:n])
					atomic.AddUint64(&s.reads, 1)
					if err != nil || got < keyLen {
						atomic.AddUint64(&s.shortReads, 1)
						continue
					}
					atomic.AddUint64(&s.bytesRead, uint64(got))
					st := s.WindowStride
					if st == 0 {
						st = 1
					}
					for i := 0; i+keyLen <= got; i += int(st) {
						if s.budgetExceeded() {
							return
						}
						atomic.AddUint64(&s.candidates, 1)
						if s.Check(buf[i:i+keyLen], "window", r.Base+off+uintptr(i)) {
							return
						}
					}
				}
			}
		}()
	}
	wg.Wait()
	return s.Found()
}

func (s *Search) stopped() bool {
	if atomic.LoadInt32(&s.found) == 1 {
		return true
	}
	return !s.Deadline.IsZero() && time.Now().After(s.Deadline)
}

func (s *Search) budgetExceeded() bool {
	if s.MaxCandidates == 0 {
		return false
	}
	return atomic.LoadUint64(&s.candidates) >= s.MaxCandidates
}

func (s *Search) readFull(addr uintptr, buf []byte) error {
	n, err := s.Proc.ReadAt(addr, buf)
	atomic.AddUint64(&s.reads, 1)
	if err != nil {
		atomic.AddUint64(&s.shortReads, 1)
		return err
	}
	if n != len(buf) {
		atomic.AddUint64(&s.shortReads, 1)
		return fmt.Errorf("short read at %#x: %d/%d", addr, n, len(buf))
	}
	atomic.AddUint64(&s.bytesRead, uint64(n))
	return nil
}

// recoverWorker 对应 recoverWorker @0x17a100：把 panic 转成 ErrWorkerPanic。
func recoverWorker(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%w: %v", ErrWorkerPanic, r)
		}
	}()
	fn()
	return nil
}

// FindPrivWithHints 对应 findPrivWithHints @0x17bbc0：总编排。
//
// 顺序：scanHints → scanAnchors → scanWindows。
// 任一阶段命中即返回；全部走完仍未命中则按是否超时给出对应错误。
func (s *Search) FindPrivWithHints(regions []memscan.Region) ([]byte, string, uintptr, error) {
	if len(s.TargetPub) != keyLen {
		return nil, "", 0, errors.New("handshake public key not found in readable memory")
	}
	var (
		priv []byte
		tag  string
		addr uintptr
		hit  bool
	)
	s.OnFound = func(p []byte, t string, a uintptr) {
		priv, tag, addr, hit = p, t, a, true
	}
	if err := recoverWorker(func() {
		if s.scanHints() {
			return
		}
		if s.scanAnchors(regions) {
			return
		}
		s.scanWindows(regions)
	}); err != nil {
		s.err = err
		close(s.done)
		return nil, "", 0, err
	}
	if !hit {
		if !s.Deadline.IsZero() && time.Now().After(s.Deadline) {
			s.err = ErrDeadline
		} else {
			s.err = ErrNoCandidate
		}
		close(s.done)
		return nil, "", 0, s.err
	}
	return priv, tag, addr, nil
}
