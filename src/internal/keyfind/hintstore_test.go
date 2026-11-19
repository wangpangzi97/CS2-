package keyfind

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"local/cs2-radar/internal/memscan"
)

// TestHintStoreRoundTrip 验证落盘/读取往返，并确认 priv 字段被剥掉。
func TestHintStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hints.json")

	in := []Hint{
		{Addr: 0x7ff6a0001234, Auto: true, Pub: strings.Repeat("ab", 32), Hits: 3},
		{Addr: 0x1234, Auto: true},
	}
	if err := SaveHints(path, in); err != nil {
		t.Fatalf("SaveHints: %v", err)
	}
	got := LoadHints(path)
	if len(got) != 2 {
		t.Fatalf("读回 %d 条，期望 2 条", len(got))
	}
	// Hits 降序：3 那条必须排第一。
	if got[0].Addr != 0x7ff6a0001234 {
		t.Fatalf("Hits 排序失效，第一条是 %#x", got[0].Addr)
	}
	if got[0].Pub != in[0].Pub {
		t.Fatalf("Pub 未保留：%q", got[0].Pub)
	}
}

// TestHintStoreNeverPersistsPriv 是最重要的一条安全断言：
// 即使调用方把私钥塞进 Hint.Priv，也绝不能落到磁盘上。
func TestHintStoreNeverPersistsPriv(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hints.json")
	secret := "SUPER-SECRET-PRIV-DO-NOT-WRITE"

	if err := SaveHints(path, []Hint{{Addr: 0x1000, Priv: secret, Auto: true}}); err != nil {
		t.Fatalf("SaveHints: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatalf("私钥被写进了 hint 文件：\n%s", raw)
	}

	// 读回来也必须被清空（防止有人手工往文件里塞 priv）。
	handwritten := `{"version":1,"hints":[{"addr":4096,"priv":"` + secret + `"}]}`
	if err := os.WriteFile(path, []byte(handwritten), 0o644); err != nil {
		t.Fatal(err)
	}
	got := LoadHints(path)
	if len(got) != 1 {
		t.Fatalf("读回 %d 条", len(got))
	}
	if got[0].Priv != "" {
		t.Fatalf("LoadHints 没有清掉 priv：%q", got[0].Priv)
	}
}

// TestHintStoreRejectsWrongVersion 版本不符必须整批丢弃（否则字段语义错位会用错地址）。
func TestHintStoreRejectsWrongVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hints.json")
	bad := `{"version":999,"hints":[{"addr":4096}]}`
	if err := os.WriteFile(path, []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := LoadHints(path); len(got) != 0 {
		t.Fatalf("版本不符却读回了 %d 条", len(got))
	}
}

// TestLoadHintsMissingFileIsNotAnError：第一次运行必然没有文件，不能报错也不能中断。
func TestLoadHintsMissingFileIsNotAnError(t *testing.T) {
	if got := LoadHints(filepath.Join(t.TempDir(), "nope.json")); len(got) != 0 {
		t.Fatalf("文件不存在却读回了 %d 条", len(got))
	}
	if got := LoadHints(""); len(got) != 0 {
		t.Fatalf("空路径却读回了 %d 条", len(got))
	}
}

// TestMergeHintAccumulatesHits：同地址合并，Hits 累加并排到最前。
func TestMergeHintAccumulatesHits(t *testing.T) {
	hs := []Hint{{Addr: 0x1000, Hits: 1}, {Addr: 0x2000, Hits: 5}}
	hs = MergeHint(hs, Hint{Addr: 0x1000, Pub: "aa"})
	if len(hs) != 2 {
		t.Fatalf("同地址应合并，实际 %d 条", len(hs))
	}
	// 0x1000 原 Hits=1，合并后 +1 → 2；仍少于 0x2000 的 5，所以排第二。
	if hs[0].Addr != 0x2000 {
		t.Fatalf("排序错误，第一条是 %#x", hs[0].Addr)
	}
	if hs[1].Hits != 2 {
		t.Fatalf("Hits 未累加，实际 %d", hs[1].Hits)
	}
	if hs[1].Pub != "aa" {
		t.Fatalf("Pub 未刷新：%q", hs[1].Pub)
	}

	// 再加两次，0x1000 应该超过 0x2000 排到第一。
	hs = MergeHint(hs, Hint{Addr: 0x1000})
	hs = MergeHint(hs, Hint{Addr: 0x1000})
	hs = MergeHint(hs, Hint{Addr: 0x1000})
	if hs[0].Addr != 0x1000 {
		t.Fatalf("累加后 0x1000 应排第一，实际 %#x", hs[0].Addr)
	}
}

// TestMergeHintCapsAtMaxHints：表不能无限增长（每条都是一次 ReadProcessMemory）。
func TestMergeHintCapsAtMaxHints(t *testing.T) {
	var hs []Hint
	for i := 0; i < MaxHints*3; i++ {
		hs = MergeHint(hs, Hint{Addr: uintptr(0x1000 + i*0x10)})
	}
	if len(hs) > MaxHints {
		t.Fatalf("表长 %d 超过上限 %d", len(hs), MaxHints)
	}
}

// TestSaveHintsLeavesNoTemp：原子写不能在旁边留下 .tmp。
func TestSaveHintsLeavesNoTemp(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hints.json")
	for i := 0; i < 3; i++ {
		if err := SaveHints(path, []Hint{{Addr: uintptr(0x1000 + i)}}); err != nil {
			t.Fatalf("第 %d 次 SaveHints: %v", i, err)
		}
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Fatalf("残留临时文件：%s", e.Name())
		}
	}
	// 文件必须是合法 JSON 且版本正确。
	raw, _ := os.ReadFile(path)
	var f HintFile
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatalf("落盘内容不是合法 JSON：%v", err)
	}
	if f.Version != HintFileVersion {
		t.Fatalf("版本 %d，期望 %d", f.Version, HintFileVersion)
	}
}

// TestProbeHintsFastPath 是快路径的端到端验证：
// 把私钥埋进本进程堆，用 ProbeHints 只读 32 字节×2 就挖出来。
//
// 这条测试的意义：它证明了"不冻结、不枚举区域、不扫描"也能拿到私钥 ——
// 也就是原版不被检测的那条路径在本重构里是通的。
func TestProbeHintsFastPath(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows 有效")
	}
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	p := plantKey(t, priv.Bytes(), true)

	// 第一条故意给一个读不到的地址，验证"miss 不致命、继续试下一条"。
	hs := []Hint{
		{Addr: 0x10, Auto: true},
		{Addr: p.keyAddr, Auto: true},
	}
	s := New(proc, pub, time.Now().Add(10*time.Second))
	res := s.ProbeHints(hs)

	if !res.Hit {
		t.Fatalf("快路径未命中（试了 %d 条，读了 %d 字节）", res.Tried, res.Bytes)
	}
	if res.Addr != p.keyAddr {
		t.Fatalf("命中地址 %#x 与埋点 %#x 不一致", res.Addr, p.keyAddr)
	}
	if len(res.Priv) != 32 {
		t.Fatalf("私钥长度 %d", len(res.Priv))
	}
	if res.Priv[0] != priv.Bytes()[0] || res.Priv[31] != priv.Bytes()[31] {
		t.Fatal("取到的私钥与埋点不一致")
	}
	if res.Tried != 2 {
		t.Fatalf("Tried=%d，期望 2（第一条失败也要计数）", res.Tried)
	}
	// 只有第二条读成功，所以字节数恰好是 32 —— 这就是"轻量"的量化证明。
	if res.Bytes != 32 {
		t.Fatalf("读量 %d 字节，期望 32", res.Bytes)
	}
	t.Logf("快路径命中：addr=%#x 读 %d 字节 试 %d 条", res.Addr, res.Bytes, res.Tried)
}

// TestProbeHintsAllMissIsCheap：全部 miss 时读量也是 0（地址读不到就不计），
// 且不能 panic、不能误报命中。
func TestProbeHintsAllMissIsCheap(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows 有效")
	}
	curve := ecdh.X25519()
	priv, _ := curve.GenerateKey(rand.Reader)
	pub := priv.PublicKey().Bytes()

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	hs := []Hint{{Addr: 0x10}, {Addr: 0x20}, {Addr: 0}}
	s := New(proc, pub, time.Now().Add(5*time.Second))
	res := s.ProbeHints(hs)
	if res.Hit {
		t.Fatal("全是无效地址却报命中")
	}
	if res.Tried != 2 {
		t.Fatalf("Tried=%d，期望 2（Addr==0 的应跳过）", res.Tried)
	}
	if res.Bytes != 0 {
		t.Fatalf("读量应为 0，实际 %d", res.Bytes)
	}
}

// TestProbeHintsStopsOnWrongKey：地址读得到但内容不是私钥时，必须不命中。
func TestProbeHintsStopsOnWrongKey(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows 有效")
	}
	curve := ecdh.X25519()
	want, _ := curve.GenerateKey(rand.Reader)
	other, _ := curve.GenerateKey(rand.Reader)

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	// 埋一把"别的"私钥，但用 want 的公钥去验证 → 必须 miss。
	p := plantKey(t, other.Bytes(), true)
	s := New(proc, want.PublicKey().Bytes(), time.Now().Add(5*time.Second))
	res := s.ProbeHints([]Hint{{Addr: p.keyAddr}})
	if res.Hit {
		t.Fatal("错误的私钥通过了验证")
	}
	if res.Bytes != 32 {
		t.Fatalf("读量 %d，期望 32（读成功了但验证失败）", res.Bytes)
	}
}

// TestDescribeHints 只做文案断言，防止以后改坏诊断输出。
func TestDescribeHints(t *testing.T) {
	if s := DescribeHints(nil); !strings.Contains(s, "全量扫描") {
		t.Fatalf("空表文案不对：%q", s)
	}
	s := DescribeHints(make([]Hint, 4))
	if !strings.Contains(s, "4 条") || !strings.Contains(s, "128") {
		t.Fatalf("非空表文案不对：%q", s)
	}
}

// TestHintFileToProbeEndToEnd 走的就是 collector 的真实路径：
//
//	全量扫描命中 → rememberHint(addr) → 落盘
//	→ 下次运行 LoadHints → ProbeHints → 只读 32 字节命中
//
// 这是整个改动的核心承诺：**第二次以后不再扫描**。如果这条断了，
// 就等于每次运行都要读 7.5 GB，反作弊侧看到的正是那个特征。
func TestHintFileToProbeEndToEnd(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("仅 Windows 有效")
	}
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()

	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	// ① 模拟"第一次运行全量扫描命中"，把地址记进表。
	p := plantKey(t, priv.Bytes(), true)
	path := filepath.Join(t.TempDir(), "hints.json")
	hs := MergeHint(nil, Hint{Addr: p.keyAddr, Auto: true, Pub: "deadbeef"})
	if err := SaveHints(path, hs); err != nil {
		t.Fatalf("SaveHints: %v", err)
	}

	// ② 模拟"第二次运行"：从磁盘读回来，直接 probe。
	loaded := LoadHints(path)
	if len(loaded) != 1 {
		t.Fatalf("读回 %d 条", len(loaded))
	}
	s := New(proc, pub, time.Now().Add(5*time.Second))
	res := s.ProbeHints(loaded)
	if !res.Hit {
		t.Fatal("从文件读回的 hint 没能命中 —— 快路径等于没接上")
	}
	if res.Addr != p.keyAddr {
		t.Fatalf("命中地址 %#x，期望 %#x", res.Addr, p.keyAddr)
	}
	if res.Bytes != 32 {
		t.Fatalf("读量 %d 字节，期望 32（这就是「不扫描」的量化证明）", res.Bytes)
	}
	t.Logf("端到端：全量扫描一次 → 落盘 → 下次只读 %d 字节命中 %#x", res.Bytes, res.Addr)
}

// ───────────────── 相对偏移 / rebase 的单测 ─────────────────
//
// 这一组是「自己测出 hint 偏移」那套工具的骨架：
// MakeHint 记下相对量，HintCandidates 在当前进程里把它们展开成候选。

func mkRegions() []memscan.Region {
	return []memscan.Region{
		{Base: 0x7ff6a0000000, Size: 0x2000000, Protect: 0x02, Type: 0x1000000}, // 映像
		{Base: 0x10000000, Size: 0x100000, Protect: 0x04, Type: 0x20000},        // 堆 A
		{Base: 0x20000000, Size: 0x100000, Protect: 0x04, Type: 0x20000},        // 堆 B（同指纹）
		{Base: 0x30000000, Size: 0x40000, Protect: 0x04, Type: 0x20000},         // 堆 C（不同大小）
	}
}

func TestRegionOf(t *testing.T) {
	rs := mkRegions()
	if r, ok := memscan.RegionOf(rs, 0x10000010); !ok || r.Base != 0x10000000 {
		t.Fatalf("RegionOf 未命中堆 A：%+v ok=%v", r, ok)
	}
	// 边界：末字节属于本区域，末字节+1 属于下一个/不存在。
	if _, ok := memscan.RegionOf(rs, 0x10100000); ok {
		t.Fatal("末字节+1 不应落在堆 A")
	}
	if _, ok := memscan.RegionOf(rs, 0x40000000); ok {
		t.Fatal("不存在的地址不应命中")
	}
}

func TestMakeHintRecordsRelativeOffsets(t *testing.T) {
	rs := mkRegions()
	moduleBase := uintptr(0x7ff6a0000000)
	addr := uintptr(0x10000100)
	pub := make([]byte, 32)

	h := MakeHint(addr, pub, "cs2.exe", moduleBase, rs)

	if h.ModuleBase != moduleBase {
		t.Fatalf("ModuleBase=%#x", h.ModuleBase)
	}
	if h.ModuleOff != int64(addr)-int64(moduleBase) {
		t.Fatalf("ModuleOff=%#x，期望 %#x", h.ModuleOff, int64(addr)-int64(moduleBase))
	}
	if h.RegionBase != 0x10000000 || h.RegionOff != 0x100 {
		t.Fatalf("区域相对量错：base=%#x off=%#x", h.RegionBase, h.RegionOff)
	}
	if h.RegionSize != 0x100000 || h.RegionProtect != 0x04 || h.RegionType != 0x20000 {
		t.Fatalf("区域指纹没记全：%+v", h)
	}
	if h.Pub == "" || len(h.Pub) != 64 {
		t.Fatalf("Pub 应为 64 位 hex，实际 %q", h.Pub)
	}
	if h.Priv != "" {
		t.Fatal("MakeHint 不得写入 Priv")
	}
}

func TestMakeHintWithoutModuleBase(t *testing.T) {
	h := MakeHint(0x10000100, make([]byte, 32), "cs2.exe", 0, mkRegions())
	if h.ModuleBase != 0 || h.ModuleOff != 0 {
		t.Fatalf("拿不到模块基址时不该记模块相对量：base=%#x off=%#x", h.ModuleBase, h.ModuleOff)
	}
	if h.RegionOff != 0x100 {
		t.Fatal("区域相对量仍应记录")
	}
}

// TestHintCandidatesOrderAndDedup 验证候选顺序（as-is 必须排第一）与去重。
//
// 注意这里的场景：学习时和查询时的模块基址**相同**，所以 module+off 算出来的
// 地址正好等于 as-is —— 必须被去重掉，不能读两遍同一个地址。
func TestHintCandidatesOrderAndDedup(t *testing.T) {
	rs := mkRegions()
	moduleBase := uintptr(0x7ff6a0000000)
	h := Hint{
		Addr:          0x10000100,
		ModuleBase:    moduleBase,
		ModuleOff:     int64(0x10000100) - int64(moduleBase),
		RegionBase:    0x10000000,
		RegionOff:     0x100,
		RegionSize:    0x100000,
		RegionProtect: 0x04,
		RegionType:    0x20000,
	}
	cands := HintCandidates(h, moduleBase, rs)
	if len(cands) == 0 {
		t.Fatal("一个候选都没有")
	}
	if cands[0].Source != "as-is" || cands[0].Addr != h.Addr {
		t.Fatalf("第一个候选必须是 as-is，实际 %+v", cands[0])
	}
	seen := map[uintptr]bool{}
	for _, c := range cands {
		if seen[c.Addr] {
			t.Fatalf("候选重复：%#x", c.Addr)
		}
		seen[c.Addr] = true
	}
	// module+off 与 as-is 同址，应被去重 —— 所以不该出现 module+off 来源。
	for _, c := range cands {
		if c.Source == "module+off" {
			t.Fatalf("module+off 与 as-is 同址，应被去重，实际保留：%+v", c)
		}
	}
	// 同指纹区域只有 A 和 B（C 大小不同）。但 A 的 base+off 正好等于 as-is，
	// 已被去重，所以 region+off 只剩 B 一个候选。
	n := 0
	for _, c := range cands {
		if c.Source == "region+off" {
			n++
			if want := uintptr(0x20000100); c.Addr != want {
				t.Fatalf("region+off 换算地址 %#x，期望 %#x（B 区 base+0x100）", c.Addr, want)
			}
		}
	}
	if n != 1 {
		t.Fatalf("region+off 候选 %d 个，期望 1（A 与 as-is 同址已去重，只剩 B）", n)
	}
}

// TestHintCandidatesModuleRebase：模拟 ASLR 让主映像搬家。
// 这是最关键的一条 —— 如果私钥落在映像里，模块相对偏移就是那个"可复用的偏移"。
func TestHintCandidatesModuleRebase(t *testing.T) {
	// 学习时：映像在 0x7ff6a0000000，私钥在映像内 +0x1000100。
	learnBase := uintptr(0x7ff6a0000000)
	h := Hint{
		Addr:       0x7ff6a1000100,
		ModuleBase: learnBase,
		ModuleOff:  int64(0x7ff6a1000100) - int64(learnBase), // = 0x1000100
	}
	// 查询时：映像搬到 0x7ff6c0000000，原地址已不可达。
	now := []memscan.Region{
		{Base: 0x7ff6c0000000, Size: 0x2000000, Protect: 0x02, Type: 0x1000000},
	}
	cands := HintCandidates(h, 0x7ff6c0000000, now)
	if len(cands) != 1 {
		t.Fatalf("候选 %d 个，期望 1：%+v", len(cands), cands)
	}
	if cands[0].Source != "module+off" {
		t.Fatalf("来源应为 module+off，实际 %q", cands[0].Source)
	}
	if want := uintptr(0x7ff6c1000100); cands[0].Addr != want {
		t.Fatalf("换算地址 %#x，期望 %#x", cands[0].Addr, want)
	}
}

// TestHintCandidatesSkipUnreachable：落不到可读区域的候选必须被丢掉，
// 否则 probe 全是白读（还多留了 ReadProcessMemory 调用痕迹）。
func TestHintCandidatesSkipUnreachable(t *testing.T) {
	rs := mkRegions()
	// 地址不在任何区域，且没有模块/区域相对量 → 一个候选都不该有。
	h := Hint{Addr: 0xDEAD0000}
	if c := HintCandidates(h, 0, rs); len(c) != 0 {
		t.Fatalf("不可达的 hint 不应产生候选，实际 %d 个：%+v", len(c), c)
	}
}

// TestHintCandidatesRegionRebase：模拟 ASLR 让堆整体搬家，
// 区域相对量应该把地址换算到新位置。
func TestHintCandidatesRegionRebase(t *testing.T) {
	// 学习时堆在 0x10000000，私钥在 +0x100。
	h := Hint{
		Addr:          0x10000100,
		RegionBase:    0x10000000,
		RegionOff:     0x100,
		RegionSize:    0x100000,
		RegionProtect: 0x04,
		RegionType:    0x20000,
	}
	// 重开后堆搬到 0x50000000（大小/保护/类型不变）。
	now := []memscan.Region{
		{Base: 0x50000000, Size: 0x100000, Protect: 0x04, Type: 0x20000},
	}
	cands := HintCandidates(h, 0, now)
	if len(cands) != 1 {
		t.Fatalf("候选 %d 个，期望 1：%+v", len(cands), cands)
	}
	if cands[0].Source != "region+off" {
		t.Fatalf("来源应为 region+off，实际 %q", cands[0].Source)
	}
	if cands[0].Addr != 0x50000100 {
		t.Fatalf("换算地址 %#x，期望 0x50000100", cands[0].Addr)
	}
}

// TestHintCandidatesRegionCap：同指纹区域很多时，候选数要被截断。
func TestHintCandidatesRegionCap(t *testing.T) {
	var now []memscan.Region
	for i := 0; i < 50; i++ {
		now = append(now, memscan.Region{
			Base: uintptr(0x10000000 + i*0x1000000),
			Size: 0x100000, Protect: 0x04, Type: 0x20000,
		})
	}
	h := Hint{Addr: 0x1, RegionBase: 0x10000000, RegionOff: 0x100,
		RegionSize: 0x100000, RegionProtect: 0x04, RegionType: 0x20000}
	cands := HintCandidates(h, 0, now)
	if len(cands) > maxRegionCands {
		t.Fatalf("候选 %d 个，超过上限 %d", len(cands), maxRegionCands)
	}
}
