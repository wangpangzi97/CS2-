// hint 表持久化。
//
// 为什么需要它：原版 capture.exe 的快路径是 probeHint —— 直接读一个已知地址的
// 32 字节，用 X25519 反算公钥验证。这样一次运行只读几十~几百字节，不冻结、
// 不枚举区域、不扫描，反作弊侧几乎看不到东西。
//
// 2026-10-18 用户实测：原版未被检测到。反汇编确认原版 FreezeFast 就是
// NtSuspendProcess（和我们完全一样），所以差别不在冻结动作，而在**读了多少**：
//
//	原版快路径   : 32 字节 × hint 条数
//	我们之前     : 7,567 MB 定位 + 512 MB 冻结抓取 + 6,621 MB 指针反查 + 69 MB 邻域
//
// 这个文件负责把"上次在哪里找到私钥"记下来，让下一次直接去读那 32 字节。
//
// ⚠ 安全约束：只存**地址**，绝不存私钥。会话私钥下次就失效，落盘纯属留痕。
package keyfind

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"local/cs2-radar/internal/memscan"
)

// HintFileVersion 是文件格式版本。字段有增减时递增，读到不认识的就整批丢弃。
const HintFileVersion = 1

// MaxHints 是 hint 表上限。
//
// 为什么不无限增长：快路径的成本是 32 字节/条，但每次都要 ReadProcessMemory 一次。
// 32 条 = 1 KB / 32 次调用，仍然是"看不见"的量级；再往上就没有收益了
// （同一局里稳定命中的通常只有一两条）。
const MaxHints = 32

// HintFile 是落盘格式。
type HintFile struct {
	Version int    `json:"version"`
	Note    string `json:"note,omitempty"`
	Hints   []Hint `json:"hints"`
}

// LoadHints 读 hint 表。文件不存在、格式不对、版本不匹配都返回空表 + nil 错误 ——
// 快路径失败是常态（第一次运行必然没有 hint），不能因此中断整个流程。
func LoadHints(path string) []Hint {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var f HintFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil
	}
	if f.Version != HintFileVersion {
		return nil
	}
	out := make([]Hint, 0, len(f.Hints))
	for _, h := range f.Hints {
		if h.Addr == 0 {
			continue
		}
		h.Priv = "" // 防御：即使文件里被塞了 priv，也绝不使用
		out = append(out, h)
	}
	sortHints(out)
	if len(out) > MaxHints {
		out = out[:MaxHints]
	}
	return out
}

// SaveHints 原子写 hint 表。
//
// 原子性用「临时文件 + rename」：这个文件会在每次命中后被重写，
// 如果中途崩溃留下半个 JSON，下次启动就整批失效 —— 而失效意味着又要全量扫描，
// 那正是我们想避免的事。
func SaveHints(path string, hs []Hint) error {
	if path == "" {
		return errors.New("hint path is empty")
	}
	clean := make([]Hint, 0, len(hs))
	for _, h := range hs {
		if h.Addr == 0 {
			continue
		}
		h.Priv = ""
		clean = append(clean, h)
	}
	sortHints(clean)
	if len(clean) > MaxHints {
		clean = clean[:MaxHints]
	}
	f := HintFile{
		Version: HintFileVersion,
		Note:    "自动生成。只记录地址，不含私钥。删掉它会让下次运行退回全量扫描。",
		Hints:   clean,
	}
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o755)
	}
	tmp := path + ".tmp"
	fh, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := fh.Write(b); err != nil {
		fh.Close()
		os.Remove(tmp)
		return err
	}
	if err := fh.Sync(); err != nil {
		fh.Close()
		os.Remove(tmp)
		return err
	}
	if err := fh.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// MergeHint 把一条新 hint 并入表：同地址的合并（累加 Hits、刷新时间），
// 按 Hits 降序保留前 MaxHints 条。
func MergeHint(hs []Hint, h Hint) []Hint {
	if h.Addr == 0 {
		return hs
	}
	h.Priv = ""
	if h.LearnedAt == "" {
		h.LearnedAt = time.Now().Format(time.RFC3339)
	}
	out := make([]Hint, 0, len(hs)+1)
	merged := false
	for _, old := range hs {
		if old.Addr == h.Addr {
			old.Hits += h.Hits + 1
			old.Pub = h.Pub
			old.Exe = h.Exe
			old.LearnedAt = h.LearnedAt
			if h.Dist != 0 {
				old.Dist = h.Dist
			}
			old.Auto = true
			out = append(out, old)
			merged = true
			continue
		}
		out = append(out, old)
	}
	if !merged {
		h.Hits++
		h.Auto = true
		out = append(out, h)
	}
	sortHints(out)
	if len(out) > MaxHints {
		out = out[:MaxHints]
	}
	return out
}

// sortHints 按 Hits 降序、地址升序排列。命中多的排前面，快路径就能更早撞上。
func sortHints(hs []Hint) {
	sort.SliceStable(hs, func(i, j int) bool {
		if hs[i].Hits != hs[j].Hits {
			return hs[i].Hits > hs[j].Hits
		}
		return hs[i].Addr < hs[j].Addr
	})
}

// DescribeHints 给日志用的一行摘要（不打印地址列表，避免日志太长）。
func DescribeHints(hs []Hint) string {
	if len(hs) == 0 {
		return "空（本次必然走全量扫描）"
	}
	return fmt.Sprintf("%d 条，最快路径预计读 %d 字节", len(hs), len(hs)*32)
}

// ─────────────────── 相对偏移：把历史地址换算到当前进程 ───────────────────
//
// 为什么需要这一段：hint 的绝对地址会随 ASLR 变化。要让它跨会话有用，
// 必须记下**相对量**。这里记两种：
//
//	ModuleOff = addr - 主映像基址     （如果私钥在 cs2.exe 的固定映射区里，这个最稳）
//	RegionOff = addr - 所属区域基址   （区域布局稳定时可用，需要区域指纹重新认出）
//
// 下次运行时把两种相对量都展开成候选地址，逐个 probe（每个 32 字节）。
// **哪个来源命中，就说明哪种偏移在你的机器上是稳的** —— 这就是"自己测出偏移"。

// HintCand 是一个待 probe 的候选地址，带来源标签（诊断用）。
type HintCand struct {
	Addr   uintptr
	Source string // as-is / module+off / region+off
}

// MakeHint 从一次成功命中构造 hint，并把当时的相对偏移一并算好。
//
// moduleBase 传 0 表示拿不到（就不记模块相对量）。
// regions 传 nil 表示不记区域相对量。
func MakeHint(addr uintptr, pub []byte, exe string, moduleBase uintptr, regions []memscan.Region) Hint {
	h := Hint{
		Addr: addr,
		Auto: true,
		Pub:  fmt.Sprintf("%x", pub),
		Exe:  exe,
	}
	if moduleBase != 0 {
		h.ModuleBase = moduleBase
		h.ModuleOff = int64(addr) - int64(moduleBase)
	}
	if r, ok := memscan.RegionOf(regions, addr); ok {
		h.RegionBase = r.Base
		h.RegionOff = int64(addr) - int64(r.Base)
		h.RegionSize = uint64(r.Size)
		h.RegionProtect = r.Protect
		h.RegionType = r.Type
	}
	return h
}

// maxRegionCands 限制区域相对量展开出的候选数。
//
// 为什么要有上限：如果很多区域的指纹完全一样（大小/保护/类型相同），
// 展开会得到几十个候选。每个 32 字节本身不贵，但候选太多会拖慢快路径、
// 也让"哪个来源命中"的诊断变模糊。8 个足够覆盖典型情况。
const maxRegionCands = 8

// HintCandidates 把一条历史 hint 展开成当前进程里的候选地址，按可信度排序：
//
//  1. as-is     —— 原地址还落在某个可读区域里，直接用（最可能命中）
//  2. module+off —— 主映像基址 + 模块相对偏移
//  3. region+off —— 与记录指纹一致的区域基址 + 区域相对偏移
//
// 返回值可能为空（说明这条 hint 在当前进程里完全落不到可读内存上）。
func HintCandidates(h Hint, moduleBase uintptr, regions []memscan.Region) []HintCand {
	var out []HintCand
	seen := map[uintptr]bool{}
	add := func(addr uintptr, src string) {
		if addr == 0 || seen[addr] {
			return
		}
		if _, ok := memscan.RegionOf(regions, addr); !ok {
			return // 落不到可读区域，probe 也是白读
		}
		seen[addr] = true
		out = append(out, HintCand{Addr: addr, Source: src})
	}

	// 1. 原地址
	add(h.Addr, "as-is")

	// 2. 模块相对
	if moduleBase != 0 && h.ModuleOff != 0 {
		add(uintptr(int64(moduleBase)+h.ModuleOff), "module+off")
	}

	// 3. 区域相对：只在记过区域指纹时展开
	if h.RegionOff != 0 && h.RegionSize != 0 {
		n := 0
		for _, r := range regions {
			if uint64(r.Size) != h.RegionSize ||
				r.Protect != h.RegionProtect ||
				r.Type != h.RegionType {
				continue
			}
			add(uintptr(int64(r.Base)+h.RegionOff), "region+off")
			n++
			if n >= maxRegionCands {
				break
			}
		}
	}
	return out
}
