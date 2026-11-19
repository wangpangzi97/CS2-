package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

// ── 第九轮：不再重复扫同一片内存 ──
//
// 用户现场 17:27（12 分 37 秒）里有两处纯浪费：
//
//	邻域搜索：读 50.7 MB｜校验 8828279 次｜耗时 1m8s     ← 快照已校验过，被重扫
//	其余副本：读 450.8 MB｜耗时 2m38s
//	全可写区兜底：读 3356.2 MB｜…                        ← 又把那 450 MB 扫了一遍
//
// 两条测试把这两个契约钉死：coveredRanges 必须准确，preDone 必须真的被扣掉。

func snapBase(b []byte) uintptr {
	return (*reflect.SliceHeader)(unsafe.Pointer(&b)).Data
}

// TestSnapshotCoveredRanges 副本覆盖的区间必须和抓下来的字节一一对应。
func TestSnapshotCoveredRanges(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	a := make([]byte, 64<<10)
	b := make([]byte, 32<<10)
	fillRealistic(a)
	fillRealistic(b)

	ra := scanRange{lo: snapBase(a), hi: snapBase(a) + uintptr(len(a)), tag: "r1"}
	rb := scanRange{lo: snapBase(b), hi: snapBase(b) + uintptr(len(b)), tag: "r2"}
	snap := takeSnapshot(proc, []scanRange{ra, rb}, 2, snapshotDefaultMax, time.Now().Add(5*time.Second))
	if snap.bytes != uint64(len(a)+len(b)) {
		t.Fatalf("快照字节数 %d，期望 %d", snap.bytes, len(a)+len(b))
	}

	got := snap.coveredRanges()
	if len(got) == 0 {
		t.Fatalf("coveredRanges 为空")
	}
	// 相邻/重叠要合并，所以这里只能校验"总字节数不虚增、且每段都在原始区间内"。
	var total uintptr
	for _, r := range got {
		if r.hi <= r.lo {
			t.Fatalf("非法区间 %#x-%#x", r.lo, r.hi)
		}
		total += r.hi - r.lo
	}
	if total != uintptr(len(a)+len(b)) {
		t.Fatalf("覆盖字节数 %d，期望 %d（合并后不该虚增或丢失）", total, len(a)+len(b))
	}
	// 只能做"外包络"校验：a 和 b 是两次独立 make，地址既不相邻也不保证 b 在 a 之后，
	// 合并结果与 [ra.lo, rb.hi] 没有包含关系。要求覆盖区间整体不超出两段的外包络即可。
	lo, hi := ra.lo, ra.hi
	if rb.lo < lo {
		lo = rb.lo
	}
	if rb.hi > hi {
		hi = rb.hi
	}
	if got[0].lo < lo || got[len(got)-1].hi > hi {
		t.Fatalf("覆盖区间跑出了抓取范围：%#x-%#x 超出 %#x-%#x",
			got[0].lo, got[len(got)-1].hi, lo, hi)
	}
	// nil 安全
	var nilSnap *memSnapshot
	if nilSnap.coveredRanges() != nil {
		t.Fatalf("nil 快照应返回 nil")
	}
}

// TestCoversRange 钉死"邻域到底盖没盖全"这个判据。
//
// 第九轮的 coveredNear 只看 `snap.primary > 0`，而 primary 是在遍历到第
// primaryCount 段时就记下的下标 —— 段内短读 / 尾部不足 32 字节都会留下洞，
// 但 primary 仍然 > 0。于是前三级邻域会被**静默跳过**：不报错、不提示，
// 只是永远找不到私钥。这条测试就是为了让那种"有洞也算覆盖"再也不可能通过。
func TestCoversRange(t *testing.T) {
	rs := mergeRanges([]scanRange{
		{lo: 0x1000, hi: 0x2000},
		{lo: 0x2000, hi: 0x3000}, // 与上一段相邻，合并成 0x1000-0x3000
		{lo: 0x5000, hi: 0x6000}, // 中间 0x3000-0x5000 是洞
	})

	cases := []struct {
		lo, hi uintptr
		want   bool
		why    string
	}{
		{0x1000, 0x3000, true, "正好落在一段合并后的区间里"},
		{0x1800, 0x2800, true, "落在区间内部"},
		{0x2000, 0x2000, true, "空窗口算覆盖（交集为空本来就没东西要扫）"},
		{0x1000, 0x4000, false, "越过第一段末尾就是洞"},
		{0x2500, 0x5500, false, "跨过洞"},
		{0x5000, 0x6000, true, "第二段完整覆盖"},
		{0x0f00, 0x1100, false, "左边界露出去了"},
		{0x5800, 0x6800, false, "右边界露出去了"},
	}
	for _, c := range cases {
		if got := coversRange(rs, c.lo, c.hi); got != c.want {
			t.Fatalf("coversRange(%#x,%#x)=%v 期望 %v（%s）", c.lo, c.hi, got, c.want, c.why)
		}
	}
	if coversRange(nil, 0x1000, 0x2000) {
		t.Fatalf("空覆盖集不该报告覆盖")
	}
}

// TestPrimaryRangesReportsHoles 钉死"邻域副本有洞时 primaryRanges 能看出来"。
func TestPrimaryRangesReportsHoles(t *testing.T) {
	snap := &memSnapshot{
		primary: 2,
		chunks: []snapChunk{
			{addr: 0x10000, data: make([]byte, 0x1000)},
			{addr: 0x20000, data: make([]byte, 0x1000)}, // 与上一段之间是洞
			{addr: 0x30000, data: make([]byte, 0x1000)}, // 属于"其余副本"
		},
	}
	prim := snap.primaryRanges()
	if len(prim) != 2 {
		t.Fatalf("邻域覆盖段数 %d，期望 2", len(prim))
	}
	if !coversRange(prim, 0x10000, 0x11000) {
		t.Fatalf("第一段应被完整覆盖")
	}
	if coversRange(prim, 0x10000, 0x21000) {
		t.Fatalf("两段之间有洞，不该报告整段覆盖")
	}
	// primary=0 时必须返回 nil —— 这是"邻域没抓到"的信号，不能假装覆盖了。
	empty := &memSnapshot{chunks: []snapChunk{{addr: 0x1000, data: make([]byte, 0x100)}}}
	if empty.primaryRanges() != nil {
		t.Fatalf("primary=0 应返回 nil")
	}
	var nilSnap *memSnapshot
	if nilSnap.primaryRanges() != nil {
		t.Fatalf("nil 快照应返回 nil")
	}
}

// TestRunKeySearchSkipsPreDone 钉死"已经校验过的区间不再扫"。
//
// 断言方式：把私钥埋在一段内存里，然后告诉 runKeySearch "这段已经扫过了"。
// 此时它**不该**再读这段 —— 所以既读不到字节，也找不到私钥。
// 这条测试看着像在验证"找不到"，其实是在验证去重真的生效：
// 如果哪天 preDone 被忽略，这条会变成"找到了"，从而失败。
func TestRunKeySearchSkipsPreDone(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	buf := make([]byte, 256<<10)
	fillRealistic(buf)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := key.PublicKey().Bytes()
	copy(buf[4096:], key.Bytes())

	base := snapBase(buf)
	regions := []memscan.Region{{Base: base, Size: uintptr(len(buf)), Protect: 0x04, Type: 0x20000}}
	hits := []pubHit{{Addr: base + 4096, Region: regions[0]}}

	kf := keyfind.New(proc, pub, time.Now().Add(20*time.Second))
	preDone := []scanRange{{lo: base, hi: base + uintptr(len(buf)), tag: "snap"}}

	ok, rep := runKeySearch(kf, proc, regions, hits,
		func(string) {}, 20*time.Second, len(nearStages), preDone, nil)
	if ok {
		t.Fatalf("preDone 里的区间被重扫了（应该扫不到才对）")
	}
	if kf.Stats()["bytes"] != 0 {
		t.Fatalf("preDone 区间被重读：%d 字节（报告 %s）", kf.Stats()["bytes"], rep.Full)
	}
}

// TestRunKeySearchWithoutPreDone 是上一条的反面：不传 preDone 时同样的内存必须能找到。
//
// 两条一起才有意义 —— 只测"跳过"会把"搜索彻底坏了"也当成通过。
func TestRunKeySearchWithoutPreDone(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	buf := make([]byte, 64<<10)
	fillRealistic(buf)
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := key.PublicKey().Bytes()
	copy(buf[4097:], key.Bytes()) // 故意不对齐

	base := snapBase(buf)
	regions := []memscan.Region{{Base: base, Size: uintptr(len(buf)), Protect: 0x04, Type: 0x20000}}
	hits := []pubHit{{Addr: base + 4097, Region: regions[0]}}

	kf := keyfind.New(proc, pub, time.Now().Add(60*time.Second))
	var at uintptr
	kf.OnFound = func(_ []byte, _ string, a uintptr) { at = a }

	ok, _ := runKeySearch(kf, proc, regions, hits, func(string) {}, 60*time.Second, 0, nil, nil)
	if !ok {
		t.Fatalf("没传 preDone 也没找到私钥 —— 兜底路径本身坏了")
	}
	if want := base + 4097; at != want {
		t.Fatalf("命中地址 %#x，期望 %#x", at, want)
	}
}
