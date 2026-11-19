package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
	"local/cs2-radar/internal/winapi"
)

// TestNearRangesIntersectsNeighborRegions 钉死"近邻窗口要与全部区域求交"。
//
// 用户现场就是栽在这里：6 个公钥命中点全落在 16 KB ~ 216 KB 的小区域里，
// 旧实现把 ±8 MB 的窗口裁到"命中点自己那一小块"，三级窗口加起来只扫了
// 0.6 MB —— 等于根本没放大，直接跳到全内存兜底。
//
// 这个用例构造"一个 16 KB 的小区域 + 紧邻的 4 MB 大区域"，要求 ±1 MB 的
// 窗口必须覆盖到那个大区域。
func TestNearRangesIntersectsNeighborRegions(t *testing.T) {
	const base = uintptr(0x10000000)
	small := memscan.Region{Base: base, Size: 16 << 10, Protect: winapi.PAGE_READWRITE, Type: winapi.MEM_PRIVATE}
	big := memscan.Region{Base: base + (16 << 10), Size: 4 << 20, Protect: winapi.PAGE_READWRITE, Type: winapi.MEM_PRIVATE}
	far := memscan.Region{Base: base + (64 << 20), Size: 1 << 20, Protect: winapi.PAGE_READWRITE, Type: winapi.MEM_PRIVATE}
	regions := []memscan.Region{small, big, far}

	hit := pubHit{Addr: base + 0x100, Region: small}

	// 旧语义：只裁到 small 自己 → 16 KB 以内
	old := nearRanges([]pubHit{hit}, 1<<20, "near")
	if got := totalRangeBytes(old); got > 16<<10 {
		t.Fatalf("旧语义应当被裁到 16 KB，实际 %d", got)
	}

	// 新语义：与全部区域求交 → 必须包含 big 的前 1 MB
	rs := nearRangesIn([]pubHit{hit}, 1<<20, "near", regions)
	total := totalRangeBytes(rs)
	if total <= 16<<10 {
		t.Fatalf("±1 MB 窗口没有跨出小区域，仍只有 %d 字节 —— 求交没生效", total)
	}
	// 窗口是以命中点为中心的 [addr-1MB, addr+1MB+32]，命中点在 base+0x100，
	// 所以向上只能覆盖到 base+1MB+0x120（小区域 16 KB 全部在内）。
	if want := uintptr(1<<20) + 0x100 + 32; total != want {
		t.Fatalf("覆盖量不对：%d（期望 %d）", total, want)
	}
	// 远处那块不能被误包含
	for _, r := range rs {
		if r.lo >= far.Base && r.hi <= far.Base+far.Size {
			t.Fatalf("把 64 MB 外的区域也包进来了：%#x-%#x", r.lo, r.hi)
		}
	}

	// ±8 MB 时应当覆盖到 big 的全部 4 MB
	rs8 := nearRangesIn([]pubHit{hit}, 8<<20, "near", regions)
	// ±8 MB 时窗口上界超出邻居区域末端，覆盖量 = 小区域 16 KB + 邻居 4 MB 全部。
	if got, want := totalRangeBytes(rs8), uintptr(16<<10+(4<<20)); got != want {
		t.Fatalf("±8 MB 覆盖量 %d，期望 %d（16 KB + 4 MB）", got, want)
	}
}

// TestScanRangesUnalignedKey 钉死"逐字节扫描"。
//
// 旧实现是 `off += 8`，只检查 8 字节对齐的窗口。当时的测试能过，是因为
// Go 的 `ecdh.PrivateKey` 结构体里还有一份**对齐**的内部副本被命中了，
// 埋进去的未对齐副本从来没被检查过 —— 测试给的是虚假的安全感。
//
// 这个用例把私钥只放在一个未对齐偏移上，扫描范围严格限定在那块缓冲内。
func TestScanRangesUnalignedKey(t *testing.T) {
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	defer proc.Close()

	buf := make([]byte, 1<<20)
	// 填成真实堆内存的形态（零填充 + 指针表），确保不会被判成高熵块降级
	fillRealistic(buf)

	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub := key.PublicKey().Bytes()
	priv := append([]byte(nil), key.Bytes()...)

	const off = 12345 // 不是 8 的倍数（12345 % 8 == 1）
	copy(buf[off:], priv)

	hdr := (*reflect.SliceHeader)(unsafe.Pointer(&buf))
	base := hdr.Data
	ranges := []scanRange{{lo: base, hi: base + uintptr(len(buf)), tag: "test"}}

	kf := keyfind.New(proc, pub, time.Now().Add(30*time.Second))
	var (
		found []byte
		at    uintptr
	)
	kf.OnFound = func(p []byte, tag string, a uintptr) {
		found = append([]byte(nil), p...)
		at = a
	}
	st := new(scanStat)
	if !scanRangesStat(kf, proc, ranges, time.Now().Add(30*time.Second), st) {
		t.Fatalf("未对齐偏移上的私钥没被找到（%s）", st.summary())
	}
	if want := base + off; at != want {
		t.Fatalf("命中地址 %#x，期望 %#x", at, want)
	}
	if string(found) != string(priv) {
		t.Fatalf("命中的字节不是埋进去的私钥")
	}
	runtime.KeepAlive(buf)
}

// TestWireLike 钉死"报文副本"判据。
//
// 用户现场的握手消息是 `0a 31 | 08 01 | 12 20 <32B 公钥> | ...`，
// 所以公钥前面 4 字节是 `08 01 12 20`，或至少 2 字节 `12 20`。
// 报告靠这个判据区分"报文副本"和"密钥材料"。
func TestWireLike(t *testing.T) {
	cases := []struct {
		name string
		buf  []byte
		pos  int
		want bool
	}{
		{"带版本号前缀", []byte{0x0a, 0x31, 0x08, 0x01, 0x12, 0x20, 0xaa}, 6, true},
		{"只有字段头", []byte{0x99, 0x99, 0x12, 0x20, 0xaa}, 4, true},
		{"前面是随机字节", []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0xaa}, 5, false},
		{"位置太靠前", []byte{0x12, 0x20}, 2, true},
		{"位置 0", []byte{0xaa}, 0, false},
	}
	for _, c := range cases {
		if got := wireLike(c.buf, c.pos); got != c.want {
			t.Errorf("%s: wireLike=%v，期望 %v", c.name, got, c.want)
		}
	}
}
