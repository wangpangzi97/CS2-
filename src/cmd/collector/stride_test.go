package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"os"
	"reflect"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

// sliceBase 取切片底层数组的起始地址（测试里用来算"命中地址应该是多少"）。
func sliceBase(b []byte) uintptr {
	return (*reflect.SliceHeader)(unsafe.Pointer(&b)).Data
}

// fillRealistic 把 buf 填成"像真实进程内存"的样子：零填充为主，每 8 字节一个
// 典型堆指针（x64 用户态地址高 2 字节为 0）。
//
// ⚠ 测试里**不能**用 `byte(i % N)` 这种周期填充当"低熵内存"。预筛的判据是
// "零字节多不多、不同值少不少"，周期填充两条都不满足（32 字节窗口里 32 个不同值、
// 零字节≈0），通过率接近 100%，会被判成高熵块降级 —— 与真实内存（通过率 0.3%）
// 的行为正好相反，用它写的测试会反过来掩盖 bug。
func fillRealistic(buf []byte) {
	for i := 0; i+8 <= len(buf); i += 8 {
		v := uint64(0x000001F000000000) + uint64(i)*16
		binary.LittleEndian.PutUint64(buf[i:], v)
	}
}

// ── 高熵块自适应步长（第八轮）──
//
// 用户现场 17:02：`区域扫描：读 0.5 MB｜校验 507749 次｜耗时 11.537s`。
// 0.5 MB 做 50 万次校验 = 预筛通过率 96.8%，也就是说这些块**全是随机数据**，
// 预筛在这种块上等于没开。按 1 字节步长扫下去，1 MB 要 38 秒（X25519 实测
// 38.6 µs/次），一块就能吃掉整个预算。
//
// 下面三条测试钉死三件事：
//  1. 高熵块确实被降级成 8 字节步长（不然等于没改）；
//  2. 降级后 8 字节对齐的私钥仍然能找到（这是降级的正当性）；
//  3. 低熵块**不能**被降级（否则非对齐私钥会被误伤）。

func newSelfProc(t *testing.T) *memscan.Process {
	t.Helper()
	proc, err := memscan.OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("OpenForRead(self): %v", err)
	}
	t.Cleanup(func() { proc.Close() })
	return proc
}

func newKey(t *testing.T) (priv, pub []byte) {
	t.Helper()
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return append([]byte(nil), k.Bytes()...), k.PublicKey().Bytes()
}

func newFinder(t *testing.T, proc *memscan.Process, pub []byte) (*keyfind.Search, *uintptr) {
	t.Helper()
	kf := keyfind.New(proc, pub, time.Now().Add(30*time.Second))
	at := new(uintptr)
	kf.OnFound = func(_ []byte, _ string, a uintptr) { *at = a }
	return kf, at
}

// TestHighEntropyBlockUsesStride 高熵块必须被识别出来并降级。
func TestHighEntropyBlockUsesStride(t *testing.T) {
	proc := newSelfProc(t)
	priv, pub := newKey(t)

	// 1 MB 纯随机数据 —— 这正是"预筛筛不掉"的那种块。
	buf := make([]byte, 1<<20)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	// 埋在 8 字节对齐的位置（降级后的覆盖范围）。
	const off = 8192
	copy(buf[off:], priv)

	base := sliceBase(buf)
	kf, at := newFinder(t, proc, pub)
	st := new(scanStat)
	if !scanBufferStat(kf, buf, base, "stride-test", DefaultPrivFilter, st) {
		t.Fatalf("8 字节对齐的私钥在高熵块里没找到（%s）", st.summary())
	}
	if got, want := *at, base+off; got != want {
		t.Fatalf("命中地址 %#x，期望 %#x", got, want)
	}
	if n := st.strided.Load(); n != 1 {
		t.Fatalf("高熵块没有被降级（strided=%d）", n)
	}
	// 降级后校验次数应该是 1/8 量级，这是"能扫完"的前提。
	if c := st.cand.Load(); c > uint64(len(buf)/4) {
		t.Fatalf("降级后校验次数仍然过多：%d（块大小 %d）", c, len(buf))
	}
}

// TestLowEntropyBlockKeepsByteStride 低熵块必须保持逐字节，否则非对齐私钥被误伤。
//
// 这条是上一条的反面保险：如果哪天有人把"高熵判断"写成"永远降级"，
// TestScanRangesUnalignedKey 会挂；但如果判断阈值写反（低熵反而降级），
// 只有这条能抓住。
func TestLowEntropyBlockKeepsByteStride(t *testing.T) {
	proc := newSelfProc(t)
	priv, pub := newKey(t)

	buf := make([]byte, 1<<20)
	fillRealistic(buf) // 零填充 + 指针表 = 真实堆内存的形态
	const off = 12345  // 非 8 对齐
	copy(buf[off:], priv)

	base := sliceBase(buf)
	kf, at := newFinder(t, proc, pub)
	st := new(scanStat)
	if !scanBufferStat(kf, buf, base, "stride-test", DefaultPrivFilter, st) {
		t.Fatalf("低熵块里非对齐的私钥没找到（%s）", st.summary())
	}
	if got, want := *at, base+off; got != want {
		t.Fatalf("命中地址 %#x，期望 %#x", got, want)
	}
	if n := st.strided.Load(); n != 0 {
		t.Fatalf("低熵块不该被降级（strided=%d）", n)
	}
}

// TestHighEntropyStrideMissesUnaligned 如实记录降级的代价。
//
// 8 字节步长会漏掉非对齐的偏移。这条测试不是在"验证功能"，而是把
// 这个已知代价固定下来：将来如果有人认为"降级没有代价"，跑这条会看到真相。
func TestHighEntropyStrideMissesUnaligned(t *testing.T) {
	proc := newSelfProc(t)
	priv, pub := newKey(t)

	buf := make([]byte, 256<<10)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	const off = 8193 // 8193 % 8 == 1，非对齐
	copy(buf[off:], priv)

	kf, _ := newFinder(t, proc, pub)
	st := new(scanStat)
	if scanBufferStat(kf, buf, sliceBase(buf), "stride-test", DefaultPrivFilter, st) {
		t.Fatalf("8 字节步长居然命中了非对齐偏移 —— 说明步长逻辑不是我以为的那样")
	}
	// 降级是按 64 KB 分段算的，256 KB 会有 4 段被降级。
	if n := st.strided.Load(); n == 0 {
		t.Fatalf("高熵块没有被降级（strided=0）")
	}
}
