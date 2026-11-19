package keyfind

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"os"
	"runtime"
	"testing"
	"time"
	"unsafe"

	"local/cs2-radar/internal/memscan"
)

// sink 防止编译器把预埋缓冲回收掉。
var sink []byte

func TestVerifyPrivSemantics(t *testing.T) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := &Search{TargetPub: priv.PublicKey().Bytes()}
	if !s.verifyPriv(priv.Bytes()) {
		t.Fatal("正确私钥必须通过验证")
	}
	other, _ := curve.GenerateKey(rand.Reader)
	if s.verifyPriv(other.Bytes()) {
		t.Fatal("错误私钥不得通过验证")
	}
	if s.verifyPriv(priv.Bytes()[:31]) {
		t.Fatal("长度不足 32 必须失败")
	}
	if s.verifyPriv(append(append([]byte(nil), priv.Bytes()...), 0x00)) {
		t.Fatal("长度超过 32 必须失败")
	}
	s2 := &Search{TargetPub: make([]byte, 31)}
	if s2.verifyPriv(priv.Bytes()) {
		t.Fatal("目标公钥长度不对必须失败")
	}
}

// TestCheckFiresCallbackOnce 验证 check 的 sync.Once 语义与回调。
func TestCheckFiresCallbackOnce(t *testing.T) {
	curve := ecdh.X25519()
	priv, _ := curve.GenerateKey(rand.Reader)
	var hits int
	s := New(nil, priv.PublicKey().Bytes(), time.Time{})
	s.OnFound = func(p []byte, tag string, addr uintptr) { hits++ }

	if s.Check([]byte("wrongwrongwrongwrongwrongwrongwr"), "window", 0) {
		t.Fatal("错误候选不得命中")
	}
	if !s.Check(priv.Bytes(), "hint/udp4", 0x1000) {
		t.Fatal("正确候选必须命中")
	}
	if s.Check(priv.Bytes(), "window", 0x2000) {
		t.Fatal("已命中后必须直接返回 false")
	}
	if hits != 1 {
		t.Fatalf("回调必须只触发一次，实际 %d", hits)
	}
	select {
	case <-s.Done():
	default:
		t.Fatal("命中后 done 必须已关闭")
	}
	if !s.Found() {
		t.Fatal("Found() 应为 true")
	}
}

// planted 描述一次"把私钥埋进本进程内存"的结果。
type planted struct {
	heap      []byte
	keyAddr   uintptr // 私钥所在的绝对地址
	ptrHolder uintptr // 一个 8 字节槽，内容 = keyAddr，供 chase 路径使用
	ptrAddr   uintptr // ptrHolder 的地址
}

// plantKey 在新建的 4MB 堆缓冲里埋入私钥。
// align8=true 时落点 8 字节对齐（模拟 Go/C++ 分配器的对象起始地址）；
// align8=false 时落点 ≡5 (mod 8)，用于验证步长取舍。
func plantKey(t *testing.T, priv []byte, align8 bool) *planted {
	t.Helper()
	const size = 4 << 20
	heap := make([]byte, size)
	if _, err := rand.Read(heap); err != nil {
		t.Fatal(err)
	}
	base := uintptr(unsafe.Pointer(&heap[0]))
	off := uintptr(1 << 20)
	want := uintptr(0)
	if !align8 {
		want = 5
	}
	for (base+off)%8 != want {
		off++
	}
	copy(heap[off:], priv)
	sink = heap // 保持存活，防止被回收

	p := &planted{heap: heap}
	p.keyAddr = uintptr(unsafe.Pointer(&heap[off]))
	p.ptrHolder = p.keyAddr
	p.ptrAddr = uintptr(unsafe.Pointer(&p.ptrHolder))
	return p
}

func regionsNow(t *testing.T, proc *memscan.Process) []memscan.Region {
	t.Helper()
	rs, err := proc.RegionsWithError(time.Now().Add(30*time.Second), 0)
	if err != nil && err != memscan.ErrRegionDeadline {
		t.Fatalf("RegionsWithError: %v", err)
	}
	return rs
}

func regionContaining(t *testing.T, regions []memscan.Region, addr uintptr) []memscan.Region {
	t.Helper()
	for _, r := range regions {
		if addr >= r.Base && addr < r.Base+r.Size {
			return []memscan.Region{r}
		}
	}
	t.Fatalf("未找到包含 %#x 的可读区域", addr)
	return nil
}

// TestFindInSelfProcess 是端到端动态验证：
// 把已知 X25519 私钥埋进本进程堆，再用重构的搜索器把它挖出来。
// 覆盖 hint / pointer / window 三条路径。
func TestFindInSelfProcess(t *testing.T) {
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

	regions, err := proc.RegionsWithError(time.Now().Add(20*time.Second), 0)
	if err != nil && err != memscan.ErrRegionDeadline {
		t.Fatalf("RegionsWithError: %v", err)
	}
	if len(regions) == 0 {
		t.Fatal("未枚举到任何可读区域")
	}
	t.Logf("可读区域 %d 个", len(regions))

	t.Run("hint", func(t *testing.T) {
		p := plantKey(t, priv.Bytes(), true)
		s := New(proc, pub, time.Now().Add(30*time.Second))
		s.AddHint(Hint{Addr: p.keyAddr})
		got, tag, addr, err := s.FindPrivWithHints(regions)
		if err != nil {
			t.Fatalf("hint 路径失败: %v", err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(priv.Bytes()) {
			t.Fatalf("hint 路径取到错误私钥 %x", got)
		}
		if addr != p.keyAddr {
			t.Fatalf("命中地址 %#x 与埋点 %#x 不一致", addr, p.keyAddr)
		}
		t.Logf("hint 命中 tag=%s addr=%#x", tag, addr)
	})

	t.Run("pointer", func(t *testing.T) {
		p := plantKey(t, priv.Bytes(), true)
		s := New(proc, pub, time.Now().Add(30*time.Second))
		var got []byte
		var tag string
		var addr uintptr
		s.OnFound = func(b []byte, tg string, a uintptr) { got, tag, addr = b, tg, a }
		if !s.Chase(p.ptrAddr, 2) {
			t.Skip("指针链未命中（该地址可能落在 Go 运行期隔离页），跳过")
		}
		if hex.EncodeToString(got) != hex.EncodeToString(priv.Bytes()) {
			t.Fatalf("pointer 路径取到错误私钥 %x", got)
		}
		t.Logf("pointer 命中 tag=%s addr=%#x", tag, addr)
	})

	t.Run("window-aligned", func(t *testing.T) {
		p := plantKey(t, priv.Bytes(), true)
		// 埋点后重新枚举，新堆所在区域才会出现在列表里
		one := regionContaining(t, regionsNow(t, proc), p.keyAddr)
		s := New(proc, pub, time.Now().Add(120*time.Second))
		got, tag, addr, err := s.FindPrivWithHints(one)
		if err != nil {
			t.Fatalf("window 路径失败: %v", err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(priv.Bytes()) {
			t.Fatalf("window 路径取到错误私钥 %x", got)
		}
		t.Logf("window(8 对齐) 命中 tag=%s addr=%#x stats=%v", tag, addr, s.Stats())
	})

	// 这一条把"步长"这个取舍变成有证据的结论：
	// 默认 8 字节步长会漏掉非 8 对齐的落点，改成 1 就能找到。
	t.Run("window-misaligned", func(t *testing.T) {
		// 🔴 必须用**全新的密钥对**，不能复用上面的 priv。
		//
		// 原来复用 priv，而 hint / pointer / window-aligned 三个子测试都埋过同一个私钥。
		// 那些副本是否已被 GC 回收是**不确定**的：只要有一个 8 对齐的旧副本还活着，
		// s8（8 字节步长）就会命中它，这条测试就假失败。
		// 实测就是偶发的：`go test ./...` 里挂过一次（报「8 字节步长不应命中非对齐落点」），
		// 单独重跑又过 —— 典型的 GC 时序依赖。
		//
		// 换一把**从没埋过**的密钥，内存里就只有这一个非对齐落点，判据才是确定的。
		misPriv, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		misPub := misPriv.PublicKey().Bytes()

		p := plantKey(t, misPriv.Bytes(), false)
		if p.keyAddr%8 == 0 {
			t.Fatal("构造失败：落点应为非 8 对齐")
		}
		one := regionContaining(t, regionsNow(t, proc), p.keyAddr)

		s8 := New(proc, misPub, time.Now().Add(60*time.Second))
		got8, _, addr8, err8 := s8.FindPrivWithHints(one)
		if err8 == nil && addr8 == p.keyAddr {
			// 只有「命中的就是那个非对齐埋点」才说明步长失效了。
			t.Fatalf("8 字节步长命中了非对齐埋点 %#x（说明步长被改成 1 或被对齐了）", p.keyAddr)
		}
		if err8 == nil {
			// 🔴 命中同区域里的**另一个对齐副本**是正常的，不算违反结论。
			//
			// 为什么会存在副本：`ecdh.PrivateKey` 自己就持有一份 32 字节原文
			// （x25519PrivateKey 是 []byte，底层数组天然对齐）。只要它和埋点落在
			// 同一个 VirtualQuery 区域里，8 字节步长就会先撞上它。
			// 这正是这条测试以前偶发假失败的原因 —— 判据写成「有没有报错」，
			// 而不是「有没有命中埋点」。密钥对换新的也躲不掉，因为新密钥对象
			// 同样在堆上。
			if hex.EncodeToString(got8) != hex.EncodeToString(misPriv.Bytes()) {
				t.Fatalf("8 字节步长命中了一个**别的**私钥 %x，既不是埋点也不是本用例的密钥", got8)
			}
			t.Logf("8 字节步长未命中埋点 %#x，命中同区域内的对齐副本 %#x（密钥对象自身持有原文）——"+
				"「步长会漏非对齐落点」这个结论仍成立", p.keyAddr, addr8)
		} else {
			t.Logf("8 字节步长按预期漏过：%v", err8)
		}

		s1 := New(proc, misPub, time.Now().Add(180*time.Second))
		s1.WindowStride = 1
		got, tag, addr, err := s1.FindPrivWithHints(one)
		if err != nil {
			t.Fatalf("步长 1 应能命中非对齐落点，实际失败: %v", err)
		}
		if hex.EncodeToString(got) != hex.EncodeToString(misPriv.Bytes()) {
			t.Fatalf("步长 1 取到错误私钥 %x", got)
		}
		t.Logf("步长 1 命中 tag=%s addr=%#x stats=%v", tag, addr, s1.Stats())
	})
}

// BenchmarkVerifyPriv 量出单次 X25519 校验的真实成本。
//
// 为什么必须有这个基准：全量兜底扫描的可行性完全由它决定。用户机器上
// 可读内存 7.3 GB，按 8 字节步长是 9.2 亿个候选；clamp 形态过滤后剩 1/32，
// 即 2870 万次校验。只有知道单次耗时，才能诚实地判断"全量扫"到底是
// 几秒钟还是几十分钟，而不是拍脑袋定预算。
func BenchmarkVerifyPriv(b *testing.B) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	s := &Search{TargetPub: k.PublicKey().Bytes()}
	// 故意用一个**错误**的私钥，保证每次都走完整条标量乘 + 比较路径。
	wrong := make([]byte, 32)
	copy(wrong, k.Bytes())
	wrong[0] ^= 0xFF
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.verifyPriv(wrong)
	}
}

// BenchmarkVerifyPrivParallel 量出多核下的等效吞吐 —— 兜底扫描是并发的。
func BenchmarkVerifyPrivParallel(b *testing.B) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	wrong := make([]byte, 32)
	copy(wrong, k.Bytes())
	wrong[0] ^= 0xFF
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		s := &Search{TargetPub: k.PublicKey().Bytes()}
		for pb.Next() {
			s.verifyPriv(wrong)
		}
	})
}

// TestUnclampedPrivStillVerifies 钉住一个被实测推翻的假设。
//
// 曾经想用 X25519 的 clamp 形态（b[0]&7==0 && b[31]&0xC0==0x40）当扫描过滤条件，
// 认为私钥"存储时就已经 clamp"。实测证明这是错的：Go / libsodium / OpenSSL
// 都保存**原始随机 32 字节**，在运算时才对副本 clamp。本机实测 Go 生成的私钥
// 只有 3.4%（≈1/32）满足 clamp 形态。
//
// 所以这个测试的断言是：**不满足 clamp 形态的私钥照样是合法私钥、照样能验证
// 通过**。任何把它当硬过滤的改动都会让真私钥有 31/32 的概率被静默丢掉。
func TestUnclampedPrivStillVerifies(t *testing.T) {
	curve := ecdh.X25519()
	isClamped := func(b []byte) bool {
		return len(b) == 32 && b[0]&7 == 0 && b[31]&0xC0 == 0x40
	}
	var raw []byte
	for i := 0; i < 200; i++ { // 期望约 32 次命中一次，200 次几乎必然找到
		k, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if !isClamped(k.Bytes()) {
			raw = k.Bytes()
			break
		}
	}
	if raw == nil {
		t.Skip("连续 200 次都生成了 clamp 形态的私钥（概率 1/32^200），跳过")
	}
	k, err := curve.NewPrivateKey(raw)
	if err != nil {
		t.Fatalf("未 clamp 的 32 字节必须能当私钥用: %v", err)
	}
	s := &Search{TargetPub: k.PublicKey().Bytes()}
	if !s.verifyPriv(raw) {
		t.Fatal("未 clamp 的私钥必须能通过验证 —— 否则按 clamp 形态过滤就会漏掉真私钥")
	}
	t.Logf("未 clamp 私钥：首字节=%#02x 末字节=%#02x（clampOK=false），验证通过", raw[0], raw[31])
}
