package main

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
)

// gnsTestBytes 生成一段确定性的伪随机字节。
//
// 不能用「seed+i」这种算术序列：那样不同 seed 的数据会互相包含
// （0x40..0xa0 里就藏着 0x80 开头的 12 字节），gnsScanRawForWire 的
// 12 字节针会假命中，测试会误报。xorshift 出来的数据没有这种结构。
func gnsTestBytes(seed, n int) []byte {
	x := uint32(seed)*2654435761 + 12345
	if x == 0 {
		x = 1
	}
	b := make([]byte, n)
	for i := range b {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		b[i] = byte(x)
	}
	return b
}

// gnsTestHandshake 造一份握手材料。cert 97 字节 / crypt 49 字节，
// 和 10:02 现场实测的长度一致。
func gnsTestHandshake() *cs2crypto.GNSHandshake {
	return &cs2crypto.GNSHandshake{
		ClientConnID: []byte{1, 2, 3, 4},
		ServerConnID: []byte{5, 6, 7, 8},
		ClientNonce:  []byte{0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18},
		ServerNonce:  []byte{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28},
		ClientCert:   gnsTestBytes(11, 97),
		ServerCert:   gnsTestBytes(22, 97),
		ClientCrypt:  gnsTestBytes(33, 49),
		ServerCrypt:  gnsTestBytes(44, 49),
	}
}

func TestGNSSaltVerdict(t *testing.T) {
	h := gnsTestHandshake()
	cases := []struct {
		name string
		a, b []byte
		want string
	}{
		{"一致", h.ClientNonce, h.ServerNonce, "salt=client||server（与线上一致）"},
		{"相反", h.ServerNonce, h.ClientNonce, "salt=server||client（与线上相反，需换 salt 顺序）"},
		{"全错", []byte{9, 9, 9, 9, 9, 9, 9, 9}, []byte{8, 8, 8, 8, 8, 8, 8, 8},
			"两段都对不上（+0x1890/+0x1968 可能不是这对 nonce）"},
	}
	for _, c := range cases {
		if got := gnsSaltVerdict(c.a, c.b, h); got != c.want {
			t.Fatalf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestGNSScanRawForWire(t *testing.T) {
	h := gnsTestHandshake()
	wire := gnsWireBlobs(h)

	// 把 client_cert 摆在 +0x1798，server_crypt 摆在 +0x19b8，其余不放。
	raw := make([]byte, gnsConnSpan)
	copy(raw[gnsOffBlob0:], h.ClientCert)
	copy(raw[gnsOffBlob3:], h.ServerCrypt)

	got := gnsScanRawForWire(raw, wire)
	for _, want := range []string{
		"client_cert@+0x1798",
		"server_crypt@+0x19b8",
		"server_cert@未找到",
		"client_crypt@未找到",
	} {
		if !containsStr(got, want) {
			t.Fatalf("扫描结果里缺 %q，实际：%s", want, got)
		}
	}
}

// fakeReader 是 gnsReader 的测试实现：按地址从 map 里取。
func fakeReader(pages map[uintptr][]byte) gnsReader {
	return func(addr uintptr, n int) []byte {
		b, ok := pages[addr]
		if !ok {
			return nil
		}
		if len(b) > n {
			b = b[:n]
		}
		return b
	}
}

// TestGNSReadSlotPtrLayout 覆盖真实布局：槽位是 {ptr, alloc, grow, len}，
// 数据在 *ptr。
func TestGNSReadSlotPtrLayout(t *testing.T) {
	h := gnsTestHandshake()
	const ptr = 0x1f0000

	raw := make([]byte, gnsConnSpan)
	off := gnsOffBlob0
	binary.LittleEndian.PutUint64(raw[off:], ptr)
	binary.LittleEndian.PutUint32(raw[off+8:], uint32(len(h.ClientCert)))  // alloc
	binary.LittleEndian.PutUint32(raw[off+12:], 0)                         // grow
	binary.LittleEndian.PutUint32(raw[off+16:], uint32(len(h.ClientCert))) // len

	read := fakeReader(map[uintptr][]byte{ptr: h.ClientCert})
	s := gnsReadSlot(read, raw, off)
	if s.Alloc != len(h.ClientCert) || s.Len16 != len(h.ClientCert) {
		t.Fatalf("长度解读不对：alloc=%d len16=%d", s.Alloc, s.Len16)
	}
	if s.AsPtrCap == "" || s.AsPtrLen == "" {
		t.Fatalf("指针型解读为空：cap=%q len=%q", s.AsPtrCap, s.AsPtrLen)
	}
	gnsMatchSlot(&s, gnsWireBlobs(h))
	if !containsStr(s.Matched, "client_cert") {
		t.Fatalf("指针布局没匹配上 client_cert：%s", s.Matched)
	}
}

// TestGNSMatchSlotRejectsWrongBytes 确认「长度对但内容不同」不会被误判成命中。
func TestGNSMatchSlotRejectsWrongBytes(t *testing.T) {
	h := gnsTestHandshake()
	const ptr = 0x1f0000

	bad := append([]byte(nil), h.ClientCert...)
	bad[3] ^= 0xff

	raw := make([]byte, gnsConnSpan)
	off := gnsOffBlob0
	binary.LittleEndian.PutUint64(raw[off:], ptr)
	binary.LittleEndian.PutUint32(raw[off+8:], uint32(len(bad)))

	read := fakeReader(map[uintptr][]byte{ptr: bad})
	s := gnsReadSlot(read, raw, off)
	gnsMatchSlot(&s, gnsWireBlobs(h))
	if s.Matched != "" {
		t.Fatalf("改了一个字节仍然命中：%s", s.Matched)
	}
}

// TestGNSAnalyzeKDFInputsFullMatch 覆盖端到端：四个槽位都按指针布局摆好，
// 应该得到 4/4。
func TestGNSAnalyzeKDFInputsFullMatch(t *testing.T) {
	h := gnsTestHandshake()
	wire := gnsWireBlobs(h)

	// 四段按 client_cert / server_cert / client_crypt / server_crypt 摆进四个槽位，
	// 并让 fakeReader 在各自指针处返回对应内容。
	order := [4][]byte{h.ClientCert, h.ServerCert, h.ClientCrypt, h.ServerCrypt}
	offs := [4]int{gnsOffBlob0, gnsOffBlob1, gnsOffBlob2, gnsOffBlob3}

	raw := make([]byte, gnsConnSpan)
	copy(raw[gnsOffSaltA:], h.ClientNonce)
	copy(raw[gnsOffSaltB:], h.ServerNonce)
	pages := map[uintptr][]byte{}
	for i, off := range offs {
		p := uintptr(0x1f0000 + i*0x1000)
		binary.LittleEndian.PutUint64(raw[off:], uint64(p))
		binary.LittleEndian.PutUint32(raw[off+8:], uint32(len(order[i])))
		binary.LittleEndian.PutUint32(raw[off+16:], uint32(len(order[i])))
		pages[p] = order[i]
	}

	// gnsAnalyzeKDFInputs 内部直接读 proc，所以这里只验证它的判定逻辑：
	// 用同样的解读函数手工跑一遍，确保四个槽位都能独立命中不同的段。
	read := fakeReader(pages)
	matched := 0
	seen := map[string]bool{}
	for i, off := range offs {
		s := gnsReadSlot(read, raw, off)
		gnsMatchSlot(&s, wire)
		if s.Matched == "" {
			t.Fatalf("槽位 %#x 未命中（期望 %s）", off, wire[i].Name)
		}
		if !containsStr(s.Matched, wire[i].Name) {
			t.Fatalf("槽位 %#x 命中 %s，期望 %s", off, s.Matched, wire[i].Name)
		}
		if !seen[wire[i].Name] {
			seen[wire[i].Name] = true
			matched++
		}
	}
	if matched != 4 {
		t.Fatalf("命中数 %d，期望 4", matched)
	}
	if got := gnsSaltVerdict(raw[gnsOffSaltA:gnsOffSaltA+8], raw[gnsOffSaltB:gnsOffSaltB+8], h); !containsStr(got, "一致") {
		t.Fatalf("salt 判定不对：%s", got)
	}
}

// containsStr 已移到 gnskdf.go（生产代码要用它数槽位命中），
// 这里不再重复定义 —— 同一包里重复定义会编译失败。

// TestGNSFindBlobToleratesLeadingByte 钉死「内存 blob 首字节被改写成 00 也能找到」。
//
// 夹具是 2026-10-19 15:08 现场 gns-kdf-20261019-150841.json 里的真实字节：
//
//	conn+0x1798 指针目标 : 00 01 12 20 30327618...  ← server_cert
//	线上 server_cert     : 08 01 12 20 30327618...
//
// 除首字节（00 / 08）外逐字节相同。旧实现从下标 0 取 12 字节当针，
// 永远找不到，日志写「四段在 conn 对象里的实际位置 未找到」——
// 把「已经拿到」误报成「没拿到」，这个假信号误导了好几轮方向判断。
func TestGNSFindBlobToleratesLeadingByte(t *testing.T) {
	mem := []byte{
		0x00, 0x01, 0x12, 0x20, 0x30, 0x32, 0x76, 0x18,
		0x9d, 0x26, 0xbc, 0x7e, 0x6d, 0xce, 0x47, 0x42,
		0x85, 0x9d, 0xfd, 0x52, 0x61, 0xe5, 0xb4, 0xaa,
	}
	wire := []byte{
		0x08, 0x01, 0x12, 0x20, 0x30, 0x32, 0x76, 0x18,
		0x9d, 0x26, 0xbc, 0x7e, 0x6d, 0xce, 0x47, 0x42,
		0x85, 0x9d, 0xfd, 0x52, 0x61, 0xe5, 0xb4, 0xaa,
	}
	if got := gnsFindBlob(mem, wire, 12); got != 0 {
		t.Fatalf("首字节差异（内存 00 / 线上 08）必须能找到，起点应为 0，现在 %d", got)
	}

	// 前缀不同的数据不能误命中 —— 这条防止「放宽成模糊匹配」把别的
	// 32 字节随机块也认成 cert。
	other := append([]byte(nil), wire...)
	other[4] ^= 0xFF
	if got := gnsFindBlob(mem, other, 12); got >= 0 {
		t.Fatalf("内容不同不该命中，现在命中在 %d", got)
	}

	// 偏移不为 0 时，返回的必须是 blob 的真实起点（要往回退 1）。
	pad := append([]byte{0xAA, 0xBB, 0xCC}, mem...)
	if got := gnsFindBlob(pad, wire, 12); got != 3 {
		t.Fatalf("blob 起点应为 3（3 字节填充），现在 %d", got)
	}
}

// TestGNSRecoverGateNeedsBothDirs 钉死「两个方向都够帧才开跑内存恢复」。
//
// 2026-10-19 15:08 现场：闸门是 `len(c2s) < 6 && len(s2c) < 6`，
// 只要有**一边**到 6 就开跑，于是第一次恢复在 c2s=6 / s2c=3 时启动。
// gnsTryKey 要求 3 帧全过，s2c 只有 3 帧 = 一帧不完整就判密钥错，
// 而日志上只写「都不对」。这条假阴性比「没跑」难查得多。
func TestGNSRecoverGateNeedsBothDirs(t *testing.T) {
	// gnsTryKey 的内部要求是 3 帧（见 gnsRecoverFromMemory 里的 need=3）。
	const tryKeyNeed = 3
	if gnsRecoverMinFrames < tryKeyNeed*2 {
		t.Fatalf("gnsRecoverMinFrames=%d 太小 —— 必须至少是 gnsTryKey 要求的 %d 帧的两倍，"+
			"否则一帧不完整就会把正确密钥判死", gnsRecoverMinFrames, tryKeyNeed)
	}
	if gnsRecoverMinFrames > gnsMaxFrames {
		t.Fatalf("gnsRecoverMinFrames=%d 超过缓冲区上限 %d —— 那样永远凑不够，内存恢复再也不会启动",
			gnsRecoverMinFrames, gnsMaxFrames)
	}
	if gnsRecoverMaxTries < 4 {
		t.Fatalf("gnsRecoverMaxTries=%d 太少 —— 要覆盖 6/12/18/24 四档帧数，"+
			"否则重试预算在开局几秒内就烧完，之后帧涨到 2000 也不再试", gnsRecoverMaxTries)
	}
}

// TestGNSAlignRead 钉住「按页读」的对齐算术。
//
// 这条测试的由来：10:22 现场 `[gnsnear] 扫 0.0 KB / 试 0 个窗口` ——
// ReadProcessMemory 只要范围内有一个不可读字节就整段返回 0，
// 所以一次性读 64 KB 窗口等于什么都没读，而日志看起来像「扫过了没命中」。
func TestGNSAlignRead(t *testing.T) {
	cases := []struct {
		addr  uintptr
		n     int
		start uintptr
		total int
		lead  int
	}{
		{0x1000, 0x100, 0x1000, 0x100, 0},          // 页对齐
		{0x1234, 0x100, 0x1000, 0x334, 0x234},      // 非对齐
		{0x22f27b84440, 0x10000, 0x22f27b84000, 0x10440, 0x440},
		{0x1fff, 1, 0x1000, 0x1000, 0xfff},         // 跨页的单字节
	}
	for _, c := range cases {
		start, total, lead := gnsAlignRead(c.addr, c.n)
		if start != c.start || total != c.total || lead != c.lead {
			t.Fatalf("gnsAlignRead(%#x,%#x) = (%#x,%#x,%#x)，期望 (%#x,%#x,%#x)",
				c.addr, c.n, start, total, lead, c.start, c.total, c.lead)
		}
		if start+uintptr(total) < c.addr+uintptr(c.n) {
			t.Fatalf("对齐后范围没覆盖请求范围")
		}
	}
}

// TestGNSWriteReproGuards 确认材料不全时不落盘（不产生误导性的半截文件）。
func TestGNSWriteReproGuards(t *testing.T) {
	h := gnsTestHandshake()
	if p := gnsWriteRepro(gnsConn{}, h, nil, nil, nil); p != "" {
		t.Fatalf("没有私钥却落盘了：%s", p)
	}
	if p := gnsWriteRepro(gnsConn{}, nil, gnsTestBytes(1, 32), nil, nil); p != "" {
		t.Fatalf("没有握手材料却落盘了：%s", p)
	}
}

// TestGNSHighEntropySegments 验证高熵区段定位。
//
// 背景：Valve 用 AES-NI，内存里**不存** key schedule，所以「扫 240 字节自洽」
// 这条路 0 命中（现场实证）。只能靠熵找裸 key，这个函数就是那个定位器，
// 它错了下一轮就还是瞎猜。
func TestGNSHighEntropySegments(t *testing.T) {
	// 全零：不该报任何区段。
	if segs := gnsHighEntropySegments(make([]byte, 4096), 0x1000); len(segs) != 0 {
		t.Fatalf("全零输入不该有高熵区段，得到 %d 段：%v", len(segs), segs)
	}

	// 在 +0x800 处埋 32 字节伪随机，前后都是零。
	buf := make([]byte, 4096)
	// 手工构造 32 个互不相同的字节：xorshift 出来的 32 字节常因生日悖论
	// 出现重复，去重数可能低于 28 的阈值，测试就会假失败。
	rnd := gnsDistinct(0)
	copy(buf[0x800:], rnd)

	segs := gnsHighEntropySegments(buf, 0x10000)
	if len(segs) != 1 {
		t.Fatalf("应只找到 1 段，得到 %d 段：%v", len(segs), segs)
	}
	// 起点会比埋入点早几字节（滑窗从 +4 起「零字节+28 随机」也够 28 种），
	// 所以不断言精确起点，只要求区段描述里含**完整的 32 字节 hex**。
	if !strings.Contains(segs[0], fmt.Sprintf("%x", rnd)) {
		t.Fatalf("区段描述里没有埋进去的 32 字节：%s", segs[0])
	}

	// 两段相隔很远：应各自成为一段，不能合并。
	buf2 := make([]byte, 8192)
	copy(buf2[0x100:], gnsDistinct(0))
	copy(buf2[0x1000:], gnsDistinct(64))
	if segs := gnsHighEntropySegments(buf2, 0); len(segs) != 2 {
		t.Fatalf("相隔很远的两个高熵块应报 2 段，得到 %d 段：%v", len(segs), segs)
	}
}

// gnsDistinct 返回 32 个互不相同的字节（base 只是起点偏移，用来区分不同用例）。
func gnsDistinct(base int) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte((base + i*7) & 0xFF)
	}
	return b
}
