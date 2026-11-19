package radarsrv

import (
	"encoding/hex"
	"testing"
)

// 下面三条是 2026-10-19 16:30 现场 `gns-msgframed-20261019-163006.bin` 里的
// **原样字节**，不是构造的。它们把位级分帧的规则钉死：
//
//	[u8 0x01][varint tick][位打包 netmessage 链]
//	cmd = ReadUBitVar（Source 版，先 6 位）｜size = ReadVarInt32（8 位一组）
//	body 从当前**位**位置开始，不字节对齐
//
// 规则要是改错（比如把 ReadUBitVar 换成「2 位选择器」的简化版），
// 这三条会立刻失败。
const (
	// 330 字节：单条 cmd=207 size=324，body 里是完美平台的 UI 文本。
	fxGNSMsg330 = "01001f130b40880768a00a2004488c0af098bdb9d1818cb185cdcdf59c98bdb9d14d" +
		"a5e995b5cc9df8941fee9a77029a5fdaa65fd2bef36af2bc98bdb9d1f9f098bdb9d1818c" +
		"b185cdcdf59cccd1c985d1d5b5b588bdb191b5a4d185b1a58d9d808cbdb1bdc9f59c8ce0" +
		"c0e0c0e0c09cf8b4b480b4cdf1bc98bdb9d1f980f081f098bdb9d1818cb185cdcdf59c98" +
		"bdb9d14da5e995b5cc9df89803969607729a2342962b7e9e3b1ebef36af2bc98bdb9d1f9" +
		"f098bdb9d1818cb185cdcdf59cccd1c985d1d5b5b588bdb191b5a4d185b1a58d9d808cbd" +
		"b1bdc9f59c8ce0c0e0c0e0c09cf8b4b48094f0bc98bdb9d1f9f088c9f9f0a4b59d81cc" +
		"c98df59ca0d1d1c1e9bcbcc0dd858d91b9b9dcb5c1d9c1b98cbdb5bd8ccdc98cbdb5b5" +
		"d5b9a5d1e5bdb0bd9dbdbdc0dd857dd9b8ccd99d9dbcf86810200c800468102024a0706" +
		"810202080008030d70618"

	// 760 字节：8 条记录混在一起，cmd 依次出现 207/201/208。
	fxGNSMsg760 = "01001fb7402c0a68102024a05068202020804c0b22a6166814200c803023681c200874" +
		"000000fc68102018e004802cd7067cec02011aa04180908052a181808000f20f48bf4ca0" +
		"f1801020b170571606f7e6f615b64673a3418060800300a25c1b90b197c24303408f185" +
		"005003812500700db3e90c44303d0cd9d4f456defd94fc783c1ac0f88008a00106b78f" +
		"bb2009420e1e900daffffffffffffffff7f80dc4303f0d4d04fc57bdb3e5087afe88e90" +
		"de4343c455db4f8590c2ac4f0731b2824fc6420a0f0d5329d6441512fc8a441d8a491e43" +
		"120f0df31408b915593f62bd1df39b7f3f20ffffffffffffffffff0140f7a6f6e20f50" +
		"80800168ffffffffffffffffff011f4f414068102024a000683420208008123adbeeff" +
		"ffffff0768102024a0546820202080fc03d22f1368102014c08068102014c080692020" +
		"04481084add1dc68102010a08468102014c01068102014c00c8028d70640ed82807c54" +
		"a14c557384312d00827ca4e2d1e4cca7a5c000c050d346145a823df4ff002c1414be91" +
		"2d4000305e0ea706f50882f251852b0fcf0786200188f291ca4493339f960203c0abf3" +
		"385156992251d1b3c7d0c7c40210e2011aa802080112a3023c666f6e7420636c617373" +
		"3d27666f6e7453697a652d73273ee587bbe69d80e697b6e997b4efbc9a3c2f666f6e74" +
		"3e3c666f6e7420636c6173733d277374726174756d2d626f6c642d6974616c69632720" +
		"636f6c6f723d2723383038303830273e2d2d206d733c2f666f6e743e207c203c666f6e" +
		"7420636c6173733d27666f6e7453697a652d73273ee680a5e5819ce68890e58a9fe78e" +
		"87efbc9a3c2f666f6e743e3c666f6e7420636c6173733d277374726174756d2d626f6c" +
		"642d6974616c69632720636f6c6f723d2723383038303830273e2d2d20253c2f666f6e" +
		"743e3c62723e3c696d67207372633d27687474703a2f2f70776163646e2e776d707670" +
		"2e636f6d2f637332636f6d6d756e6974792f6c6f676f2f7077615f362e737667272f3e" +
		"1a04080320011a040809281c1a040808200020cbb501"

	// 26 字节：带 tick 的那条（tick=22834，不是 0），单条 cmd=58 size=19。
	fxGNSMsg26 = "01b2b201da4c20b0ffffff1f482c8cb17db185b99dd5859d9501"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("夹具 hex 解不开: %v", err)
	}
	return b
}

// consumedBits 返回这条载荷里 netmessage 链实际占掉的位数（含载荷头）。
func consumedBits(t *testing.T, m []byte, msgs []gnsNetMsg) int {
	t.Helper()
	head := 8
	if _, n, ok := readGNSVarint(m[1:]); ok {
		head = 8 + n*8
	}
	total := head
	for _, nm := range msgs {
		total += nm.HdrBits + len(nm.Body)*8
	}
	return total
}

// TestGNSParseNetMsgsSingle 验证单条消息：cmd=207、size=324、尾部只剩 6 位。
func TestGNSParseNetMsgsSingle(t *testing.T) {
	m := mustHex(t, fxGNSMsg330)
	msgs, tick, err := gnsParseNetMsgs(m)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if tick != 0 {
		t.Fatalf("tick = %d，期望 0", tick)
	}
	if len(msgs) != 1 {
		t.Fatalf("解出 %d 条，期望 1 条", len(msgs))
	}
	if msgs[0].Cmd != 207 {
		t.Fatalf("cmd = %d，期望 207", msgs[0].Cmd)
	}
	if len(msgs[0].Body) != 324 {
		t.Fatalf("body 长 %d，期望 324", len(msgs[0].Body))
	}
	if got := len(m)*8 - consumedBits(t, m, msgs); got != 6 {
		t.Fatalf("尾部剩 %d 位，期望 6 位（对齐填充）", got)
	}
	// body 是 protobuf，且里面是完美平台的 UI 文本。
	body := msgs[0].Body
	if len(body) < 12 || body[0] != 0x10 {
		t.Fatalf("body 开头不像 protobuf: % x", body[:min(12, len(body))])
	}
}

// TestGNSParseNetMsgsMulti 验证一条载荷里混了 8 条消息，且尾部正好对齐。
//
// 这一条最要紧：它证明「一条可靠消息 = 多条 netmessage」，
// 而不是「一条可靠消息 = 一条消息」。
func TestGNSParseNetMsgsMulti(t *testing.T) {
	m := mustHex(t, fxGNSMsg760)
	msgs, _, err := gnsParseNetMsgs(m)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(msgs) != 8 {
		t.Fatalf("解出 %d 条，期望 8 条", len(msgs))
	}
	wantCmd := []uint32{207, 207, 201, 201, 207, 208, 208, 207}
	wantLen := []int{45, 46, 94, 66, 83, 46, 35, 324}
	for i := range msgs {
		if i < len(wantCmd) && msgs[i].Cmd != wantCmd[i] {
			t.Fatalf("#%d cmd = %d，期望 %d", i, msgs[i].Cmd, wantCmd[i])
		}
		if i < len(wantLen) && len(msgs[i].Body) != wantLen[i] {
			t.Fatalf("#%d body 长 %d，期望 %d", i, len(msgs[i].Body), wantLen[i])
		}
	}
	if got := len(m)*8 - consumedBits(t, m, msgs); got != 0 {
		t.Fatalf("尾部剩 %d 位，期望 0（正好吃满）", got)
	}
}

// TestGNSParseNetMsgsTick 验证带 tick 的那条：tick=22834、cmd=58、body 19 字节。
//
// tick 不为 0 说明这个字段确实是 tick，不是常量 0。
func TestGNSParseNetMsgsTick(t *testing.T) {
	m := mustHex(t, fxGNSMsg26)
	msgs, tick, err := gnsParseNetMsgs(m)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if tick != 22834 {
		t.Fatalf("tick = %d，期望 22834", tick)
	}
	if len(msgs) != 1 {
		t.Fatalf("解出 %d 条，期望 1 条", len(msgs))
	}
	if msgs[0].Cmd != 58 {
		t.Fatalf("cmd = %d，期望 58", msgs[0].Cmd)
	}
	if len(msgs[0].Body) != 19 {
		t.Fatalf("body 长 %d，期望 19", len(msgs[0].Body))
	}
}

// TestGNSParseNetMsgsRejectsNonReliable 保证首字节不是 0x01 的载荷不会被硬解。
//
// 现场 328 条里有 6 条是 0x03/0xa1/0xfc/0xb0，硬解会产出垃圾 cmd，
// 把「cmd 种类收敛」这个判据污染掉。
func TestGNSParseNetMsgsRejectsNonReliable(t *testing.T) {
	for _, first := range []byte{0x03, 0xa1, 0xfc, 0xb0, 0x00} {
		m := []byte{first, 0x00, 0x11, 0x22, 0x33}
		if _, _, err := gnsParseNetMsgs(m); err == nil {
			t.Fatalf("首字节 0x%02x 不该被当成 netmessage 链", first)
		}
	}
	if _, _, err := gnsParseNetMsgs([]byte{0x01}); err == nil {
		t.Fatal("只有 1 字节的载荷不该解析成功")
	}
}

// TestGNSReadUBitVarIsSourceVersion 盯住 ReadUBitVar 的**具体**编码。
//
// 现场 cmd=207 = 0b11001111，编码成「6 位 0b001111 + 0x10 档 + 4 位 0b1100」。
// 如果换成「2 位选择器」的简化版，会读成完全不同的值（硬规则 218 第 4 组
// 就是这么读出 1505/57580 这类垃圾的）。
func TestGNSReadUBitVarIsSourceVersion(t *testing.T) {
	// 现场真实字节 `1f 13`（330 字节那条的开头）就是 cmd=207 的编码：
	//   前 6 位 = 0x1f & 0x3f = 31 → 31&0x30 = 0x10 → 走「再读 4 位」档
	//   再 4 位 = 12（0b1100）
	//   cmd = (31 & 15) | (12 << 4) = 15 | 192 = 207
	// 换成「2 位选择器」的简化版会读成完全不同的值。
	br := newGNSBitReader([]byte{0x1f, 0x03}, 0)
	got, ok := br.readUBitVar()
	if !ok {
		t.Fatal("readUBitVar 失败")
	}
	if got != 207 {
		t.Fatalf("cmd = %d，期望 207（Source 版 ReadUBitVar）", got)
	}
	if br.pos != 10 {
		t.Fatalf("读了 %d 位，期望 10 位（6+4）", br.pos)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
