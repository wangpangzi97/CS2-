package radarsrv

import (
	"encoding/hex"
	"strings"
	"testing"
)

// 现场真实载荷：2026-10-20 08:27 那局 gns-signon-*.bin 里
// `27 dc 04 0a 08 userinfo ...` 这条 CreateStringTable 的 field7（574 字节）。
// 它是 snappy 压缩态，解出来正好 638 字节 —— 与同一条消息的 field8
// (uncompressed_size=638) 逐位相等，这是「压缩算法是 snappy」的硬证据。
const realUserinfoSnappyHex = "" +
	"fe04908301188dc2044879e021ba62ec78a02bfa6de7b9e9ae39e167044bc1235300004400064008110ba00a000c0012" +
	"0014c0620072a2e000724e896a8e781b43435363030313014ec5af12000011801110024e0d0b28020003800400053019" +
	"009b05675cc8b9aee8f9e0e939a32aba20e8b9286339296d047b481a50016708c64008110b116774680046a33001523e" +
	"9a6baea8785eea79befb78be98498e6b1b516a704211016c08411052110b0d6c60b01a8095281c8098978292ebb6460c" +
	"8ec63105004004601484110bf06da000c00020014001cc0660340a1320e8af8be6af81e4b88de5a682e68f90e58d8711" +
	"c059cc5a01001001180621c059cc5a010010012800300048005000bb01488d820508baa32cba626cf92369f9a723fa60" +
	"68f9a66ff9a66fc42d14d95200004400c641c82d14d952000044000a2d316870007aa20001824e186b3e5b7afe395b1e" +
	"4a595eb81871f831881001c708811072110b11c7001c01c72cd0a5a1d58dddb54578a1f0a205c7042484110b11c7f0bd" +
	"2c0606c06262002c4606c06266002c8606c0626a002cc606c0626e002c0607c06272004c0606c06462004c4606c06466" +
	"004c8606c0646a004cc606c0646e004c0607c06472006c0606c06662006c4606c06666006c8606c0666a006cc606c066" +
	"6e006c0607c06672008c0606c06862008c4606c06866008c8606c0686a008cc606c0686e008c0607c0687200ac0606c0" +
	"6a6200ac4606c06a6600ac8606c06a6a00acc606c06a6e00ac0607c06a7200cc0606c06c6200cc4606c06c660000"

func TestGNSSnappyRealUserinfo(t *testing.T) {
	raw, err := hex.DecodeString(realUserinfoSnappyHex)
	if err != nil {
		t.Fatalf("测试数据 hex 坏：%v", err)
	}
	if len(raw) != 574 {
		t.Fatalf("测试数据长度 = %d，期望 574", len(raw))
	}
	out, err := gnsSnappyDecode(raw)
	if err != nil {
		t.Fatalf("gnsSnappyDecode 失败：%v", err)
	}
	// 638 是 CSVCMsg_CreateStringTable 的 field8（uncompressed_size），
	// 与 snappy 头部 varint 独立算出来的一致 —— 这条断言等于交叉验证两次。
	if len(out) != 638 {
		t.Fatalf("解压长度 = %d，期望 638（field8 的 uncompressed_size）", len(out))
	}
	// 表数据里应当有 UTF-8 玩家名（现场这条含「不如提升」）。
	if !strings.Contains(string(out), "不如提升") {
		t.Fatalf("解压结果里没找到现场存在的 UTF-8 玩家名「不如提升」")
	}
}

func TestGNSSnappyRejectsBad(t *testing.T) {
	if _, err := gnsSnappyDecode(nil); err == nil {
		t.Fatal("空输入应当报错")
	}
	// 长度声明 100，但只给一个 literal 头，属于截断。
	if _, err := gnsSnappyDecode([]byte{100, 0xfc, 1, 2}); err == nil {
		t.Fatal("截断输入应当报错")
	}
	// 回溯偏移超过已出长度。
	if _, err := gnsSnappyDecode([]byte{10, 0x01, 0x50}); err == nil {
		t.Fatal("非法回溯偏移应当报错")
	}
}

// 构造一条最小的 CSVCMsg_CreateStringTable：
//
//	0a 08 "userinfo" 10 40 18 00 20 00 28 00 30 00 3a 06 <snappy 6B> 40 06 48 01
func buildCSTPayload(name string, snappy []byte) []byte {
	body := []byte{0x0a, byte(len(name))}
	body = append(body, name...)
	body = append(body, 0x10, 0x40) // f2 max_entries=64
	body = append(body, 0x18, 0x00, 0x20, 0x00, 0x28, 0x00, 0x30, 0x00)
	body = append(body, 0x3a, byte(len(snappy))) // f7 string_data
	body = append(body, snappy...)
	body = append(body, 0x40, 0x06) // f8 uncompressed_size=6
	body = append(body, 0x48, 0x01) // f9 data_compressed=1
	p := []byte{39, byte(len(body))} // cmd=39, size（<128 用单字节 varint）
	return append(p, body...)
}

func TestGNSScanCreateStringTable(t *testing.T) {
	// snappy: 声明 6 字节，literal 6 字节
	snappy := []byte{0x06, 0x14, 'a', 'b', 'c', 'd', 'e', 'f'}
	payload := buildCSTPayload("userinfo", snappy)
	// 前面垫一点无关字节，验证是「扫描」而不是「从 0 开始」
	payload = append([]byte{0x9c, 0xcc, 0x28}, payload...)

	tabs := gnsScanCreateStringTable(payload)
	if len(tabs) != 1 {
		t.Fatalf("扫出 %d 张表，期望 1 张：%+v", len(tabs), tabs)
	}
	got := tabs[0]
	if got.Name != "userinfo" {
		t.Fatalf("表名 = %q，期望 userinfo", got.Name)
	}
	if got.MaxEntries != 64 {
		t.Fatalf("MaxEntries = %d，期望 64", got.MaxEntries)
	}
	if !got.DataCompressed {
		t.Fatal("DataCompressed 应为 true")
	}
	if got.UncompressedSize != 6 {
		t.Fatalf("UncompressedSize = %d，期望 6", got.UncompressedSize)
	}
	if got.DecodedLen != 6 {
		t.Fatalf("DecodedLen = %d，期望 6（err=%s）", got.DecodedLen, got.DecodeErr)
	}
}

func TestGNSScanCreateStringTableNoFalsePositive(t *testing.T) {
	// 随机字节里不该扫出表
	b := make([]byte, 512)
	for i := range b {
		b[i] = byte(i*37 + 11)
	}
	if tabs := gnsScanCreateStringTable(b); len(tabs) != 0 {
		t.Fatalf("随机数据扫出 %d 张表：%+v", len(tabs), tabs)
	}
	// 表名不可打印也应当被拒
	bad := buildCSTPayload("ab\x01cd", []byte{0x00})
	if tabs := gnsScanCreateStringTable(bad); len(tabs) != 0 {
		t.Fatalf("不可打印表名被误收：%+v", tabs)
	}
}

func TestGNSSplitReliable(t *testing.T) {
	// 三条消息：size 3 / 4 / 5（都 < 0x20，用 6 位直接编码）
	var buf []byte
	for _, body := range [][]byte{{1, 2, 3}, {4, 5, 6, 7}, {8, 9, 10, 11, 12}} {
		buf = append(buf, byte(len(body)))
		buf = append(buf, body...)
	}
	msgs, resync, _ := gnsSplitReliable(buf)
	if resync != 0 {
		t.Fatalf("重同步 %d 次，期望 0", resync)
	}
	if len(msgs) != 3 {
		t.Fatalf("切出 %d 条，期望 3", len(msgs))
	}
	if msgs[2][4] != 12 {
		t.Fatalf("第 3 条尾字节 = %d，期望 12", msgs[2][4])
	}

	// 大消息：s6 >= 0x20 走「低 5 位 + 高位 varint」
	big := make([]byte, 300)
	for i := range big {
		big[i] = byte(i)
	}
	var b2 []byte
	b2 = append(b2, 0x20|(300&0x1f)) // 0x20 标记 + 低 5 位
	b2 = append(b2, byte(300>>5))    // 高位 varint = 9
	b2 = append(b2, big...)
	m2, _, _ := gnsSplitReliable(b2)
	if len(m2) != 1 || len(m2[0]) != 300 {
		t.Fatalf("大消息切分失败：%d 条，长度 %d", len(m2), len(m2[0]))
	}
}
