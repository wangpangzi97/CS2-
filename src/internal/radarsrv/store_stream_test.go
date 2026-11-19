package radarsrv

import (
	"encoding/binary"
	"testing"
)

// mkChunk 造一帧现场同构的 GCM 明文帧。
//
// 2026-10-19 16:07 现场定案的头（14 字节）：
//
//	80 <seq> 98 <??> 00 <??> 00 57 <offset u32le> [载荷]
//
// offset 在 [8:12]，载荷从 14 开始。
func mkChunk(seq byte, off int, payload []byte) []byte {
	f := make([]byte, 14+len(payload))
	f[0] = 0x80
	f[1] = seq
	f[2] = 0x98
	f[4] = 0x00
	f[7] = 0x57
	binary.LittleEndian.PutUint32(f[8:12], uint32(off))
	copy(f[14:], payload)
	return f
}

// TestGNSRebuildStreamStripsHeaderAndOrders 覆盖重建流的三件事：
// 剥头、按 offset 排序、空洞补齐。
func TestGNSRebuildStreamStripsHeaderAndOrders(t *testing.T) {
	a := []byte("AAAA")
	b := []byte("BBBB")
	c := []byte("CCCC")
	// 故意打乱顺序：重建必须按 offset 排，不能按到达顺序。
	frames := [][]byte{
		mkChunk(3, 8, c),
		mkChunk(1, 0, a),
		mkChunk(2, 4, b),
	}
	got, st := gnsRebuildStream(frames)
	if string(got) != "AAAABBBBCCCC" {
		t.Fatalf("重建流 = %q，期望 AAAABBBBCCCC", string(got))
	}
	if st.frames != 3 {
		t.Fatalf("帧数 = %d，期望 3", st.frames)
	}
	if st.hdr != 14 {
		t.Fatalf("头长 = %d，期望 14", st.hdr)
	}
	if st.holes != 0 {
		t.Fatalf("空洞 = %d，期望 0", st.holes)
	}
}

// TestGNSRebuildStreamIgnoresMinorityLength 保证小帧（控制消息）不会混进流。
//
// 现场 128 帧里有 125 条 1151 字节 + 3 条 54/28/98 字节，
// 后者头长度不同，混进去会把整条流顶歪。
func TestGNSRebuildStreamIgnoresMinorityLength(t *testing.T) {
	frames := [][]byte{
		mkChunk(1, 0, []byte("AAAA")),
		mkChunk(2, 4, []byte("BBBB")),
		mkChunk(3, 8, []byte("CCCC")),
		// 小帧：长度必须与分片帧**不同**，否则众数判断没法把它排除。
		// 现场是 1151 vs 54/28/98，这里用 18 vs 22 等价模拟。
		{0x80, 0x00, 0x98, 0x02, 0x00, 0x89, 0x01, 0x37, 0x01, 0x00, 0x00, 0x00, 0xff, 0xff,
			0xff, 0xff, 0x41, 0x00, 0x03, 0x00, 0x00, 0x00},
	}
	got, st := gnsRebuildStream(frames)
	if string(got) != "AAAABBBBCCCC" {
		t.Fatalf("重建流 = %q，小帧被混进来了", string(got))
	}
	if st.frames != 3 {
		t.Fatalf("帧数 = %d，期望 3（小帧应被排除）", st.frames)
	}
}

// TestGNSRebuildStreamFillsHole 保证 offset 不连续时补零，而不是硬拼。
//
// 硬拼会让后面的字节全部前移，离线就再也对不上边界 —— 这是最坏的一种错，
// 因为拼出来的东西"看起来"像数据。
func TestGNSRebuildStreamFillsHole(t *testing.T) {
	frames := [][]byte{
		mkChunk(1, 0, []byte("AAAA")),
		mkChunk(2, 8, []byte("CCCC")), // 4..8 缺失
		mkChunk(3, 12, []byte("DDDD")),
	}
	got, st := gnsRebuildStream(frames)
	if len(got) != 16 {
		t.Fatalf("长度 = %d，期望 16（空洞要补零）", len(got))
	}
	if string(got[:4]) != "AAAA" || string(got[8:12]) != "CCCC" || string(got[12:]) != "DDDD" {
		t.Fatalf("重建流位置错乱: %q", string(got))
	}
	if st.holes != 4 {
		t.Fatalf("空洞 = %d，期望 4", st.holes)
	}
}

// TestGNSRebuildStreamRejectsSingleFrame 保证样本太少时不硬凑。
//
// 只有 1 帧时无法判断头长和 offset 语义，宁可返回空，也不要给出一份
// 看起来像流、实际错位的文件 —— 那会浪费一整轮离线分析。
func TestGNSRebuildStreamRejectsSingleFrame(t *testing.T) {
	got, _ := gnsRebuildStream([][]byte{mkChunk(1, 0, []byte("AAAA"))})
	if len(got) != 0 {
		t.Fatalf("单帧应当拒绝重建，却得到 %d 字节", len(got))
	}
}

// TestPlainDumpTargetCoversIngame 盯住「明文样本要够到进局之后」。
//
// 2026-10-19 16:07 现场：那一局解出 3251 帧，但 plainDumpTarget=128
// 只落了 142 KB，全在 signon 段，进局后的实体消息一条都没有。
func TestPlainDumpTargetCoversIngame(t *testing.T) {
	if plainDumpTarget < 512 {
		t.Fatalf("plainDumpTarget = %d，太少 —— 128 时只够 signon 段，"+
			"进局后的实体消息全部丢失（2026-10-19 16:07 现场已复现）", plainDumpTarget)
	}
	if plainBinEvery <= plainDumpTarget {
		t.Fatalf("plainBinEvery(%d) 应当大于 plainDumpTarget(%d)，"+
			"否则二进制全量落盘会比 hex 样本还碎", plainBinEvery, plainDumpTarget)
	}
	if plainBinMaxFiles < 1 || plainBinMaxFiles > 8 {
		t.Fatalf("plainBinMaxFiles = %d，超出合理范围（1~8）", plainBinMaxFiles)
	}
}
