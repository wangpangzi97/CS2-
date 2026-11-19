package radarsrv

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
	"time"

	"local/cs2-radar/internal/cs2crypto"
	"local/cs2-radar/internal/cs2proto"
)

// 这个文件锁死「只解一个方向」这个致命回归。
//
// 现场症状（13:24 日志，4207 个包全程）：
//
//	[snp] 方向=c2s 包=4207 可靠段=68 不可靠=4216 坏帧=0(0x00) 可靠消息=68
//	      首段位置=1224 流位置=0 已出=0 最大空洞=0 待补段=0 netchan=0 已切=0
//
// s2c 一条都没解、`流位置`/`已出` 恒为 0、`netchan` 恒为 0 —— 服务端下发的
// 实体数据全部丢掉，雷达自然没有任何目标。三个根因：
//
//  1. scheme / relStream / msgSplit 是**单份**的，方向一换就 `Reset()`；
//  2. runProbe 只挑一个方向，装上后 `if sess.scheme != nil { return }` 再不重跑；
//  3. tryGNS 短路判据是 `anyScheme() != nil`，而内存直读只装一个方向。
//
// 本测试用两个**互不相同的密钥**分别封 s2c / c2s 帧，然后交错喂进去：
// 只要还残留任何一个根因，下面的断言就会失败。

// dualScheme 造一对独立的加解密方案（s2c 一套、c2s 一套），并交出各自的封帧闭包。
func dualScheme(t *testing.T) (sess *Session, sealS2C, sealC2S func(from, to int) [][]byte) {
	t.Helper()
	curve := ecdh.X25519()
	sPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverPub := sPriv.PublicKey().Bytes()
	clientPriv := cPriv.Bytes()
	shared, err := cs2crypto.SharedSecret(clientPriv, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	// 两个方向用**不同**的 KDF info，等价于真实链路的 RecvKey / SendKey 两把密钥。
	schS2C, err := cs2crypto.SchemeByName("hkdf-sha256/info-empty", "aes-256-gcm", "ctr-le-u64",
		2, false, shared, serverPub)
	if err != nil {
		t.Fatal(err)
	}
	schC2S, err := cs2crypto.SchemeByName("hkdf-sha256/info-cs2", "aes-256-gcm", "ctr-le-u64",
		2, false, shared, serverPub)
	if err != nil {
		t.Fatal(err)
	}

	// 两个方向各一个 builder：SNP 的流位置按方向独立累加。
	bS2C, bC2S := newSNPBuilder(), newSNPBuilder()

	mk := func(sch *cs2crypto.Scheme, b *snpBuilder, payload func(int) [][]byte) func(int, int) [][]byte {
		return func(from, to int) [][]byte {
			out := make([][]byte, 0, to-from)
			for i := from; i < to; i++ {
				f, err := sch.SealFrame(i, []byte{0xAA, 0xBB}, b.wrap(payload(i)))
				if err != nil {
					t.Fatal(err)
				}
				out = append(out, f)
			}
			return out
		}
	}

	sealS2C = mk(schS2C, bS2C, func(i int) [][]byte { return streamAt(i, 3) })
	// c2s 的载荷带一个独特标记，用来断言它没有污染 netchan。
	sealC2S = mk(schC2S, bC2S, func(i int) [][]byte {
		p := append([]byte{}, c2sMarker...)
		p = append(p, uvarint(uint64(i))...)
		return [][]byte{p}
	})

	sess = &Session{
		id:         "dual",
		clientPriv: clientPriv,
		serverPub:  serverPub,
		schemeS2C:  schS2C,
		schemeC2S:  schC2S,
		decoder:    cs2proto.NewHeuristicDecoderWithTTL(64, time.Minute),
	}
	return sess, sealS2C, sealC2S
}

// c2sMarker 是 c2s 载荷里的独特前缀。netchan 只收 s2c，所以它不该出现在里面。
var c2sMarker = []byte("C2S-ONLY-MARKER")

// TestDecodeRunsBothDirections 断言 decode() 对两个方向都推进了游标与消息计数。
func TestDecodeRunsBothDirections(t *testing.T) {
	sess, sealS2C, sealC2S := dualScheme(t)
	const n = 40
	sess.s2c = sealS2C(0, n)
	sess.c2s = sealC2S(0, n)

	sess.decode()

	if sess.stS2C.fedFrames != n {
		t.Fatalf("s2c 游标应推进到 %d，实际 %d（s2c 根本没被解）", n, sess.stS2C.fedFrames)
	}
	if sess.stC2S.fedFrames != n {
		t.Fatalf("c2s 游标应推进到 %d，实际 %d", n, sess.stC2S.fedFrames)
	}
	if sess.stS2C.msgs == 0 {
		t.Fatal("s2c 没有切出任何可靠消息")
	}
	if sess.stC2S.msgs == 0 {
		t.Fatal("c2s 没有切出任何可靠消息")
	}
	if sess.stS2C.bad != 0 || sess.stC2S.bad != 0 {
		t.Fatalf("不应有坏帧：s2c=%d(0x%02x) c2s=%d(0x%02x)",
			sess.stS2C.bad, sess.stS2C.badType, sess.stC2S.bad, sess.stC2S.badType)
	}
}

// TestDirectionSwitchKeepsStream 是核心回归：两个方向**交错**喂帧时，
// 可靠流不得被清空，netchan 必须持续增长。
//
// 旧实现里 decode() 每次方向切换都 `relStream.Reset() / netchan = nil`，
// 于是现场 `netchan` 永远停在开头那 332 字节、`已切=0` 一动不动。
func TestDirectionSwitchKeepsStream(t *testing.T) {
	sess, sealS2C, sealC2S := dualScheme(t)
	const n = 40

	prev := 0
	for i := 0; i < n; i++ {
		// 严格交错：一帧 s2c、一帧 c2s，然后 decode 一次。
		sess.s2c = append(sess.s2c, sealS2C(i, i+1)[0])
		sess.c2s = append(sess.c2s, sealC2S(i, i+1)[0])
		sess.decode()

		if len(sess.netchan) < prev {
			t.Fatalf("第 %d 帧后 netchan 缩水：%d → %d（方向切换把流清空了）",
				i, prev, len(sess.netchan))
		}
		prev = len(sess.netchan)
	}

	if len(sess.netchan) == 0 {
		t.Fatal("交错喂帧后 netchan 仍为 0 —— 可靠流被反复重置")
	}
	// 每帧 3 条消息、每帧都被收进来，netchan 至少要超过单帧的量。
	if len(sess.netchan) < 300 {
		t.Fatalf("netchan 只有 %d 字节，明显没攒起来", len(sess.netchan))
	}
	if bytes.Contains(sess.netchan, c2sMarker) {
		t.Fatal("c2s 的载荷混进了 netchan —— netchan 必须只收 s2c")
	}
}

// TestNetchanOnlyFromS2C 断言 c2s 单独喂进来时 netchan 不增长。
func TestNetchanOnlyFromS2C(t *testing.T) {
	sess, _, sealC2S := dualScheme(t)
	sess.c2s = sealC2S(0, 20)

	sess.decode()

	if sess.stC2S.msgs == 0 {
		t.Fatal("c2s 应切出可靠消息")
	}
	if len(sess.netchan) != 0 {
		t.Fatalf("只喂 c2s 时 netchan 应为空，实际 %d 字节", len(sess.netchan))
	}
}

// TestSchemePerDirection 覆盖方案访问器的方向隔离。
func TestSchemePerDirection(t *testing.T) {
	sess, _, _ := dualScheme(t)

	if sess.schemeFor("s2c") == nil || sess.schemeFor("c2s") == nil {
		t.Fatal("两个方向都应装有方案")
	}
	if sess.schemeFor("s2c") == sess.schemeFor("c2s") {
		t.Fatal("两个方向不能共用同一份方案")
	}
	if sch, dir := sess.primaryScheme(); sch == nil || dir != "s2c" {
		t.Fatalf("primaryScheme 应优先返回 s2c，实际 dir=%q", dir)
	}
	if sess.anyScheme() == nil {
		t.Fatal("anyScheme 不应为空")
	}

	// 只装 c2s 时 primaryScheme 应回落到 c2s。
	only := &Session{id: "only-c2s", schemeC2S: sess.schemeFor("c2s")}
	if sch, dir := only.primaryScheme(); sch == nil || dir != "c2s" {
		t.Fatalf("只有 c2s 时 primaryScheme 应返回 c2s，实际 dir=%q", dir)
	}
	// 空会话两个都为空。
	empty := &Session{id: "empty"}
	if sch, dir := empty.primaryScheme(); sch != nil || dir != "" {
		t.Fatal("空会话 primaryScheme 应返回 nil/空")
	}
	if empty.anyScheme() != nil {
		t.Fatal("空会话 anyScheme 应为 nil")
	}
}
