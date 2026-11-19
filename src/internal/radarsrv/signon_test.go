package radarsrv

import "testing"

// TestSignonDumpCoversObservedSignon 钉住「阈值必须盖住现场实测的 signon 段」。
//
// 08:12 那局第一条 [snp] 统计时 s2c 已出 146427 字节，那就是 signon 的实际长度。
// 阈值一旦被改小到 146428 以下，GameEventList 就会被截断丢掉 ——
// 而截断后的表现和"没抓到"完全一样，又要花几轮去查。
func TestSignonDumpCoversObservedSignon(t *testing.T) {
	const observedSignonBytes = 146428 // 08:12 那局 s2c 已出字节数
	if signonDumpBytes < observedSignonBytes {
		t.Fatalf("signonDumpBytes = %d，小于现场实测的 signon 段 %d 字节",
			signonDumpBytes, observedSignonBytes)
	}
}

// TestNoteSignonStreamAccumulates 保证按到达顺序累积、够阈值才落盘。
func TestNoteSignonStreamAccumulates(t *testing.T) {
	sess := &Session{}
	sess.noteSignonStream([]byte("abc"))
	sess.noteSignonStream([]byte("defg"))
	if got := string(sess.signonDump); got != "abcdefg" {
		t.Fatalf("累积结果 = %q，期望 %q", got, "abcdefg")
	}
	if sess.signonDone {
		t.Fatal("没到阈值就标了 signonDone，后面的字节会被丢掉")
	}
}

// TestNoteSignonStreamStopsAfterDone 保证落盘之后不再吃内存。
//
// signon 只有连接起点那一段；落盘后再往里追加，长时间挂机会把内存吃满。
func TestNoteSignonStreamStopsAfterDone(t *testing.T) {
	sess := &Session{signonDone: true}
	sess.noteSignonStream([]byte("xyz"))
	if len(sess.signonDump) != 0 {
		t.Fatalf("signonDone 之后仍在累积：%d 字节", len(sess.signonDump))
	}
}
