package cs2crypto

// TryOpen 只做一件事：用一把候选密钥试解一帧，认证通过返回 true。
//
// 这是「全内存暴力找会话密钥」的内层函数，必须尽量轻：
// 每调一次就做一遍 AES 密钥展开 + 一次 GCM 认证，实测约 280 ns。
// 因此这里刻意不做任何额外判断 —— 打分、多帧复核都放到外层，
// 只有认证通过（概率约 2^-128）才值得多花时间。
func TryOpen(key, nonce, ct, aad []byte) bool {
	g, err := newGCM(key)
	if err != nil {
		return false
	}
	_, err = g.Open(nil, nonce, ct, aad)
	return err == nil
}

// TryDecrypt 与 TryOpen 相同，但返回解出来的明文（失败返回 nil）。
// 只在 TryOpen 已经通过、需要复核时才调用 —— 它比 TryOpen 多一次分配。
func TryDecrypt(key, nonce, ct, aad []byte) []byte {
	g, err := newGCM(key)
	if err != nil {
		return nil
	}
	pt, err := g.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil
	}
	return pt
}

// SealWith 用给定密钥/nonce/AAD 加密一段明文（只给单测造靶标用）。
func SealWith(key, nonce, pt, aad []byte) []byte {
	g, err := newGCM(key)
	if err != nil {
		return nil
	}
	return g.Seal(nil, nonce, pt, aad)
}
