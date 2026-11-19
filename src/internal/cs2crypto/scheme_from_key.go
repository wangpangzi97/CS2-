package cs2crypto

import "errors"

// SchemeFromKey 用一把**现成的对称密钥**构造方案（跳过 KDF）。
//
// 用途：共享密钥 → 会话密钥的 KDF 是未知的（info/salt 串不在 v2.0.5 的两个
// EXE 里）。但 AES-GCM 的认证标签本身就是"这把密钥对不对"的**完美判据** ——
// 错一个字节就一定失败。所以不必知道密钥是怎么推出来的，直接在目标进程
// 内存里找那把能解开真实密文的密钥即可。
//
// 找到之后用它构造 Scheme，后续 decode() 走的就是正常路径。
func SchemeFromKey(key []byte, cand Candidate) (*Scheme, error) {
	var cp Cipher
	okCipher := false
	for _, c := range Ciphers() {
		if c.Name == cand.Cipher {
			cp, okCipher = c, true
			break
		}
	}
	if !okCipher {
		return nil, errors.New("unknown cipher: " + cand.Cipher)
	}
	if len(key) != cp.KeyLen {
		return nil, errors.New("key length mismatch")
	}

	var ns NonceScheme
	okNonce := false
	for _, n := range NonceSchemes() {
		if n.Name == cand.Nonce {
			ns, okNonce = n, true
			break
		}
	}
	if !okNonce {
		return nil, errors.New("unknown nonce scheme: " + cand.Nonce)
	}

	dup := make([]byte, len(key))
	copy(dup, key)
	return &Scheme{Candidate: cand, cipher: cp, nonce: ns, key: dup}, nil
}

// SchemeFromGNS 用 SteamNetworkingSockets 握手派生出的密钥 + 基础 IV 构造方案。
//
// 这是**确定解**：KDF、AEAD、nonce、AAD、密文起点全部来自 GNS 源码 + 真实抓包核对，
// 不再走 Probe 的候选枚举。只要 clientPriv 和双向握手材料齐全，就一定解得出。
func SchemeFromGNS(key, iv []byte) (*Scheme, error) {
	if len(iv) != 12 {
		return nil, errors.New("GNS 基础 IV 必须是 12 字节")
	}
	aead, err := gnsAEAD(key)
	if err != nil {
		return nil, err
	}
	return &Scheme{
		Candidate: Candidate{
			KDF:    "gns-hkdf-sha256",
			Cipher: "aes-256-gcm",
			Nonce:  "gns-iv-add-seq",
			Offset: -1, // 由帧标志字节动态决定
			GNSIV:  append([]byte(nil), iv...),
		},
		key: append([]byte(nil), key...),
		gns: aead,
	}, nil
}
