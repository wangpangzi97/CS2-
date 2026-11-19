package radarsrv

import "testing"

// TestGNSGameEventID 用现场真实载荷锁死 eventid 提取。
//
// 两条样本都来自 2026-10-20 07:56 那局的全量明文（gns-plainbin）：
//   - eventid=226 是完美平台注入的 HTML（占 cmd=207 的 94.4%）；
//   - eventid=160 是真实游戏事件（key 里带 weapon_ak47）。
//
// 如果这个函数取错，平台 HTML 会被当成游戏事件继续喂进解码器，
// 而真正的游戏事件反而可能被跳过 —— 两种错都不会报错，只会让日志变哑。
func TestGNSGameEventID(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want uint32
		ok   bool
	}{
		{
			name: "平台 HTML 注入（eventid 226）",
			hex:  "10e2011aa802080112a3023c666f6e7420636c6173733d27666f6e7453697a652d73273e",
			want: 226,
			ok:   true,
		},
		{
			name: "真实游戏事件（eventid 160，带 weapon_ak47）",
			hex:  "10a0011a040809281c1a0d0808209885f2d9fbffffffff011a0f0801120b776561706f6e5f616b34371a0408063800209ccc06",
			want: 160,
			ok:   true,
		},
		{
			name: "真实游戏事件（eventid 267）",
			hex:  "108b021a04080928151a0d080820b082ecaffbffffffff011a05080320cc081a0708021d0000003f1a0408063801209ccc06",
			want: 267,
			ok:   true,
		},
		{name: "空载荷", hex: "", want: 0, ok: false},
		{name: "截断的 varint", hex: "10e2", want: 0, ok: false},
	}
	for _, c := range cases {
		var b []byte
		for i := 0; i+1 < len(c.hex); i += 2 {
			b = append(b, unhexByte(c.hex[i], c.hex[i+1]))
		}
		got, ok := gnsGameEventID(b)
		if ok != c.ok || (ok && got != c.want) {
			t.Errorf("%s: got (%d,%v) want (%d,%v)", c.name, got, ok, c.want, c.ok)
		}
	}
}

func unhexByte(hi, lo byte) byte {
	f := func(c byte) byte {
		switch {
		case c >= '0' && c <= '9':
			return c - '0'
		case c >= 'a' && c <= 'f':
			return c - 'a' + 10
		case c >= 'A' && c <= 'F':
			return c - 'A' + 10
		}
		return 0
	}
	return f(hi)<<4 | f(lo)
}
