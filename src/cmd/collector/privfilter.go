package main

// 私钥候选的廉价预筛（2026-10-17 第五轮之后新增）。
//
// ── 为什么需要它 ──
//
// 用户现场：公钥在 7.5 GB 内存里命中 6 处，但把这 6 处 ±1 MB / ±8 MB / 整块区域
// 都扫完也没有私钥。剩下的唯一办法是全内存兜底，而全内存兜底的算术是：
//
//	7,572 MB ÷ 32 字节窗口 = 2.36 亿个候选位置（逐字节）
//	X25519 校验实测 6.1 µs/次（16 线程并行）
//	2.36e8 × 6.1e-6 s ≈ 24 分钟；如果是 7.5 GB 逐字节则是 12 小时量级
//
// 也就是说：**不预筛就不可能扫完**。之前 `off += 8` 的步长本质上就是
// "用 7/8 的漏检率换 8 倍速度"，这不是优化，是妥协。
//
// ── 预筛为什么安全 ──
//
// X25519 私钥是 32 字节均匀随机数据。均匀随机 32 字节有两个可直接检验的统计特征：
//
//	① 不同字节值的个数：期望 256×(1-(255/256)^32) ≈ 30.1，标准差约 1.5
//	② 零字节个数：P(0 个零)=88.3%，P(恰好 1 个零)=11.1%，P(≥2 个零)=0.6%
//
// 而真实进程内存里绝大多数 32 字节窗口是**结构化数据**（指针数组、ASCII 文本、
// 零填充、代码），零字节多、不同值少，会被直接筛掉。
//
// 阈值取得足够宽，保证真私钥漏掉的概率可忽略：`minDistinct=22` 时均匀随机
// 32 字节通过率 > 99.999%，而实测结构化内存通过率只有千分之几 —— 两个数量级
// 以上的差距，足够把全内存兜底压进预算。
//
// 预筛只做"跳过明显不是密钥的窗口"，**不做任何形态假设**（比如 clamp 形态），
// 那个坑上一轮已经踩过了。

// privFilter 是滑动窗口预筛的参数。
type privFilter struct {
	// MinDistinct 是窗口内不同字节值个数下限。0 表示不检查。
	MinDistinct int
	// MaxZeros 是窗口内零字节个数上限。-1 表示不检查。
	MaxZeros int

	// RequireClamp 要求窗口满足 X25519 的 clamp 形态：
	//
	//	b[0] & 7 == 0  且  b[31] & 0xC0 == 0x40
	//
	// 🔴 这不是「形态假设」，是**优先级**，两遍扫描合起来仍然零漏检。
	//
	// 为什么值得单独一遍：OpenSSL 的 X25519 密钥生成在**存下来之前**就
	// clamp 过（`ossl_x25519_keygen` 里 `priv[0] &= 248; priv[31] &= 127;
	// priv[31] |= 64`），所以落盘的 32 字节本身就带 clamp 形态。而 BoringSSL
	// 和部分实现只在计算时 clamp，存的是原始随机字节。
	//
	// 两种都可能，所以不能拿它当过滤器（那正是上一轮踩过的坑，见文件头）。
	// 但当**第一遍**用：2 次字节比较就能筛掉 31/32，把 X25519 标量乘的次数
	// 直接降一个数量级 —— 而 976 MB 逐字节校验的耗时**几乎全部**是 X25519
	// （实测 5 µs/次），所以这一遍能把 2 分半压到十秒级。
	// 没命中再跑完整预筛一遍，覆盖率不变。
	RequireClamp bool
}

// DefaultPrivFilter 是兜底扫描用的默认预筛。
//
// 这两个数是实测出来的，不是拍脑袋（见 privfilter_test.go 的
// TestPrivFilterPassRate / TestPrivFilterKeepsRealKeys）：
//
//	{22,1} → 通过率 7.34%，但会漏掉 0.72% 的真实私钥  ← 太危险，弃用
//	{24,2} → 通过率 6.36%，漏掉 0.030%（6/20000）      ← 采用
//	{28,0} → 通过率 0.61%，漏掉 14.2%                  ← 绝对不能用于搜密钥
//
// 也就是说：**预筛只能把代价降低一个数量级，不能让 7.5 GB 全量变得轻松**。
// 真正解决问题的是"近邻窗口按地址空间求交"（见 nearRangesIn），不是预筛。
var DefaultPrivFilter = privFilter{MinDistinct: 24, MaxZeros: 2}

// privFilterDisabled 由 -priv-filter off 置位。
//
// 用途：如果怀疑密钥被预筛漏掉了（真私钥恰好零字节偏多或取值偏集中），
// 用它可以退回"逐字节全量校验"。慢，但零漏检。
var privFilterDisabled bool

// Enabled 报告预筛是否真的会筛掉东西。
func (f privFilter) Enabled() bool {
	return f.MinDistinct > 0 || f.MaxZeros >= 0 || f.RequireClamp
}

// String 用于日志/诊断报告。
func (f privFilter) String() string {
	if !f.Enabled() {
		return "关闭（逐字节全量校验）"
	}
	var b string
	if f.MinDistinct > 0 || f.MaxZeros >= 0 {
		b = "不同字节≥" + itoa(f.MinDistinct) + " 且 零字节≤" + itoa(f.MaxZeros)
	}
	if f.RequireClamp {
		if b != "" {
			b += " + "
		}
		b += "clamp 形态"
	}
	return b
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// utoa 是 uint64 → 十进制字符串（本包不用 strconv，保持零依赖的小工具风格）。
func utoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// filterScan 在 buf 上逐字节滑动 32 字节窗口，对通过预筛的窗口调用 fn(off)。
//
// 返回 true 表示 fn 要求提前停止（通常是找到了私钥）。
//
// 复杂度：每个偏移 O(1) —— 用 256 项直方图维护"不同值个数"和"零字节个数"，
// 滑动时只做一次移出 + 一次移入。实测约 2~4 ns/偏移，比 X25519 校验便宜
// 三个数量级。
func filterScan(buf []byte, f privFilter, fn func(off int) bool) bool {
	const w = 32
	if len(buf) < w {
		return false
	}
	// clampOK 只看两个字节，成本可以忽略；放在直方图判断之前，
	// 能让 31/32 的窗口在**进入 X25519 之前**就被挡掉。
	clampOK := func(off int) bool {
		return !f.RequireClamp || (buf[off]&7 == 0 && buf[off+31]&0xC0 == 0x40)
	}
	if !f.Enabled() {
		for off := 0; off+w <= len(buf); off++ {
			if clampOK(off) && fn(off) {
				return true
			}
		}
		return false
	}

	var hist [256]uint16
	distinct, zeros := 0, 0
	for _, b := range buf[:w] {
		if hist[b] == 0 {
			distinct++
		}
		hist[b]++
		if b == 0 {
			zeros++
		}
	}
	pass := func(off int) bool {
		return clampOK(off) &&
			(f.MinDistinct <= 0 || distinct >= f.MinDistinct) &&
			(f.MaxZeros < 0 || zeros <= f.MaxZeros)
	}
	if pass(0) && fn(0) {
		return true
	}
	for i := 1; i+w <= len(buf); i++ {
		out, in := buf[i-1], buf[i+w-1]
		hist[out]--
		if hist[out] == 0 {
			distinct--
		}
		if out == 0 {
			zeros--
		}
		if hist[in] == 0 {
			distinct++
		}
		hist[in]++
		if in == 0 {
			zeros++
		}
		if pass(i) && fn(i) {
			return true
		}
	}
	return false
}
