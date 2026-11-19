package capturefilter

import (
	"net"
	"os"
	"testing"
)

// TestFilterEmptyPassesEverything 锁死兜底语义：
// 端口集合为空时不能过滤掉任何包 —— 宁可多收，不可漏收。
func TestFilterEmptyPassesEverything(t *testing.T) {
	f := New()
	if f.Active() {
		t.Fatal("新建的过滤器不应处于生效状态")
	}
	for _, tc := range [][2]uint16{{0, 0}, {53, 50000}, {27015, 1234}} {
		if !f.Match(tc[0], tc[1]) {
			t.Fatalf("过滤未生效时应全部放行，但 %v 被拦了", tc)
		}
	}
}

// TestFilterMatch 验证按端口过滤：源或目的命中即保留。
func TestFilterMatch(t *testing.T) {
	f := New()
	f.Set(1234, []uint16{50000, 50001})
	if !f.Active() {
		t.Fatal("设置端口后应生效")
	}
	if f.PID() != 1234 {
		t.Fatalf("PID 应为 1234，实际 %d", f.PID())
	}
	cases := []struct {
		src, dst uint16
		want     bool
	}{
		{50000, 27015, true}, // c2s：源端口是游戏本地端口
		{27015, 50000, true}, // s2c：目的端口是游戏本地端口
		{50001, 53, true},    // 另一条连接
		{53, 443, false},     // 无关流量
		{0, 0, false},        // 无关流量
	}
	for _, c := range cases {
		if got := f.Match(c.src, c.dst); got != c.want {
			t.Errorf("Match(%d,%d) = %v，期望 %v", c.src, c.dst, got, c.want)
		}
	}
	f.Clear()
	if f.Active() {
		t.Fatal("Clear 后应回到未生效")
	}
	if !f.Match(53, 443) {
		t.Fatal("Clear 后应放行全部")
	}
}

// TestDiscoverFindsOwnUDPPort 端到端验证 GetExtendedUdpTable：
// 本进程开一个 UDP socket，Discover 必须能把它找出来。
//
// 这条同时验证了"端口字节序转换"是对的（ntohs），否则端口会是个反向的大数。
func TestDiscoverFindsOwnUDPPort(t *testing.T) {
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Skipf("无法开 UDP socket: %v", err)
	}
	defer c.Close()
	want := uint16(c.LocalAddr().(*net.UDPAddr).Port)

	ports, err := Discover(uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("Discover 失败: %v", err)
	}
	for _, p := range ports {
		if p == want {
			t.Logf("发现本进程 UDP 端口 %d（共 %d 个）", want, len(ports))
			return
		}
	}
	t.Fatalf("Discover 没找到本进程的 UDP 端口 %d，返回的是 %v", want, ports)
}

// TestAddPortAdmitsNewConnection 锁死「握手端口即时入白名单」这条修复。
//
// 现场（2026-10-19 13:59）：CS2 的游戏连接是采集器启动**之后**才建立的。
// 白名单靠 3 秒周期重查 GetExtendedUdpTable，新端口在下一轮刷新之前不在集合里，
// 这期间该连接上的包全被丢掉 —— 实测丢了约 20 个 1137 字节的 signon 包
// （s2c 首个解出的可靠段声明位置 = 22809），sendtable 再也拿不到。
//
// 这个用例钉住两件事：
//  1. AddPort 之后，新端口的两个方向立刻放行（不等周期刷新）
//  2. AddPort 是幂等的，重复调用不改变集合
func TestAddPortAdmitsNewConnection(t *testing.T) {
	f := New()
	f.Set(1234, []uint16{50000})
	// 新连接的本机端口 55353 还没被发现，此刻必须被拦。
	if f.Match(55353, 17005) {
		t.Fatal("未入白名单的新端口不该放行 —— 否则这个用例测不到东西")
	}
	if f.Match(17005, 55353) {
		t.Fatal("未入白名单的新端口（s2c）不该放行")
	}

	if !f.AddPort(55353) {
		t.Fatal("AddPort 应报告「新增」")
	}
	if !f.Match(55353, 17005) {
		t.Fatal("握手端口入白名单后，c2s 方向必须立刻放行")
	}
	if !f.Match(17005, 55353) {
		t.Fatal("握手端口入白名单后，s2c 方向必须立刻放行")
	}
	// 旧端口不能被挤掉。
	if !f.Match(50000, 27015) {
		t.Fatal("AddPort 不该影响已有端口")
	}
	// 无关流量仍然要拦。
	if f.Match(53, 443) {
		t.Fatal("AddPort 之后无关流量仍应被拦")
	}

	if f.AddPort(55353) {
		t.Fatal("重复 AddPort 应返回 false（幂等）")
	}
	if f.AddPort(0) {
		t.Fatal("端口 0 不该被加进去")
	}
}

// TestAutoAdmitAdmitsGnsFlow 锁死「白名单漏端口时按 GNS 特征自动放行」。
//
// 现场依据（2026-10-19 22:35）：
//
//	[stats] 收 102181 包｜过滤丢弃 96598（其中像 GNS 的 75439）
//	[cap] ⚠ 白名单丢掉 N 个像 GNS 的包（51596→47960，1143 字节）
//
// 96% 的游戏流量被白名单当垃圾丢掉，而白名单只认 cs2.exe 自己的 UDP 端口
// （现场是 60898..60968）。真正的链路跑在平台中转/加速器持有的端口上，
// 于是整局 `可靠消息=34`、s2c 可靠流卡死在 149309。
func TestAutoAdmitAdmitsGnsFlow(t *testing.T) {
	f := New()
	f.Set(16900, []uint16{60898, 60899})
	if f.Match(51596, 47960) {
		t.Fatal("前置条件错：51596→47960 本来就不该命中白名单")
	}
	added := f.AutoAdmit(51596, 47960)
	if len(added) != 2 {
		t.Fatalf("应放行 2 个端口，实际 %v", added)
	}
	if !f.Match(51596, 47960) {
		t.Fatal("放行之后 Match 仍不通过 —— 这条流还是会被丢")
	}
	// 幂等：第二次不该再加。
	if got := f.AutoAdmit(51596, 47960); len(got) != 0 {
		t.Fatalf("重复放行应返回空，得到 %v", got)
	}
}

// TestAutoAdmitCapped 锁死「自动放行有上限，不能退化成全收」。
func TestAutoAdmitCapped(t *testing.T) {
	f := New()
	f.Set(1, []uint16{1000})
	for i := 0; i < 100; i++ {
		f.AutoAdmit(uint16(2000+i*2), uint16(2001+i*2))
	}
	got := len(f.Ports())
	if got > 1+autoAdmitMax {
		t.Fatalf("白名单涨到 %d 个端口，超过 1+%d 的上限", got, autoAdmitMax)
	}
}

// TestAutoAdmitInactiveFilterIsNoop 保证过滤没生效时不会凭空建白名单。
//
// 这条很重要：Discover 失败时白名单为空 = 全收，这是兜底路径。
// 如果 AutoAdmit 在这里也加端口，就会把「全收」变成「只收这两个端口」，
// 直接抓瞎。
func TestAutoAdmitInactiveFilterIsNoop(t *testing.T) {
	f := New()
	if got := f.AutoAdmit(51596, 47960); len(got) != 0 {
		t.Fatalf("过滤未生效时不该加端口，得到 %v", got)
	}
	if f.Active() {
		t.Fatal("过滤未生效时 Active() 应仍为 false")
	}
	if !f.Match(1234, 5678) {
		t.Fatal("过滤未生效时 Match 应恒为 true")
	}
}
