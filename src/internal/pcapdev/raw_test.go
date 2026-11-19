package pcapdev

import (
	"net"
	"testing"
	"time"

	"local/cs2-radar/internal/transport"
)

// TestRawBackendKeepsIPHeader 锁死 raw 后端返回的包带完整 IPv4 头。
//
// 背景（真实踩过的坑）：Go 的 (*net.IPConn).ReadFrom 内部会调用
// stripIPv4Header（net/iprawsock_posix.go，构建标签含 windows）把 IPv4 头剥掉；
// 而调用方紧接着用 transport.ParseIPv4UDP 解析，要求首字节是 0x4X。
// 早先用 ReadFrom，结果每一包都被 ParseIPv4UDP 丢弃、raw 后端静默失效。
//
// 现在走 WSARecvFrom 直接拿原始帧，本测试确认真实流量下首字节仍是 0x4X。
// 无管理员权限时自动跳过（SIO_RCVALL 需要管理员）。
func TestRawBackendKeepsIPHeader(t *testing.T) {
	if err := RawAvailable(); err != nil {
		t.Skipf("raw socket 不可用（通常是没有管理员权限）: %v", err)
	}

	h, err := Open()
	if err != nil {
		t.Fatalf("Open() 失败: %v", err)
	}
	defer h.Close()

	// 制造本机 UDP 流量：发往 127.0.0.1:9999
	go func() {
		dst, err := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
		if err != nil {
			return
		}
		c, err := net.DialUDP("udp", nil, dst)
		if err != nil {
			return
		}
		defer c.Close()
		for i := 0; i < 80; i++ {
			c.Write([]byte("RAWPROBE-0123456789abcdef"))
			time.Sleep(50 * time.Millisecond)
		}
	}()

	seen := 0
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := h.Next()
		if err != nil {
			continue
		}
		if len(raw) == 0 {
			continue
		}
		if raw[0]>>4 != 4 {
			t.Fatalf("raw 后端返回的包没有 IPv4 头：首字节 0x%02x。"+
				"说明读取路径把 IP 头剥掉了。", raw[0])
		}
		if _, err := transport.ParseIPv4UDP(raw); err != nil {
			t.Fatalf("带 IPv4 头却解析失败: %v", err)
		}
		seen++
		if seen >= 1 {
			return // 通过
		}
	}
	t.Skip("10 秒内未捕获到任何本机 UDP 流量，跳过（环境无网络活动）")
}

// TestRawBackendSeesSendDirection 锁死「raw 后端必须能抓到发送方向」。
//
// 背景（真实踩过的坑）：客户端握手包是**客户端发出去**的（发送方向）。
// 早期 raw 后端用 net.ListenPacket("ip4:udp","0.0.0.0")，只能收「发往本机」
// 的包 —— 实测 3 秒只收到 15 个包、发送方向 0 个。握手永远拿不到，
// 密钥搜索不启动，雷达页一直空（用户看到的现象就是「没有效果」）。
//
// 现在只保留 SIO_RCVALL（实测发送方向 702 个）。本测试向公网发 UDP，
// 确认 Next() 能返回「源 = 本机」的包。
func TestRawBackendSeesSendDirection(t *testing.T) {
	if err := RawAvailable(); err != nil {
		t.Skipf("raw socket 不可用（通常是没有管理员权限）: %v", err)
	}
	h, err := Open()
	if err != nil {
		t.Fatalf("Open() 失败: %v", err)
	}
	defer h.Close()
	if h.RawCaptureMode() != ModeName {
		t.Fatalf("抓包模式应为 %q，实际 %q", ModeName, h.RawCaptureMode())
	}

	local := outboundLocalIP()
	if local == "" {
		t.Skip("无法确定出站网卡地址")
	}

	go func() {
		for i := 0; i < 12; i++ {
			for _, s := range []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"} {
				ra, err := net.ResolveUDPAddr("udp4", s)
				if err != nil {
					continue
				}
				c, err := net.DialUDP("udp4", nil, ra)
				if err != nil {
					continue
				}
				c.Write([]byte{0xab, 0xcd, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				c.Close()
			}
			time.Sleep(120 * time.Millisecond)
		}
	}()

	seen := 0
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := h.Next()
		if err != nil {
			continue
		}
		if len(raw) < 20 || raw[0]>>4 != 4 {
			continue
		}
		seen++
		src := net.IPv4(raw[12], raw[13], raw[14], raw[15]).String()
		if src == local {
			return // 通过：看到了发送方向
		}
	}
	if seen == 0 {
		t.Skip("8 秒内一个包都没收到，环境无网络活动，跳过")
	}
	t.Fatalf("收到 %d 个包但没一个是「源=本机」：SIO_RCVALL 没生效", seen)
}

// TestDevicesNeverPanics 保证 -list-devices 不 panic（无网卡时返回空列表即可）。
func TestDevicesNeverPanics(t *testing.T) {
	devs := Devices()
	t.Logf("本机可抓包 IPv4 地址 %d 个: %v", len(devs), devs)
}

// outboundLocalIP 返回去往公网时的源地址（= 出站网卡地址）。
func outboundLocalIP() string {
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
					return v4.String()
				}
			}
		}
		return ""
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.String()
	}
	return ""
}
