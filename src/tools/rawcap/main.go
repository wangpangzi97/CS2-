// rawcap 验证 pcapdev 的 raw 后端修复后能否真正抓到并解析 UDP 包。
//
// 这是 tools/rawtest 的端到端版本：不再只看首字节，而是走完整链路
//
//	pcapdev.Open() -> Handle.Next() -> transport.ParseIPv4UDP
//
// 统计「收到多少包 / 成功解析多少包」。
//
// 现在走 SIO_RCVALL + WSARecvFrom，保留完整 IPv4 头 → 解析数 > 0。
//
// 运行：rawcap.exe   （需要管理员）
package main

import (
	"fmt"
	"net"
	"os"
	"time"

	"local/cs2-radar/internal/pcapdev"
	"local/cs2-radar/internal/transport"
)

func main() {
	h, err := pcapdev.Open()
	if err != nil {
		fmt.Println("打开 raw 后端失败:", err)
		os.Exit(1)
	}
	defer h.Close()
	fmt.Println("抓包已打开，模式 =", h.RawCaptureMode())

	// 制造流量：往本机 9999 端口 + 外部 DNS 端口发 UDP
	stop := make(chan struct{})
	go func() {
		d1, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
		c1, err := net.DialUDP("udp", nil, d1)
		if err != nil {
			fmt.Println("dial 失败:", err)
			return
		}
		defer c1.Close()
		d2, _ := net.ResolveUDPAddr("udp", "8.8.8.8:53")
		c2, _ := net.DialUDP("udp", nil, d2)
		if c2 != nil {
			defer c2.Close()
		}
		for i := 0; i < 200; i++ {
			select {
			case <-stop:
				return
			default:
			}
			c1.Write([]byte("RAWPROBE-0123456789abcdef"))
			if c2 != nil {
				// 一个极简 DNS 查询，触发外部 UDP
				q := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
				q = append(q, 3, 'w', 'w', 'w', 6, 'g', 'o', 'o', 'g', 'l', 'e', 3, 'c', 'o', 'm', 0)
				q = append(q, 0, 1, 0, 1)
				c2.Write(q)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()

	var seen, parsed, ipHdrOK int
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := h.Next()
		if err != nil {
			fmt.Println("Next 错误:", err)
			break
		}
		if raw == nil {
			continue
		}
		seen++
		if len(raw) > 0 && raw[0]>>4 == 4 {
			ipHdrOK++
		}
		u, err := transport.ParseIPv4UDP(raw)
		if err != nil {
			continue
		}
		parsed++
		if parsed <= 3 {
			fmt.Printf("  解析成功 #%d: %s:%d -> %s:%d  payload=%d 字节\n",
				parsed, net.IP(u.SrcIP[:]), u.SrcPort, net.IP(u.DstIP[:]), u.DstPort, len(u.Data))
		}
	}
	close(stop)

	fmt.Println()
	fmt.Printf("收到包数        : %d\n", seen)
	fmt.Printf("带 IPv4 头      : %d\n", ipHdrOK)
	fmt.Printf("ParseIPv4UDP 成功: %d\n", parsed)
	fmt.Println()
	if parsed > 0 {
		fmt.Println("结论：原始套接字抓包可用（免驱动、无 Npcap）。")
	} else {
		fmt.Println("结论：未能解析任何包 —— 检查管理员权限或环境限制。")
		os.Exit(1)
	}
}
