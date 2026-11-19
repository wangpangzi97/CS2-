// rawtest 用于验证 pcapdev 的 raw socket 后端到底能不能收到完整 IPv4 包。
//
// 背景：Go 的 (*net.IPConn).ReadFrom 会调用 stripIPv4Header 把 IP 头剥掉，
// 而采集器后续用 transport.ParseIPv4UDP 解析，要求 IP 头存在。
// 本程序对比 ReadFrom 与 ReadMsgIP 两条读取路径的实际返回内容。
//
// 运行：rawtest.exe            （需要管理员）
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	// 同时开两个 raw socket，分别用 ReadFrom / ReadMsgIP 读同一批包。
	c1, err := net.ListenPacket("ip4:udp", "0.0.0.0")
	if err != nil {
		fmt.Println("ReadFrom  路径 open 失败:", err)
		os.Exit(1)
	}
	defer c1.Close()

	c2, err := net.ListenPacket("ip4:udp", "0.0.0.0")
	if err != nil {
		fmt.Println("ReadMsgIP 路径 open 失败:", err)
		os.Exit(1)
	}
	defer c2.Close()

	fmt.Println("raw socket 打开成功（管理员权限 OK）")

	// 后台持续往 127.0.0.1:9999 与外部 DNS 端口发 UDP，制造可捕获的流量。
	go func() {
		dst, _ := net.ResolveUDPAddr("udp", "127.0.0.1:9999")
		conn, err := net.DialUDP("udp", nil, dst)
		if err != nil {
			fmt.Println("dial udp 失败:", err)
			return
		}
		defer conn.Close()
		for i := 0; i < 40; i++ {
			conn.Write([]byte("RAWPROBE-0123456789abcdef"))
			time.Sleep(100 * time.Millisecond)
		}
	}()

	type res struct {
		who string
		n   int
		b   []byte
		err error
	}
	ch := make(chan res, 2)

	// 路径 A：ReadFrom（Go 会剥 IP 头）
	go func() {
		buf := make([]byte, 65536)
		for i := 0; i < 60; i++ {
			c1.SetReadDeadline(time.Now().Add(6 * time.Second))
			n, _, err := c1.ReadFrom(buf)
			if err != nil {
				ch <- res{"ReadFrom", 0, nil, err}
				return
			}
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				ch <- res{"ReadFrom", n, cp, nil}
				return
			}
		}
		ch <- res{"ReadFrom", 0, nil, fmt.Errorf("超时未收到包")}
	}()

	// 路径 B：ReadMsgIP（Go 不剥 IP 头）
	go func() {
		ipc, ok := c2.(*net.IPConn)
		if !ok {
			ch <- res{"ReadMsgIP", 0, nil, fmt.Errorf("不是 *net.IPConn")}
			return
		}
		buf := make([]byte, 65536)
		for i := 0; i < 60; i++ {
			ipc.SetReadDeadline(time.Now().Add(6 * time.Second))
			n, _, _, _, err := ipc.ReadMsgIP(buf, nil)
			if err != nil {
				ch <- res{"ReadMsgIP", 0, nil, err}
				return
			}
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				ch <- res{"ReadMsgIP", n, cp, nil}
				return
			}
		}
		ch <- res{"ReadMsgIP", 0, nil, fmt.Errorf("超时未收到包")}
	}()

	got := 0
	deadline := time.After(20 * time.Second)
	for got < 2 {
		select {
		case r := <-ch:
			got++
			fmt.Printf("\n=== %s ===\n", r.who)
			if r.err != nil {
				fmt.Println("  错误:", r.err)
				continue
			}
			fmt.Printf("  长度: %d\n", r.n)
			show := r.b
			if len(show) > 48 {
				show = show[:48]
			}
			fmt.Printf("  前 48 字节: %s\n", hex.EncodeToString(show))
			v := r.b[0] >> 4
			fmt.Printf("  首字节 0x%02x → IP 版本字段 = %d  ", r.b[0], v)
			if v == 4 {
				fmt.Println("→ **带 IPv4 头**（ParseIPv4UDP 可用）")
			} else {
				fmt.Println("→ **无 IPv4 头**（ParseIPv4UDP 会丢弃此包）")
			}
		case <-deadline:
			fmt.Println("\n总超时，结束")
			got = 2
		}
	}
}
