// Command udpprobe 用于端到端验证 capturefilter：
// 打开两个 UDP socket（一个 bind 到随机端口，一个 connect 到远端），
// 周期性地向远端发包，并打印自己的 PID 与端口，然后保持存活到 -duration。
//
// 用法（配合 capture.exe -pid <PID> 观察 capture_filter 事件）：
//
//	udpprobe.exe -duration 20s -peer 8.8.8.8:53
//
// 它只用来做验证，不参与正式分发。
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	dur := flag.Duration("duration", 20*time.Second, "存活时长")
	peer := flag.String("peer", "8.8.8.8:53", "发包目标（用于产生真实出向流量）")
	flag.Parse()

	raddr, err := net.ResolveUDPAddr("udp4", *peer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "resolve peer: %v\n", err)
		os.Exit(1)
	}

	// socket 1：bind 到随机端口，不 connect
	c1, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		fmt.Fprintf(os.Stderr, "listen udp: %v\n", err)
		os.Exit(1)
	}
	defer c1.Close()
	p1 := c1.LocalAddr().(*net.UDPAddr).Port

	// socket 2：connect 到远端
	c2, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial udp: %v\n", err)
		os.Exit(1)
	}
	defer c2.Close()
	p2 := c2.LocalAddr().(*net.UDPAddr).Port

	fmt.Printf("PID=%d PORT1=%d PORT2=%d PEER=%s\n", os.Getpid(), p1, p2, raddr)
	os.Stdout.Sync()

	payload := make([]byte, 64)
	binary.BigEndian.PutUint32(payload, 0xdeadbeef)

	deadline := time.Now().Add(*dur)
	tick := time.NewTicker(200 * time.Millisecond)
	defer tick.Stop()
	sent := 0
	for time.Now().Before(deadline) {
		<-tick.C
		if _, err := c2.Write(payload); err == nil {
			sent++
		}
		if _, err := c1.WriteToUDP(payload, raddr); err == nil {
			sent++
		}
	}
	fmt.Printf("SENT=%d\n", sent)
}
