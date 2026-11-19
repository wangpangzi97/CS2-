// Command rawdir 实测：
//
//	A) 当前 raw 后端（ip4:udp / 0.0.0.0 + ReadMsgIP）能捕获哪些方向？
//	B) SIO_RCVALL（WSAIoctl，无需驱动）能捕获哪些方向？
//
// 判定：能否看到「本机→外网」的包。握手包是客户端发出的（发送方向），
// 如果两个后端都看不到发送方向，raw 就永远拿不到握手 → 雷达无解。
//
// 用法（必须管理员）：rawdir
package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	sioRCVALL  = 0x98000001
	rcvallON   = 1
	solSocket  = 0xffff
	soRcvTimeo = 0x1006
)

var ws2_32 = syscall.NewLazyDLL("ws2_32.dll")

func main() {
	outIP := outboundIPv4()
	if outIP == nil {
		fmt.Println("无法确定出站网卡地址")
		os.Exit(2)
	}
	fmt.Printf("出站源地址: %s\n", outIP)

	test("A) 当前 raw (ip4:udp/0.0.0.0 + ReadMsgIP)", openCurrentRaw, outIP)
	test("B) SIO_RCVALL", openRCVALL, outIP)
}

// reader 抽象：返回一个读包函数与关闭函数。
type reader interface {
	read(buf []byte) (int, error)
	close()
}

func test(name string, open func(net.IP) (reader, error), outIP net.IP) {
	fmt.Printf("\n===== %s =====\n", name)
	r, err := open(outIP)
	if err != nil {
		fmt.Printf("  打开失败: %v\n", err)
		return
	}
	defer r.close()

	stop := make(chan struct{})
	type pkt struct {
		src, dst, proto string
		n               int
		head            string
	}
	ch := make(chan pkt, 256)
	errCh := make(chan string, 64)
	go func() {
		buf := make([]byte, 65536)
		for {
			select {
			case <-stop:
				return
			default:
			}
			n, err := r.read(buf)
			if err != nil {
				select {
				case errCh <- err.Error():
				default:
				}
				continue
			}
			if n <= 0 {
				continue
			}
			p := pkt{n: n}
			if n >= 20 && buf[0]>>4 == 4 {
				ihl := int(buf[0]&0x0f) * 4
				p.src = net.IPv4(buf[12], buf[13], buf[14], buf[15]).String()
				p.dst = net.IPv4(buf[16], buf[17], buf[18], buf[19]).String()
				p.proto = fmt.Sprintf("proto=%d", buf[9])
				if buf[9] == 17 && n >= ihl+8 {
					sp := int(buf[ihl])<<8 | int(buf[ihl+1])
					dp := int(buf[ihl+2])<<8 | int(buf[ihl+3])
					p.proto = fmt.Sprintf("udp %d->%d", sp, dp)
				}
			} else {
				p.proto = "non-IPv4"
			}
			if n > 40 {
				p.head = hex.EncodeToString(buf[:24])
			} else {
				p.head = hex.EncodeToString(buf[:n])
			}
			select {
			case ch <- p:
			default:
			}
		}
	}()

	go sendQueries()

	deadline := time.After(3 * time.Second)
	total, sentDir, recvDir, other := 0, 0, 0, 0
	samples := []string{}
	errs := map[string]int{}
	for {
		select {
		case p := <-ch:
			total++
			if p.src == outIP.String() {
				sentDir++
			} else if p.dst == outIP.String() {
				recvDir++
			} else {
				other++
			}
			if len(samples) < 6 {
				samples = append(samples, fmt.Sprintf("%s -> %s  [%s]  %d B  %s", p.src, p.dst, p.proto, p.n, p.head))
			}
		case e := <-errCh:
			errs[e]++
		case <-deadline:
			close(stop)
			fmt.Printf("  总收包: %d\n", total)
			fmt.Printf("  发送方向(源=本机) %d  |  接收方向(目的=本机) %d  |  其它 %d\n", sentDir, recvDir, other)
			fmt.Println("  样本：")
			for _, s := range samples {
				fmt.Printf("    %s\n", s)
			}
			if len(errs) > 0 {
				fmt.Println("  读错误统计：")
				for e, c := range errs {
					fmt.Printf("    %-50s x%d\n", e, c)
				}
			}
			return
		}
	}
}

// sendQueries 反复向 8.8.8.8:53 / 1.1.1.1:53 发 DNS 查询，产生发送方向流量。
func sendQueries() {
	targets := []string{"8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"}
	for i := 0; i < 6; i++ {
		for _, t := range targets {
			ra, err := net.ResolveUDPAddr("udp4", t)
			if err != nil {
				continue
			}
			c, err := net.DialUDP("udp4", nil, ra)
			if err != nil {
				continue
			}
			c.Write([]byte{0xab, 0xcd, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 3, 'w', 'w', 'w', 0, 0, 1, 0, 1})
			c.Close()
		}
		time.Sleep(150 * time.Millisecond)
	}
}

func outboundIPv4() net.IP {
	c, err := net.Dial("udp4", "8.8.8.8:53")
	if err != nil {
		addrs, _ := net.InterfaceAddrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok {
				if v4 := ipn.IP.To4(); v4 != nil && !v4.IsLoopback() {
					return v4
				}
			}
		}
		return nil
	}
	defer c.Close()
	if ua, ok := c.LocalAddr().(*net.UDPAddr); ok {
		return ua.IP.To4()
	}
	return nil
}

// ---- A) 当前 raw ----

type ipConnReader struct {
	ipc   *net.IPConn
	conn  net.PacketConn
	deadl time.Time
}

func openCurrentRaw(_ net.IP) (reader, error) {
	c, err := net.ListenPacket("ip4:udp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	ipc, _ := c.(*net.IPConn)
	return &ipConnReader{ipc: ipc, conn: c}, nil
}

func (r *ipConnReader) read(buf []byte) (int, error) {
	if r.ipc != nil {
		_ = r.ipc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, _, _, err := r.ipc.ReadMsgIP(buf, nil)
		return n, err
	}
	_ = r.conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	n, _, err := r.conn.ReadFrom(buf)
	return n, err
}
func (r *ipConnReader) close() { r.conn.Close() }

// ---- B) SIO_RCVALL ----

func openRCVALL(local net.IP) (reader, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		return nil, fmt.Errorf("socket: %w", err)
	}
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], local.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Closesocket(fd)
		return nil, fmt.Errorf("bind %s: %w", local, err)
	}
	var in uint32 = rcvallON
	var ret uint32
	r, _, e := ws2_32.NewProc("WSAIoctl").Call(
		uintptr(fd), uintptr(sioRCVALL),
		uintptr(unsafe.Pointer(&in)), uintptr(4),
		0, 0, uintptr(unsafe.Pointer(&ret)), 0, 0,
	)
	if r != 0 {
		syscall.Closesocket(fd)
		return nil, fmt.Errorf("WSAIoctl(SIO_RCVALL): %v", e)
	}
	return &fdReader{fd: fd}, nil
}

type fdReader struct{ fd syscall.Handle }

type wsabuf struct {
	Len uint32
	Buf *byte
}

func (r *fdReader) read(buf []byte) (int, error) {
	tv := syscall.NsecToTimeval((300 * time.Millisecond).Nanoseconds())
	_ = syscall.SetsockoptTimeval(r.fd, solSocket, soRcvTimeo, &tv)

	wb := wsabuf{Len: uint32(len(buf)), Buf: &buf[0]}
	var from [16]byte
	fromLen := int32(16)
	var recvd uint32
	var flags uint32
	ret, _, e := ws2_32.NewProc("WSARecvFrom").Call(
		uintptr(r.fd),
		uintptr(unsafe.Pointer(&wb)),
		1,
		uintptr(unsafe.Pointer(&recvd)),
		uintptr(unsafe.Pointer(&flags)),
		uintptr(unsafe.Pointer(&from[0])),
		uintptr(unsafe.Pointer(&fromLen)),
		0, 0,
	)
	if int32(ret) == -1 {
		return 0, e
	}
	return int(recvd), nil
}
func (r *fdReader) close() { syscall.Closesocket(r.fd) }
