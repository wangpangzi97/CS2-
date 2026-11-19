// Package pcapdev 负责抓原始 IP 包。
//
// 本版本**只用 Windows 原始套接字**，不依赖任何第三方驱动（没有 Npcap / wpcap.dll）：
//
//	socket(AF_INET, SOCK_RAW, IPPROTO_IP)
//	  → bind(fd, 本机网卡 IPv4)
//	  → WSAIoctl(fd, SIO_RCVALL = 0x98000001, ON)   把网卡切成混杂模式 → 双向收包
//	  → WSARecvFrom(fd, ...)                        逐包取回
//
// 端口过滤不在这一层，在 internal/capturefilter（iphlpapi!GetExtendedUdpTable）。
//
// # 为什么必须是 SIO_RCVALL
//
// 客户端握手包是客户端**发出去**的（发送方向），而 net.ListenPacket("ip4:udp")
// 只能收「发往本机」的包。实测（tools/rawdir）：
//
//	ip4:udp + 0.0.0.0            发送方向 0   / 接收方向 15
//	SOCK_RAW + SIO_RCVALL        发送方向 702 / 接收方向 177
//
// 只收接收方向 → 握手永远拿不到 → 密钥搜索不启动 → 雷达页一直空白。
// 所以这里**只保留 SIO_RCVALL 一条路**，不做「只收方向」的降级 ——
// 那条路拿到包也没用，只会让人误以为在正常工作。
//
// SIO_RCVALL 需要管理员权限。GUI 版（CS2雷达.exe）会自动弹 UAC 提权；
// 命令行版必须「以管理员身份运行」。
package pcapdev

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

var ws2_32 = syscall.NewLazyDLL("ws2_32.dll")

// ---- Windows 原始套接字（SIO_RCVALL）常量 ----

const (
	sioRCVALL  = 0x98000001 // WSAIoctl：开启/关闭混杂接收（双向）
	rcvallON   = 1
	solSocket  = 0xffff
	soRcvTimeo = 0x1006
	soRcvBuf   = 0x1002
)

// rcvBufBytes 是 raw socket 的接收缓冲目标值。
//
// 🔴 硬规则 292（2026-10-20 13:20）：**默认缓冲太小是 signon 段丢包的元凶**。
//
// 13:05 那局现场：
//
//	[snp] 流位置=248169 已出=209559 最大空洞=79708 跳过=1次/38609字节
//	[signon] 走到 172724/262374 字节=65.8%
//
// 首段位置=1（确实从连接起点抓），却在 signon 中间丢了 38609 字节。
// 而 signon 是**一次性**的：svc_FlattenedSerializer 和
// svc_CreateStringTable(instancebaseline) 只在连接起点发一次，
// 丢了就永久没有 ⇒ entity_data 的字段循环一步都走不动。
//
// 连接建立瞬间服务端会一次性灌几十万字节（sendtable + serializer +
// instancebaseline + 多张 precache 表），SIO_RCVALL 的默认缓冲（通常 64KB）
// 在这个突发下必然溢出。这里直接要 8 MB —— 代价只是内核内存，
// 换来的是「signon 只抓一次」这件事不再靠运气。
const rcvBufBytes = 8 << 20

// ModeName 是唯一抓包模式的名字，进 capture_ready.mode。
const ModeName = "raw-SIO_RCVALL(双向)"

// wsabuf 对应 WinSock 的 WSABUF。
type wsabuf struct {
	Len uint32
	Buf *byte
}

// Device 描述一个可用抓包口，供 -list-devices 展示。
//
// 原始套接字是「整机抓包」，不按 Npcap 那样枚举 \\Device\\NPF_{GUID}；
// 这里列出的是本机网卡地址（每个地址会开一个 RCVALL socket）。
type Device struct {
	Name        string // 网卡名
	Description string // 该网卡上的 IPv4 地址
}

// Devices 列出本机可用于抓包的 IPv4 地址。
func Devices() []Device {
	var out []Device
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipn.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, Device{Name: ifi.Name, Description: v4.String()})
		}
	}
	return out
}

// RawAvailable 探测原始套接字后端是否可用。
//
// 只认 SIO_RCVALL：能开起来才算可用（通常意味着有管理员权限）。
func RawAvailable() error {
	fds, err := openRCVALLSockets()
	if err != nil {
		return err
	}
	for _, fd := range fds {
		syscall.Closesocket(fd)
	}
	return nil
}

// Handle 是一个打开的抓包句柄。
type Handle struct {
	received     atomic.Uint64
	queueDropped atomic.Uint64
	fds          []syscall.Handle
	ch           chan []byte
	done         chan struct{}
	wg           sync.WaitGroup
	once         sync.Once
}

// Open 打开抓包句柄：给每个本机非回环 IPv4 建一个开启 SIO_RCVALL 的原始套接字。
func Open() (*Handle, error) {
	fds, err := openRCVALLSockets()
	if err != nil {
		return nil, err
	}
	h := &Handle{
		fds:  fds,
		ch:   make(chan []byte, 8192),
		done: make(chan struct{}),
	}
	for _, fd := range fds {
		h.wg.Add(1)
		go h.readLoop(fd)
	}
	return h, nil
}

// RawCaptureMode 返回抓包模式名（固定，进 capture_ready.mode）。
func (h *Handle) RawCaptureMode() string { return ModeName }

// InterfaceCount 返回实际开了几个 RCVALL socket（= 本机非回环 IPv4 个数）。
func (h *Handle) InterfaceCount() int { return len(h.fds) }

// ---- SIO_RCVALL ----

// localIPv4s 返回本机所有非回环、非链路本地 IPv4 地址。
func localIPv4s() []net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}
	var out []net.IP
	seen := map[string]bool{}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipn.IP.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
			continue
		}
		s := v4.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, v4)
	}
	return out
}

// openRCVALLSockets 给每个本机网卡地址建一个开启 SIO_RCVALL 的原始套接字。
func openRCVALLSockets() ([]syscall.Handle, error) {
	ips := localIPv4s()
	if len(ips) == 0 {
		return nil, errors.New("本机没有可用的 IPv4 地址（非回环），无法开抓包口")
	}
	var fds []syscall.Handle
	var lastErr error
	for _, ip := range ips {
		fd, err := openOneRCVALL(ip)
		if err != nil {
			lastErr = err
			continue
		}
		fds = append(fds, fd)
	}
	if len(fds) == 0 {
		if lastErr == nil {
			lastErr = errors.New("SIO_RCVALL 在所有网卡上都失败")
		}
		return nil, lastErr
	}
	// 🔴 硬规则 292：把**实际生效**的接收缓冲报出来。
	//
	// 为什么要报实际值而不是设了多少：Windows 会把 SO_RCVBUF 静默钳制
	// （取决于网卡驱动和系统全局上限）。如果实际值远小于 8 MB，
	// 那 signon 段丢包还会复发 —— 这条日志是判断「下一局能不能抓到完整
	// signon」的唯一依据，不能省。
	//
	// 走 stderr：pcapdev 是纯库，没有日志依赖；collector 把 stderr 一起收进运行日志。
	for i, fd := range fds {
		if v, e := syscall.GetsockoptInt(fd, solSocket, soRcvBuf); e == nil {
			fmt.Fprintf(os.Stderr, "[cap] raw socket #%d 接收缓冲：目标 %d KB，实际 %d KB（配置值不能证明无丢包）\n", i, rcvBufBytes>>10, v>>10)
		} else {
			fmt.Fprintf(os.Stderr, "[cap] raw socket #%d 查询接收缓冲失败: %v\n", i, e)
		}
	}

	return fds, nil
}

func openOneRCVALL(ip net.IP) (syscall.Handle, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_IP)
	if err != nil {
		return 0, fmt.Errorf("socket(AF_INET,SOCK_RAW,IPPROTO_IP): %w", err)
	}
	sa := &syscall.SockaddrInet4{}
	copy(sa.Addr[:], ip.To4())
	if err := syscall.Bind(fd, sa); err != nil {
		syscall.Closesocket(fd)
		return 0, fmt.Errorf("bind %s: %w", ip, err)
	}
	// 🔴 硬规则 292：必须在 SIO_RCVALL 之前把接收缓冲拉大。
	//
	// 顺序有讲究：一旦 SIO_RCVALL 打开，包立刻开始往缓冲里灌，
	// 这时候再调 SO_RCVBUF 已经晚了（缓冲里已有的丢包无法补回）。
	// 所以放在 bind 之后、RCVALL 之前 —— 这是唯一正确的窗口。
	//
	// 设置失败**不报错**：某些网卡/驱动会静默钳制到上限，
	// 但那是「尽力而为」，不该让整个抓包起不来。失败时只是回到默认缓冲。
	if err := syscall.SetsockoptInt(fd, solSocket, soRcvBuf, rcvBufBytes); err != nil {
		fmt.Printf("[pcap] %s SO_RCVBUF 设置失败: %v（继续使用系统值；不据此判断丢包）\n", ip, err)
	}
	// 200ms 收超时：让 readLoop 能定期看到 done 关闭，退出及时。
	tv := syscall.NsecToTimeval((200 * time.Millisecond).Nanoseconds())
	_ = syscall.SetsockoptTimeval(fd, solSocket, soRcvTimeo, &tv)

	var in uint32 = rcvallON
	var ret uint32
	r, _, e := ws2_32.NewProc("WSAIoctl").Call(
		uintptr(fd), uintptr(sioRCVALL),
		uintptr(unsafe.Pointer(&in)), uintptr(4),
		0, 0, uintptr(unsafe.Pointer(&ret)), 0, 0,
	)
	if r != 0 {
		syscall.Closesocket(fd)
		return 0, fmt.Errorf("WSAIoctl(SIO_RCVALL) on %s: %v（通常是没有管理员权限）", ip, e)
	}
	return fd, nil
}

// readLoop 在一个 RCVALL socket 上持续收包，只把 IPv4/UDP 推进通道。
//
// SIO_RCVALL 收的是该网卡上的全部 IP 流量（含 TCP/ICMP 和其它进程），
// 这里先按协议过滤掉非 UDP，避免把无关流量灌进解码器。
func (h *Handle) readLoop(fd syscall.Handle) {
	defer h.wg.Done()
	buf := make([]byte, 65536)
	for {
		select {
		case <-h.done:
			return
		default:
		}
		n, err := wsaRecvFrom(fd, buf)
		if err != nil {
			select {
			case <-h.done:
				return
			default:
			}
			continue
		}
		if n < 20 || buf[0]>>4 != 4 || buf[9] != 17 { // 只留 IPv4 + UDP
			continue
		}
		h.received.Add(1)
		p := make([]byte, n)
		copy(p, buf[:n])
		select {
		case h.ch <- p:
		default: // bounded queue: record actual local drops
			h.queueDropped.Add(1)
		}
	}
}

// wsaRecvFrom 调 ws2_32 的 WSARecvFrom。
//
// ⚠ 导出名是 WSARecvFrom（大写 F）；写成 WSARecvfrom 会找不到过程。
// 另：Go 的 syscall.Recvfrom 在 Windows 上是空实现（返回 EWINDOWS），不能用。
func wsaRecvFrom(fd syscall.Handle, buf []byte) (int, error) {
	wb := wsabuf{Len: uint32(len(buf)), Buf: &buf[0]}
	var from [16]byte
	fromLen := int32(16)
	var recvd uint32
	var flags uint32
	ret, _, e := ws2_32.NewProc("WSARecvFrom").Call(
		uintptr(fd),
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

// Next 取下一个原始 IP 包（带完整 IPv4 头，供 transport.ParseIPv4UDP 解析）。
//
// 返回的切片是独立副本，调用方可安全持有。
// 被 Interrupt 唤醒时返回 (nil, nil)，调用方应视为"没拿到包"继续下一轮。
func (h *Handle) Next() ([]byte, error) {
	select {
	case p := <-h.ch:
		return p, nil
	case <-h.done:
		return nil, errors.New("抓包句柄已关闭")
	}
}

// Interrupt 叫醒正阻塞在 Next() 上的调用方。
//
// 为什么需要：主循环的退出判断在**循环顶部**，而它大部分时间卡在 Next() 里
// 等包。网卡安静时（目标进程没在收发）它会一直等到下一个包才回到顶部，
// 期间 Stop() 早就生效了却没人检查 —— 表现就是"点了关闭，窗口半天不关"。
// 这里主动塞一个空包把 Next 叫醒，上层拿到 nil 就 continue，
// 下一轮立刻看到 stopCh 已关并正常退出。
func (h *Handle) Interrupt() {
	select {
	case h.ch <- nil:
	default: // 缓冲已满说明有包在排队，Next 本来就不会卡住
	}
}

// Close 关闭句柄，并等所有收包 goroutine 退出。
//
// ⚠ 等待有超时，不能无限等。正常情况下 `Closesocket` 会让阻塞中的
// `WSARecvFrom` 立刻返回，readLoop 随即看到 done 并退出；但这条依赖不是
// 100% 成立的（SIO_RCVALL 下 `SO_RCVTIMEO` 的表现并不总是可靠）。
// 一旦某个 readLoop 没能退出，`wg.Wait()` 就会把整个收尾链挂住 ——
// Close 返回不了 → doneCh 关不掉 → 窗口的 PostMessage(WM_CLOSE) 发不出去
// → **窗口关不掉**。宁可漏等几个 goroutine（进程马上就要退出了），
// 也不能让用户对着一个关不掉的窗口。
func (h *Handle) Close() {
	h.once.Do(func() { close(h.done) })
	for _, fd := range h.fds {
		syscall.Closesocket(fd)
	}
	waited := make(chan struct{})
	go func() {
		h.wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		fmt.Fprintln(os.Stderr, "⚠ 关闭抓包句柄超时（3s），仍有收包线程未退出，继续收尾。")
	}
	h.fds = nil
}

func (h *Handle) Stats() map[string]any {
	return map[string]any{"udp_received": h.received.Load(), "queue_dropped": h.queueDropped.Load(), "queue_depth": len(h.ch), "queue_capacity": cap(h.ch)}
}
