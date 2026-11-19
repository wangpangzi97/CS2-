// Package capturefilter 还原 capture.exe 中 local/cs2-radar/internal/capturefilter 的行为。
//
// 对应符号/字符串（capture.exe）：
//
//	capturefilter.UDP              BPF 串 "ip and udp"
//	capturefilter.(*Filter).Match  逐包判定
//	capturefilter.(*Filter).Discover  发现"游戏占用的 UDP 端口"
//	pcapdev.UDPPortOwned           端口是否属于目标进程
//	GetExtendedUdpTable            iphlpapi.dll（动态加载）
//
// 为什么需要它：
//
//	raw 后端开了 SIO_RCVALL 之后，收到的是**该网卡上全部 UDP**（含其它程序）。
//	不过滤的话，既浪费带宽/缓冲，又可能让握手解析在无关包上误命中
//	（ParseHandshake 会扫每个包的 0x22 头；一旦误命中，靶子公钥就错了，
//	 密钥搜索会带着错误靶子跑到超时）。
//
// 过滤规则：只保留「源端口或目的端口 = 目标进程占用的本机 UDP 端口」的包。
// 客户端本地端口 L 由 cs2.exe 持有：c2s 包 src=L、s2c 包 dst=L，两侧都能命中。
//
// 保守兜底：**发现不到端口时不启用过滤**（照常收全部 UDP），
// 避免"过滤条件写错导致静默抓不到包"——那是我们反复踩过的坑。
package capturefilter

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"syscall"
	"unsafe"
)

var iphlpapi = syscall.NewLazyDLL("iphlpapi.dll")

const (
	afInet           = 2 // AF_INET
	udpTableOwnerPid = 1 // UDP_TABLE_OWNER_PID
)

// mibUDPRowOwnerPid 对应 MIB_UDPROW_OWNER_PID（12 字节）。
type mibUDPRowOwnerPid struct {
	LocalAddr uint32
	LocalPort uint32 // 端口在低 16 位，网络字节序
	OwningPid uint32
}

// Discover 返回 pid 占用的所有本机 UDP 端口（去重、升序）。
func Discover(pid uint32) ([]uint16, error) {
	if pid == 0 {
		return nil, errors.New("pid is 0")
	}
	proc := iphlpapi.NewProc("GetExtendedUdpTable")

	// 第一次调用只为拿所需缓冲区大小。
	var size uint32
	if _, _, err := proc.Call(0, uintptr(unsafe.Pointer(&size)), 0, afInet, udpTableOwnerPid, 0); size == 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable size probe failed: %v", err)
	}

	buf := make([]byte, size)
	r, _, e := proc.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		0, afInet, udpTableOwnerPid, 0,
	)
	if r != 0 {
		return nil, fmt.Errorf("GetExtendedUdpTable failed: %v", e)
	}

	numEntries := *(*uint32)(unsafe.Pointer(&buf[0]))
	rowSize := unsafe.Sizeof(mibUDPRowOwnerPid{})
	seen := map[uint16]struct{}{}
	for i := uint32(0); i < numEntries; i++ {
		off := 4 + uintptr(i)*rowSize
		if off+rowSize > uintptr(len(buf)) {
			break
		}
		row := (*mibUDPRowOwnerPid)(unsafe.Pointer(&buf[off]))
		if row.OwningPid != pid {
			continue
		}
		p := ntohs(uint16(row.LocalPort & 0xffff))
		if p != 0 {
			seen[p] = struct{}{}
		}
	}
	out := make([]uint16, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func ntohs(x uint16) uint16 { return x>>8 | x<<8 }

// Filter 是一组"目标进程占用的 UDP 端口"。并发安全。
type Filter struct {
	strict bool // immutable: production never admits with no discovered owner ports
	mu     sync.RWMutex
	ports  map[uint16]struct{}
	owned  map[uint16]struct{}
	pid    uint32
	auto   int // 已经按 GNS 特征自动放行了几个端口（上限 autoAdmitMax）
}

// New 创建空过滤器（空 = 不过滤）。
func New() *Filter { return &Filter{} }

// NewStrict is the production fail-closed filter. AddPort cannot establish ownership.
func NewStrict() *Filter { return &Filter{strict: true} }

// Set 用新的端口集合替换（pid=0 表示清空）。
func (f *Filter) Set(pid uint32, ports []uint16) {
	m := make(map[uint16]struct{}, len(ports))
	for _, p := range ports {
		m[p] = struct{}{}
	}
	f.mu.Lock()
	f.pid, f.ports, f.auto = pid, m, 0
	f.owned = make(map[uint16]struct{}, len(m))
	for p := range m {
		f.owned[p] = struct{}{}
	}
	f.mu.Unlock()
}

// Clear 清空过滤（回到"收全部 UDP"）。
func (f *Filter) Clear() { f.Set(0, nil) }

// AddPort 把一个端口并入现有集合，返回是否是新增。
//
// 为什么需要单端口追加（2026-10-19 现场定案）：
// `Discover` 是按 3 秒周期重查 GetExtendedUdpTable 的。而 CS2 的游戏连接是在
// 采集器启动**之后**才建立的 —— 新端口在下一轮刷新之前完全不在白名单里，
// 这期间该连接上的所有包都被当垃圾丢掉。实测代价：s2c 可靠流首个被解出的段
// 声明位置 = 22809（≈20 个 1137 字节的 signon 包），signon 整段丢失，
// sendtable 永远拿不到。
//
// 握手包是连接的第一包，识别到它的瞬间就把本机端口加进来，丢失窗口≈0。
func (f *Filter) AddPort(p uint16) bool {
	if f.strict {
		return false
	} // production ownership is established only by Discover/Set
	if p == 0 {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ports == nil {
		f.ports = make(map[uint16]struct{}, 8)
	}
	if _, ok := f.ports[p]; ok {
		return false
	}
	f.ports[p] = struct{}{}
	return true
}

// autoAdmitMax 是「按 GNS 特征自动放行」的端口数上限。
//
// 上限必须存在：`Match` 是白名单语义，一旦无界自动加端口，等于退化成
// 「全收」——那正是这个包最初要解决的问题（无关 UDP 会污染握手解析）。
// 12 个足够覆盖「游戏主链路 + 平台中转 + 重连」这几种情况。
const autoAdmitMax = 12

// AutoAdmit 在「已经看到一个像 GNS 加密帧的包、但两个端口都不在白名单里」时，
// 把这对端口并进白名单。返回真正新增的端口。
//
// 🔴 为什么必须做（2026-10-19 22:35 现场定案）：
// 那一局 `[stats]` 显示 `过滤丢弃 96598（其中像 GNS 的 75439）` ——
// 96% 的游戏流量被白名单当垃圾丢掉，而日志里只有一行「signon 可能正被丢弃」。
// 端口 51596→47960 上全是 1100~1180 字节、首字节高位为 1 的包，
// 与已定案的 GNS 密文帧特征完全一致，却因为「不属于 cs2.exe 的 UDP 表」
// 被全丢。结论：**白名单不能只认 cs2.exe 自己的 socket**，
// 平台中转 / 加速器会让真正的链路跑在别的进程持有的端口上。
//
// 判据（调用方负责，这里只做加法）必须足够严：首字节高位为 1 且长度 ≥64。
// 满足这个的 UDP 载荷在普通应用里几乎不存在，所以误放行的风险很低；
// 再叠加 autoAdmitMax 上限，最坏情况也只是多收十几条无关流。
func (f *Filter) AutoAdmit(a, b uint16) []uint16 {
	if f.strict {
		return nil
	} // never turn ciphertext shape into process ownership
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.ports) == 0 {
		return nil // 过滤没生效，本来就全收
	}
	var added []uint16
	for _, p := range [2]uint16{a, b} {
		if p == 0 || f.auto >= autoAdmitMax {
			continue
		}
		if _, ok := f.ports[p]; ok {
			continue
		}
		f.ports[p] = struct{}{}
		f.auto++
		added = append(added, p)
	}
	return added
}

// Active 报告过滤是否生效（端口集合非空）。
func (f *Filter) Active() bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.ports) > 0
}

// PID 返回当前绑定的进程号（0 = 未绑定）。
func (f *Filter) PID() uint32 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.pid
}

// Match 报告一个 UDP 包是否应保留。
//
// 过滤未生效（端口集合为空）时恒返回 true —— 宁可多收，不可漏收。
func (f *Filter) Match(srcPort, dstPort uint16) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.strict && (f.pid == 0 || len(f.owned) == 0) {
		return false
	}
	if len(f.ports) == 0 {
		return true
	}
	if _, ok := f.ports[srcPort]; ok {
		return true
	}
	if _, ok := f.ports[dstPort]; ok {
		return true
	}
	return false
}

// Ports 返回当前端口集合（升序副本），用于展示。
func (f *Filter) Ports() []uint16 {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := make([]uint16, 0, len(f.ports))
	for p := range f.ports {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
