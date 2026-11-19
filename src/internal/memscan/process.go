// Package memscan 还原 capture.exe 中 local/cs2-radar/internal/memscan 的行为。
//
// 对应符号（capture.exe）：
//
//	FindPid                @0xe65a0   CreateToolhelp32Snapshot + Process32FirstW/NextW
//	openWithRights         @0xe5d60   OpenProcess(rights, FALSE, pid)
//	Open / OpenForQuery    @0xe5b00   0x400
//	OpenForRead            @0xe5b80   0xC10 = VM_READ|QUERY_INFORMATION|SUSPEND_RESUME
//	(*Process).ReadAt      @0xe64e0   ReadProcessMemory（5 参数）
//	(*Process).RegionsWithError @0xe5fc0 VirtualQueryEx（带 deadline/limit）
//	(*Process).FreezeFast  @0xe5a80   NtSuspendProcess，ret==0 才算成功
//	(*Process).ThawFast    @0xe5c00   NtResumeProcess
//	(*Process).Freeze      @0xe5b00   按线程路径 OpenThread+SuspendThread
//	(*Process).CloseThreadHandles @0xe58c0
//	(*Process).Frozen      @0xe6620
//
// 关键事实：全二进制只有两处 OpenProcess 调用（0x400 与 0xC10），
// 从不申请 VM_WRITE / VM_OPERATION / CREATE_THREAD —— 因此不具备注入能力。
package memscan

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"local/cs2-radar/internal/winapi"
)

// Region 是一个可读内存区域。
type Region struct {
	Base    uintptr
	Size    uintptr
	Protect uint32
	State   uint32
	// Type 是 MEMORY_BASIC_INFORMATION.Type：MEM_PRIVATE / MEM_IMAGE / MEM_MAPPED。
	// 扫描时据此排优先级 —— 堆（PRIVATE）里才可能有密钥，PE 映像里只有代码和常量。
	Type uint32
}

// Process 持有目标进程句柄与线程句柄集合。
type Process struct {
	PID    uint32
	handle uintptr

	frozen        bool
	threadHandles []uintptr
	threadIDs     []uint32

	// 统计（对应原结构体上的原子计数器）
	//
	// 用原子操作而不是普通自增：全内存兜底搜私钥是**多 goroutine 并发读**的，
	// 普通 += 在这里就是数据竞争（race detector 会直接报，且计数会丢）。
	reads      atomic.Uint64
	bytesRead  atomic.Uint64
	blocks     atomic.Uint64
	shortReads atomic.Uint64
}

// ErrRegionEmpty 对应字符串 "VirtualQueryEx returned an empty region"。
var ErrRegionEmpty = errors.New("VirtualQueryEx returned an empty region")

// ErrRegionDeadline 对应 "region query deadline reached"。
var ErrRegionDeadline = errors.New("region query deadline reached")

// ErrRegionLimit 对应 "region query limit reached"。
var ErrRegionLimit = errors.New("region query limit reached")

// ErrProcessNotFound distinguishes absence from enumeration failure without error-text parsing.
var ErrProcessNotFound = errors.New("target process not found")

// FindPid 按进程名（不区分大小写，带/不带 .exe 均可）查找 PID。
func FindPid(name string) (uint32, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	if !strings.HasSuffix(want, ".exe") {
		want += ".exe"
	}
	snap, _, err := winapi.ProcCreateToolhelp32Snapshot.Call(winapi.TH32CS_SNAPPROCESS, 0)
	if snap == winapi.InvalidHandleValue || snap == 0 {
		return 0, fmt.Errorf("CreateToolhelp32Snapshot failed: %v", err)
	}
	defer winapi.ProcCloseHandle.Call(snap)

	var pe winapi.ProcessEntry32W
	pe.Size = uint32(unsafe.Sizeof(pe))
	ok, _, _ := winapi.ProcProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&pe)))
	if ok == 0 {
		return 0, errors.New("Process32FirstW failed")
	}
	for {
		exe := strings.ToLower(syscall.UTF16ToString(pe.ExeFile[:]))
		if exe == want {
			return pe.ProcessID, nil
		}
		ok, _, nextErr := winapi.ProcProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&pe)))
		if ok == 0 {
			if errno, valid := nextErr.(syscall.Errno); !valid || errno != 0 && errno != syscall.ERROR_NO_MORE_FILES {
				return 0, fmt.Errorf("Process32NextW failed: %v", nextErr)
			}
			break
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrProcessNotFound, want)
}

// openWithRights 直接对应同名函数：OpenProcess(rights, FALSE, pid)。
func openWithRights(pid uint32, rights uint32) (uintptr, error) {
	h, _, err := winapi.ProcOpenProcess.Call(uintptr(rights), 0, uintptr(pid))
	if h == 0 {
		// 原文：OpenProcess(pid=%d) 失败：%v（尝试以管理员运行，或用 -pid 指定）
		return 0, fmt.Errorf("OpenProcess(pid=%d) 失败：%v（尝试以管理员运行，或用 -pid 指定）", pid, err)
	}
	return h, nil
}

// Open 只申请查询权限（-memory-info / -no-keys 路径）。
func Open(pid uint32) (*Process, error) {
	return OpenForQuery(pid)
}

// OpenForQuery 使用 0x400。
func OpenForQuery(pid uint32) (*Process, error) {
	h, err := openWithRights(pid, winapi.OpenQueryRights)
	if err != nil {
		return nil, err
	}
	return &Process{PID: pid, handle: h}, nil
}

// OpenForRead 使用 0xC10（读内存 + 查询 + 挂起/恢复）。
func OpenForRead(pid uint32) (*Process, error) {
	h, err := openWithRights(pid, winapi.OpenReadRights)
	if err != nil {
		return nil, err
	}
	return &Process{PID: pid, handle: h}, nil
}

// Handle 返回原始句柄。
func (p *Process) Handle() uintptr { return p.handle }

// Close 释放句柄与线程句柄。
func (p *Process) Close() {
	if p.frozen {
		_ = p.ThawFast()
	}
	p.CloseThreadHandles()
	if p.handle != 0 {
		winapi.ProcCloseHandle.Call(p.handle)
		p.handle = 0
	}
}

// ReadAt 对应 (*Process).ReadAt：ReadProcessMemory 5 参数调用。
func (p *Process) ReadAt(addr uintptr, buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}
	var n uintptr
	p.reads.Add(1)
	r, _, err := winapi.ProcReadProcessMemory.Call(
		p.handle,
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&n)),
	)
	if r == 0 {
		p.shortReads.Add(1)
		return int(n), fmt.Errorf("ReadProcessMemory(%#x) failed: %v", addr, err)
	}
	p.bytesRead.Add(uint64(n))
	if int(n) < len(buf) {
		p.shortReads.Add(1)
	}
	return int(n), nil
}

// ReadFull 读取恰好 len(buf) 字节，短读返回错误。
func (p *Process) ReadFull(addr uintptr, buf []byte) error {
	n, err := p.ReadAt(addr, buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return fmt.Errorf("short read at %#x: %d/%d", addr, n, len(buf))
	}
	return nil
}

// RegionsWithError 枚举可读区域，对应 VirtualQueryEx 循环。
// max 为 0 表示不限；deadline 为零值表示不限时。
func (p *Process) RegionsWithError(deadline time.Time, max int) ([]Region, error) {
	var out []Region
	var addr uintptr
	for {
		if !deadline.IsZero() && time.Now().After(deadline) {
			return out, ErrRegionDeadline
		}
		var mbi winapi.MemoryBasicInformation
		r, _, err := winapi.ProcVirtualQueryEx.Call(
			p.handle,
			addr,
			uintptr(unsafe.Pointer(&mbi)),
			unsafe.Sizeof(mbi),
		)
		if r == 0 {
			if addr == 0 {
				return out, fmt.Errorf("VirtualQueryEx failed: %v", err)
			}
			break
		}
		if mbi.RegionSize == 0 {
			return out, ErrRegionEmpty
		}
		p.blocks.Add(1)
		if mbi.State == winapi.MEM_COMMIT && winapi.ReadableProtect(mbi.Protect) {
			out = append(out, Region{
				Base:    mbi.BaseAddress,
				Size:    mbi.RegionSize,
				Protect: mbi.Protect,
				State:   mbi.State,
				Type:    mbi.Type,
			})
			if max > 0 && len(out) >= max {
				return out, ErrRegionLimit
			}
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr { // 溢出或原地踏步
			break
		}
		addr = next
	}
	return out, nil
}

// FreezeFast 对应 NtSuspendProcess：单句柄参数，NTSTATUS==0 才算成功。
func (p *Process) FreezeFast() error {
	if p.handle == 0 {
		return errors.New("process handle is nil")
	}
	r, _, _ := winapi.ProcNtSuspendProcess.Call(p.handle)
	if r != 0 {
		return fmt.Errorf("NtSuspendProcess returned NTSTATUS %#x", r)
	}
	p.frozen = true
	return nil
}

// ThawFast 对应 NtResumeProcess。
func (p *Process) ThawFast() error {
	if p.handle == 0 {
		return errors.New("process handle is nil")
	}
	r, _, _ := winapi.ProcNtResumeProcess.Call(p.handle)
	if r != 0 {
		// 原文：游戏恢复调用未成功，请立即停止工具
		return fmt.Errorf("游戏恢复调用未成功，请立即停止工具 (NTSTATUS %#x)", r)
	}
	p.frozen = false
	return nil
}

// Freeze 走按线程路径（OpenThread + SuspendThread），供需要精细控制的场景使用。
func (p *Process) Freeze() error {
	ids, err := p.threadIDsOf()
	if err != nil {
		return err
	}
	for _, tid := range ids {
		h, _, _ := winapi.ProcOpenThread.Call(0x0002 /*THREAD_SUSPEND_RESUME*/, 0, uintptr(tid))
		if h == 0 {
			continue
		}
		winapi.ProcSuspendThread.Call(h)
		p.threadHandles = append(p.threadHandles, h)
	}
	p.frozen = true
	return nil
}

// Thaw 按线程路径恢复。
func (p *Process) Thaw() error {
	for _, h := range p.threadHandles {
		winapi.ProcResumeThread.Call(h)
	}
	p.CloseThreadHandles()
	p.frozen = false
	return nil
}

// CloseThreadHandles 对应同名函数。
func (p *Process) CloseThreadHandles() {
	for _, h := range p.threadHandles {
		winapi.ProcCloseHandle.Call(h)
	}
	p.threadHandles = nil
}

// Frozen 对应 (*Process).Frozen。
func (p *Process) Frozen() bool { return p.frozen }

// RegionOf 返回包含 addr 的区域；找不到返回零值 + false。
func RegionOf(regions []Region, addr uintptr) (Region, bool) {
	for _, r := range regions {
		if addr >= r.Base && addr < r.Base+r.Size {
			return r, true
		}
	}
	return Region{}, false
}

// ModuleBase 返回主映像（cs2.exe 本体）的加载基址。
//
// 两条路，按可靠性排序：
//
//  1. **Toolhelp 模块快照的第一项**。CreateToolhelp32Snapshot(TH32CS_SNAPMODULE)
//     的枚举顺序是"主模块在前，其余按加载顺序"，所以 Module32FirstW 拿到的
//     就是 exe 本体。这是准的。
//  2. 兜底：MEM_IMAGE 区域里基址最低的那个。
//
// ⚠ 曾经只有第 2 条路，而它是**错的**：cs2.exe 进程里除了 cs2.exe 自己，
// 还映射了 Steam/tier0/反作弊等一堆 DLL，其中有些（如 32 位兼容层、或
// 由系统在低地址映射的映像）基址可能比主模块更低。19:xx 现场核对 hints.json
// 的 module_off 与真实 RVA 差了几十 MB，就是这条近似造成的。
//
// 返回 0 表示没找到（枚举失败或全是私有内存）。
func (p *Process) ModuleBase() uintptr {
	if base := p.mainModuleBaseFromToolhelp(); base != 0 {
		return base
	}
	regions, err := p.RegionsWithError(time.Now().Add(5*time.Second), 0)
	if err != nil && err != ErrRegionDeadline && err != ErrRegionLimit {
		return 0
	}
	var best uintptr
	for _, r := range regions {
		if r.Type != winapi.MEM_IMAGE {
			continue
		}
		if best == 0 || r.Base < best {
			best = r.Base
		}
	}
	return best
}

// mainModuleBaseFromToolhelp 用模块快照拿主模块基址；失败返回 0。
func (p *Process) mainModuleBaseFromToolhelp() uintptr {
	snap, _, _ := winapi.ProcCreateToolhelp32Snapshot.Call(
		winapi.TH32CS_SNAPMODULE, uintptr(p.PID))
	if snap == winapi.InvalidHandleValue || snap == 0 {
		return 0
	}
	defer winapi.ProcCloseHandle.Call(snap)

	var me winapi.ModuleEntry32W
	me.Size = uint32(unsafe.Sizeof(me))
	ok, _, _ := winapi.ProcModule32FirstW.Call(snap, uintptr(unsafe.Pointer(&me)))
	if ok == 0 {
		return 0
	}
	return me.ModBaseAddr
}

// maxUserAddr 是 x64 用户态地址空间的上界（不含），用作并行枚举的扫描终点。
const maxUserAddr = 0x7fff_fffe_0000

// RegionsParallel 是 RegionsWithError 的并行版：把用户地址空间切成 N 段，
// 每段一个 goroutine 从段首开始独立走 VirtualQueryEx。
//
// ── 为什么需要它（2026-10-19 04:10 现场）────────────────────────────
//
// 那次的「握手→冻结延迟」是 188 ms，而 03:43 成功那次是 21 ms。拆开算：
// 38 ms(候选收集 + hint 探测) + **~100 ms(枚举 7579 个区域)** + 50 ms(定位公钥)。
// 私钥只活一次 RTT（客户端收完 ServerHello 就 SecureZeroMemory），
// 这一百毫秒直接决定了私钥还在不在。而 VirtualQueryEx 是**逐区域**的往返调用，
// 串行走 7579 次要 100 ms —— 但它天生可并行（见下），并行后 ~10 ms。
//
// ── 为什么可以并行 ──────────────────────────────────────────────
//
// VirtualQueryEx(addr) 返回的是**包含 addr 的那个区域**，所以从任意段首开始
// 独立往上走，都能拿到该段内的完整区域链，不需要从 0 顺序走。
// 跨段边界的区域会被两个 worker 各报一次，按 Base 去重即可。
//
// 🔴 2026-10-19 04:24 再修：**段不能按 worker 数均分**。
//
// 第一版是「地址空间切成 workers 份」，结果 04:24 现场 7624 个区域仍然花了 71 ms。
// 原因是区域分布极不均匀：cs2 的堆几乎全挤在 0x2adc_xxxx_xxxx 附近那一小片，
// 而地址空间按 16 等分后每段 8.7 TB —— 那一整片只落在**一段**里，
// 于是 15 个 worker 扫空段瞬间返回、1 个 worker 串行走完 7000 多个区域。
//
// 改成「切成 workers×32 个小段 + 动态领取」（16 核 → 512 段，每段 ~275 GB）：
// 密集区被切成十几个小段，自然摊到多个 worker 上；空段一次 VirtualQueryEx
// 就跳到段尾，几乎不花钱。多出来的 512 次探针相对 7600 个区域只有 7% 开销。
//
// 与 RegionsWithError 的契约保持一致：超时返回 ErrRegionDeadline（但**仍返回
// 已经拿到的部分**，调用方可以照常用），成功返回按 Base 升序的区域列表。
func (p *Process) RegionsParallel(deadline time.Time, workers int) ([]Region, error) {
	if p == nil {
		return nil, errors.New("memscan: nil process")
	}
	if workers < 1 {
		workers = 1
	}
	if workers > 32 {
		workers = 32
	}

	// 段数远多于 worker 数，才能让"内存密集区"被切开并摊平到多个 worker。
	// 上限 512：再多的话探针本身的开销（每段至少一次 VirtualQueryEx）就盖过收益了。
	segs := workers * 32
	if segs > 512 {
		segs = 512
	}
	if segs < 1 {
		segs = 1
	}
	span := uintptr(maxUserAddr) / uintptr(segs)

	var (
		mu       sync.Mutex
		out      []Region
		wg       sync.WaitGroup
		hitLimit bool
	)
	// 段号走动态队列：谁先干完谁领下一段，天然负载均衡。
	segCh := make(chan int, segs)
	for i := 0; i < segs; i++ {
		segCh <- i
	}
	close(segCh)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]Region, 0, 256)
			for si := range segCh {
				lo := uintptr(si) * span
				hi := lo + span
				if si == segs-1 {
					hi = maxUserAddr
				}
				addr := lo
				for addr < hi {
					if !deadline.IsZero() && time.Now().After(deadline) {
						mu.Lock()
						hitLimit = true
						mu.Unlock()
						break
					}
					var mbi winapi.MemoryBasicInformation
					r, _, _ := winapi.ProcVirtualQueryEx.Call(
						p.handle,
						addr,
						uintptr(unsafe.Pointer(&mbi)),
						unsafe.Sizeof(mbi),
					)
					if r == 0 || mbi.RegionSize == 0 {
						break
					}
					p.blocks.Add(1)
					if mbi.State == winapi.MEM_COMMIT && winapi.ReadableProtect(mbi.Protect) {
						local = append(local, Region{
							Base:    mbi.BaseAddress,
							Size:    mbi.RegionSize,
							Protect: mbi.Protect,
							State:   mbi.State,
							Type:    mbi.Type,
						})
					}
					next := mbi.BaseAddress + mbi.RegionSize
					if next <= addr { // 溢出或原地踏步
						break
					}
					addr = next
				}
			}
			mu.Lock()
			out = append(out, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()

	sort.Slice(out, func(i, j int) bool { return out[i].Base < out[j].Base })
	// 跨段边界重复报的区域：排序后相邻去重。
	if len(out) > 1 {
		w := 1
		for i := 1; i < len(out); i++ {
			if out[i].Base == out[w-1].Base && out[i].Size == out[w-1].Size {
				continue
			}
			out[w] = out[i]
			w++
		}
		out = out[:w]
	}
	if hitLimit {
		return out, ErrRegionDeadline
	}
	return out, nil
}

func (p *Process) threadIDsOf() ([]uint32, error) {
	if len(p.threadIDs) > 0 {
		return p.threadIDs, nil
	}
	snap, _, err := winapi.ProcCreateToolhelp32Snapshot.Call(winapi.TH32CS_SNAPTHREAD, 0)
	if snap == winapi.InvalidHandleValue || snap == 0 {
		return nil, fmt.Errorf("CreateToolhelp32Snapshot(TH32) failed: %v", err)
	}
	defer winapi.ProcCloseHandle.Call(snap)
	var te winapi.ThreadEntry32
	te.Size = uint32(unsafe.Sizeof(te))
	ok, _, _ := winapi.ProcThread32First.Call(snap, uintptr(unsafe.Pointer(&te)))
	if ok == 0 {
		return nil, errors.New("Thread32First failed")
	}
	for {
		if te.OwnerProcessID == p.PID {
			p.threadIDs = append(p.threadIDs, te.ThreadID)
		}
		ok, _, _ = winapi.ProcThread32Next.Call(snap, uintptr(unsafe.Pointer(&te)))
		if ok == 0 {
			break
		}
	}
	return p.threadIDs, nil
}

// Stats 返回读取统计。
func (p *Process) Stats() (reads, bytesRead, blocks, shortReads uint64) {
	return p.reads.Load(), p.bytesRead.Load(), p.blocks.Load(), p.shortReads.Load()
}
