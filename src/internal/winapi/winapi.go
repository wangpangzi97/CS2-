// Package winapi 是与原程序一致的最小 Win32 绑定层。
//
// 还原依据（capture.exe 静态分析）：
//   - memscan 包通过 LazyProc.Call 调用 OpenProcess / ReadProcessMemory /
//     VirtualQueryEx / CreateToolhelp32Snapshot / Process32FirstW / Process32NextW /
//     OpenThread / SuspendThread / ResumeThread / Thread32First / Thread32Next / CloseHandle
//   - FreezeFast / ThawFast 走 ntdll 的 NtSuspendProcess / NtResumeProcess
//   - 设备身份走 crypt32 的 CryptProtectData / CryptUnprotectData
//   - 提权判定走 shell32 的 IsUserAnAdmin
//
// 原程序未使用 x/sys/windows，只用标准库 syscall + NewLazyDLL；
// 本重构保持同样做法，因此不引入任何外部依赖。
package winapi

import "syscall"

var (
	Kernel32 = syscall.NewLazyDLL("kernel32.dll")
	Ntdll    = syscall.NewLazyDLL("ntdll.dll")
	Crypt32  = syscall.NewLazyDLL("crypt32.dll")
	Advapi32 = syscall.NewLazyDLL("advapi32.dll")
	Shell32  = syscall.NewLazyDLL("shell32.dll")
)

var (
	ProcOpenProcess              = Kernel32.NewProc("OpenProcess")
	ProcCloseHandle              = Kernel32.NewProc("CloseHandle")
	ProcReadProcessMemory        = Kernel32.NewProc("ReadProcessMemory")
	ProcVirtualQueryEx           = Kernel32.NewProc("VirtualQueryEx")
	ProcCreateToolhelp32Snapshot = Kernel32.NewProc("CreateToolhelp32Snapshot")
	ProcProcess32FirstW          = Kernel32.NewProc("Process32FirstW")
	ProcProcess32NextW           = Kernel32.NewProc("Process32NextW")
	ProcOpenThread               = Kernel32.NewProc("OpenThread")
	ProcSuspendThread            = Kernel32.NewProc("SuspendThread")
	ProcResumeThread             = Kernel32.NewProc("ResumeThread")
	ProcGetThreadContext         = Kernel32.NewProc("GetThreadContext")
	ProcThread32First            = Kernel32.NewProc("Thread32First")
	ProcThread32Next             = Kernel32.NewProc("Thread32Next")
	ProcModule32FirstW           = Kernel32.NewProc("Module32FirstW")
	ProcModule32NextW            = Kernel32.NewProc("Module32NextW")
	ProcGetModuleHandleW         = Kernel32.NewProc("GetModuleHandleW")
	ProcGetCurrentProcessId      = Kernel32.NewProc("GetCurrentProcessId")

	ProcNtSuspendProcess = Ntdll.NewProc("NtSuspendProcess")
	ProcNtResumeProcess  = Ntdll.NewProc("NtResumeProcess")

	ProcCryptProtectData   = Crypt32.NewProc("CryptProtectData")
	ProcCryptUnprotectData = Crypt32.NewProc("CryptUnprotectData")

	ProcIsUserAnAdmin = Shell32.NewProc("IsUserAnAdmin")
)

// ---- 进程访问权限（与原程序一致，见 report §8）----

const (
	PROCESS_VM_READ            = 0x0010
	PROCESS_QUERY_INFORMATION  = 0x0400
	PROCESS_SUSPEND_RESUME     = 0x0800
	PROCESS_VM_WRITE           = 0x0020
	PROCESS_VM_OPERATION       = 0x0008
	PROCESS_CREATE_THREAD      = 0x0002
	PROCESS_QUERY_LIMITED_INFO = 0x1000
)

// OpenReadRights 是原程序 main.main.func4 @0x18643f 实际使用的权限组合 0xC10。
const OpenReadRights = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME

// OpenQueryRights 是原程序 main.main @0x17f4f3 使用的权限 0x400（只查元数据）。
const OpenQueryRights = PROCESS_QUERY_INFORMATION

// ---- 内存区域状态/保护位 ----

const (
	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_FREE    = 0x10000

	// 区域类型（MEMORY_BASIC_INFORMATION.Type）。用来给扫描排优先级：
	// 私钥在堆上（MEM_PRIVATE），PE 映像（MEM_IMAGE）里是代码和只读常量，
	// 去那里找纯属浪费预算。
	MEM_PRIVATE = 0x20000
	MEM_MAPPED  = 0x40000
	MEM_IMAGE   = 0x1000000

	PAGE_NOACCESS          = 0x01
	PAGE_READONLY          = 0x02
	PAGE_READWRITE         = 0x04
	PAGE_WRITECOPY         = 0x08
	PAGE_EXECUTE           = 0x10
	PAGE_EXECUTE_READ      = 0x20
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_WRITECOPY = 0x80
	PAGE_GUARD             = 0x100
	PAGE_NOCACHE           = 0x200
)

// ReadableProtect 判定一个保护位是否允许读取。
func ReadableProtect(p uint32) bool {
	if p&PAGE_GUARD != 0 || p&PAGE_NOACCESS != 0 {
		return false
	}
	switch {
	case p&PAGE_READONLY != 0,
		p&PAGE_READWRITE != 0,
		p&PAGE_WRITECOPY != 0,
		p&PAGE_EXECUTE_READ != 0,
		p&PAGE_EXECUTE_READWRITE != 0,
		p&PAGE_EXECUTE_WRITECOPY != 0:
		return true
	}
	return false
}

// WritableProtect 判断区域是否可写。
//
// 用途：全内存兜底搜私钥时用它筛掉只读区域。会话密钥是运行时写入的，只可能
// 落在可写页里；PE 映像的代码段和只读常量段（占可读内存的相当一部分）一律
// 跳过，能砍掉大量无意义的 X25519 校验。
func WritableProtect(p uint32) bool {
	if p&PAGE_GUARD != 0 || p&PAGE_NOACCESS != 0 {
		return false
	}
	switch {
	case p&PAGE_READWRITE != 0,
		p&PAGE_WRITECOPY != 0,
		p&PAGE_EXECUTE_READWRITE != 0,
		p&PAGE_EXECUTE_WRITECOPY != 0:
		return true
	}
	return false
}

// ---- TH32CS 快照标志 ----

const (
	TH32CS_SNAPPROCESS = 0x00000002
	TH32CS_SNAPTHREAD  = 0x00000004
	TH32CS_SNAPMODULE  = 0x00000008
)

// INVALID_HANDLE_VALUE
const InvalidHandleValue = ^uintptr(0)

// ---- 结构体（x64 布局，与 Windows SDK 一致）----

type ProcessEntry32W struct {
	Size            uint32
	CntUsage        uint32
	ProcessID       uint32
	DefaultHeapID   uintptr
	ModuleID        uint32
	CntThreads      uint32
	ParentProcessID uint32
	PriClassBase    int32
	Flags           uint32
	ExeFile         [260]uint16
}

type ThreadEntry32 struct {
	Size           uint32
	CntUsage       uint32
	ThreadID       uint32
	OwnerProcessID uint32
	BasePri        int32
	DeltaPri       int32
	Flags          uint32
}

// ModuleEntry32W 是 MODULEENTRY32W 的 x64 布局。
//
// ⚠ 调用前必须把 Size 设成 unsafe.Sizeof(ModuleEntry32W{})，否则 Module32FirstW
// 返回 ERROR_INSUFFICIENT_BUFFER 且什么都不填 —— 这是 Toolhelp 系列的通病。
//
// 字段顺序/填充与 Windows SDK 一致：
//
//	0x00 dwSize / 0x04 th32ModuleID / 0x08 th32ProcessID / 0x0C GlblcntUsage
//	0x10 ProccntUsage / 0x18 modBaseAddr / 0x20 modBaseSize / 0x28 hModule
//	0x30 szModule[256] / 0x230 szExePath[MAX_PATH]
type ModuleEntry32W struct {
	Size         uint32
	ModuleID     uint32
	ProcessID    uint32
	GlblcntUsage uint32
	ProccntUsage uint32
	_            uint32
	ModBaseAddr  uintptr
	ModBaseSize  uint32
	_            uint32
	HModule      uintptr
	SzModule     [256]uint16
	SzExePath    [260]uint16
}

// ModuleName 返回模块文件名（宽字符转 ASCII 前缀，够用来比 "cs2.exe"）。
func (m *ModuleEntry32W) ModuleName() string {
	var b []byte
	for _, c := range m.SzModule {
		if c == 0 {
			break
		}
		if c < 0x80 {
			b = append(b, byte(c))
		} else {
			b = append(b, '?')
		}
	}
	return string(b)
}

type MemoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	_                 uint32
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	_                 uint32
}

// DataBlob 对应 Windows 的 DATA_BLOB。
type DataBlob struct {
	Size uint32
	_    uint32
	Data *byte
}

// IsAdmin 对应原程序 main.begin 的 IsUserAnAdmin 调用。
func IsAdmin() bool {
	r, _, _ := ProcIsUserAnAdmin.Call()
	return r != 0
}
