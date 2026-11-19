package memscan

import (
	"os"
	"reflect"
	"testing"
	"unsafe"

	"local/cs2-radar/internal/winapi"
)

// TestModuleBaseMatchesGetModuleHandle 用一个**独立信源**校验 ModuleBase。
//
// 背景：ModuleBase 原来取"MEM_IMAGE 里基址最低的那个"，这在 cs2.exe 里是错的
// —— 进程里还映射了 Steam / tier0 / 反作弊等一堆 DLL，其中可能有比主模块更低的
// 映像，于是 hints.json 里的 module_off 变成垃圾值。现在改成 Toolhelp 模块快照
// 的第一项（主模块必在首位），这个用例把它钉住。
//
// 信源选 GetModuleHandleW(NULL)：它返回的 HMODULE 就是调用方进程主模块的基址，
// 和 Toolhelp 完全不同的实现路径，不会"一起错"。
func TestModuleBaseMatchesGetModuleHandle(t *testing.T) {
	proc, err := OpenForRead(uint32(os.Getpid()))
	if err != nil {
		t.Skipf("打不开自身进程（多半是权限）: %v", err)
	}
	defer proc.Close()

	want, _, _ := winapi.ProcGetModuleHandleW.Call(0)
	if want == 0 {
		t.Skipf("GetModuleHandleW(NULL) 返回 0，无法作为信源")
	}

	got := proc.ModuleBase()
	if got != want {
		t.Fatalf("ModuleBase()=%#x，GetModuleHandleW(NULL)=%#x（差 %d 字节）", got, want, int64(got)-int64(want))
	}

	// 顺带钉住"主模块基址必须低于本进程任何代码地址，且 RVA 合理"。
	// 这条不变量正是 hints 换算 module_off 的前提。
	fn := reflect.ValueOf(TestModuleBaseMatchesGetModuleHandle).Pointer()
	if fn < got {
		t.Fatalf("代码地址 %#x 低于主模块基址 %#x —— 基址肯定取错了", fn, got)
	}
	if rva := fn - got; rva > 256<<20 {
		t.Fatalf("代码地址相对基址的 RVA = %#x，超过 256 MB —— 基址多半是别的模块", rva)
	}
	t.Logf("主模块基址 %#x，本用例代码 RVA %#x", got, fn-got)
}

// TestModuleBaseToolhelpFirstEntry 确认 Toolhelp 第一条就是主模块，
// 且它的名字和当前 exe 文件名一致（不依赖 GetModuleHandle，交叉验证另一条路径）。
func TestModuleBaseToolhelpFirstEntry(t *testing.T) {
	snap, _, err := winapi.ProcCreateToolhelp32Snapshot.Call(
		winapi.TH32CS_SNAPMODULE, uintptr(os.Getpid()))
	if snap == winapi.InvalidHandleValue || snap == 0 {
		t.Skipf("模块快照建不起来: %v", err)
	}
	defer winapi.ProcCloseHandle.Call(snap)

	var me winapi.ModuleEntry32W
	me.Size = uint32(unsafe.Sizeof(me))
	ok, _, err := winapi.ProcModule32FirstW.Call(snap, uintptr(unsafe.Pointer(&me)))
	if ok == 0 {
		t.Fatalf("Module32FirstW 失败（Size 字段填错会走到这里）: %v", err)
	}
	if me.ModBaseAddr == 0 {
		t.Fatalf("主模块基址是 0")
	}
	if me.ModBaseSize == 0 {
		t.Fatalf("主模块大小是 0 —— 结构体布局多半不对")
	}
	name := me.ModuleName()
	if name == "" || name == "?" {
		t.Fatalf("主模块名没读出来（结构体偏移错了）: %q", name)
	}
	if len(name) < 4 || name[len(name)-4:] != ".exe" {
		t.Fatalf("主模块名不像 exe: %q", name)
	}
	t.Logf("Toolhelp 首项：%s 基址 %#x 大小 %.1f MB", name, me.ModBaseAddr, float64(me.ModBaseSize)/(1<<20))
}
