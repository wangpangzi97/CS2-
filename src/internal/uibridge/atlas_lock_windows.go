package uibridge

import (
	"os"
	"syscall"
	"unsafe"
)

var atlasLockFileEx = syscall.NewLazyDLL("kernel32.dll").NewProc("LockFileEx")

func acquireAtlasLock(f *os.File) error {
	var o syscall.Overlapped
	r, _, e := atlasLockFileEx.Call(f.Fd(), 3, 0, 1, 0, uintptr(unsafe.Pointer(&o)))
	if r == 0 {
		return e
	}
	return nil
}
