//go:build !windows

package uibridge

import (
	"os"
	"syscall"
)

func acquireAtlasLock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
