package restrictedreplay

import (
	"os"
	"syscall"
)

func trustedConfig(fi os.FileInfo) bool {
	s, ok := fi.Sys().(*syscall.Stat_t)
	return ok && s.Uid == 0 && fi.Mode().Perm()&0137 == 0 // root-owned, at most0640
}
func privateDirectory(fi os.FileInfo) bool {
	s, ok := fi.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Geteuid()) && fi.Mode().Perm() == 0700
}
