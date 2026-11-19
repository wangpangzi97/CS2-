//go:build !linux

package restrictedreplay

import "os"

// Production consent loading is Linux-only. Offline unit tests can exercise the
// bounded sink in disposable directories; that does not verify Windows ACLs.
func trustedConfig(os.FileInfo) bool    { return false }
func privateDirectory(os.FileInfo) bool { return true }
