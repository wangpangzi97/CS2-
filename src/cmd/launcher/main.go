// The old HTTP/SSE + stdout-packet launcher is deliberately retired.
// No arguments, including old credentials, may start it or be echoed back.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "LEGACY_LAUNCHER_RETIRED: use the native gamesense collector GUI; old IPC/SSE launch is disabled.")
	os.Exit(2)
}
