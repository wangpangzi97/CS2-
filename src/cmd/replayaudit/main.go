// Offline private-file classifier replay; never connects to a server or emits raw messages.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"local/cs2-radar/internal/radarsrv"
	"os"
)

func main() {
	path := flag.String("input", "", "private GSRPLY01 file; gameplay plaintext, not the ordinary diagnostic.bin")
	flag.Parse()
	if *path == "" || flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "one private replay input required")
		os.Exit(64)
	}
	f, e := os.Open(*path)
	if e != nil {
		fmt.Fprintln(os.Stderr, "private replay unavailable")
		os.Exit(1)
	}
	defer f.Close()
	out, e := radarsrv.AuditRestrictedReplay(f)
	if e != nil {
		fmt.Fprintln(os.Stderr, "invalid or incomplete replay file")
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(1)
	}
}
