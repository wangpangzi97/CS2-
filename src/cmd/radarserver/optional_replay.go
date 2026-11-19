package main

import (
	"local/cs2-radar/internal/restrictedreplay"
	"log"
)

// Optional diagnostics fail closed for capture, not for the independent normal
// service. All required authority/TLS startup checks remain in main unchanged.
func optionalReplay(path string) *restrictedreplay.Capture {
	if path == "" {
		return nil
	}
	capture, err := restrictedreplay.Load(path)
	if err != nil {
		// Fixed message only: do not log private paths, configuration or error text.
		log.Print("restricted replay not armed; continuing normal authorized service")
		return nil
	}
	return capture
}
