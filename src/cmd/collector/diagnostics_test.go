package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProductionDiagnosticCollectorSinks(t *testing.T) {
	t.Chdir(t.TempDir())
	if writeJSONFile("fixture", map[string]any{"private_key": "SYNTHETIC_ONLY"}) != "" {
		t.Fatal("key dump enabled")
	}
	var s *captureSession
	if s.writeDiagnose("fixture.txt") == nil {
		t.Fatal("diagnostic report enabled")
	}
	files, err := os.ReadDir(".")
	if err != nil || len(files) != 0 {
		t.Fatalf("diagnostic file created: %v %v", files, err)
	}
	oldOut, oldErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout, os.Stderr = w, w
	privateDiagnosticf("private_key=%s", "SYNTHETIC_ONLY")
	em := &emitter{ipc: true}
	em.emit("key_attached", map[string]any{"private_key": "SYNTHETIC_ONLY"})
	em.emit("capture_stats", map[string]any{"packets": uint64(3), "bytes": uint64(7), "private_key": "SYNTHETIC_ONLY"})
	w.Close()
	os.Stdout, os.Stderr = oldOut, oldErr
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil || strings.Contains(string(b), "SYNTHETIC_ONLY") {
		t.Fatalf("secret output: %d bytes %v", len(b), err)
	}
	if !strings.Contains(string(b), "packets=3 bytes=7") {
		t.Fatal("safe numeric counters unavailable")
	}
}

func TestProductionDiagnosticFlagsBeforeAuthorization(t *testing.T) {
	ipc, dump, diag, log, freeze, hints := *flagIPC, *flagDump, *flagDiagnose, *flagLogFile, *flagUIFreeze, *flagHintsInfo
	t.Cleanup(func() {
		*flagIPC, *flagDump, *flagDiagnose, *flagLogFile, *flagUIFreeze, *flagHintsInfo = ipc, dump, diag, log, freeze, hints
	})
	reset := func() {
		*flagIPC, *flagDump, *flagDiagnose, *flagLogFile, *flagUIFreeze, *flagHintsInfo = false, "", "", "", 0, false
	}
	reset()
	if productionDiagnosticsPolicy() != nil {
		t.Fatal("safe defaults rejected")
	}
	for _, set := range []func(){func() { *flagIPC = true }, func() { *flagDump = "fixture" }, func() { *flagDiagnose = "fixture" }, func() { *flagLogFile = "fixture" }, func() { *flagUIFreeze = 1 }, func() { *flagHintsInfo = true }} {
		reset()
		set()
		if productionDiagnosticsPolicy() == nil {
			t.Fatal("sensitive flag accepted")
		}
		// This must return before licensing, UI, socket or process access.
		if s, err := startCapture(&emitter{}); err == nil || s != nil {
			t.Fatal("capture reached with sensitive diagnostic flag")
		}
	}
}

func TestProductionDiagnosticCollectorSourceBoundary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			if id.Name == "os" && (sel.Sel.Name == "Create" || sel.Sel.Name == "WriteFile" || sel.Sel.Name == "OpenFile") || id.Name == "runtime" && sel.Sel.Name == "Stack" || id.Name == "transport" && (sel.Sel.Name == "Write" || sel.Sel.Name == "EncodeEvent") {
				t.Errorf("%s: sensitive sink reintroduced: %s.%s", p, id.Name, sel.Sel.Name)
			}
			return true
		})
	}
}
