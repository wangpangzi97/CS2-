package radarsrv

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"testing"

	"local/cs2-radar/internal/cs2crypto"
)

func TestProductionDiagnosticsDiscard(t *testing.T) {
	t.Chdir(t.TempDir())
	// nil handshake must be safe: the retired sinks do not inspect input.
	if dumpGNSDiag("", nil, nil, nil, "", 0) != "" || dumpFrameHeads("", nil, nil, nil) != "" {
		t.Fatal("retired dump returned a file")
	}
	h := &cs2crypto.GNSHandshake{ClientPub: []byte("SYNTHETIC_ONLY")}
	if dumpGNSDiag("fixture", h, []byte("SYNTHETIC_ONLY"), nil, "", 0) != "" {
		t.Fatal("secret dump enabled")
	}
	s := &Session{plainWant: true}
	s.savePlain([]string{"SYNTHETIC_ONLY"})
	s.savePlainBin([][]byte{[]byte("SYNTHETIC_ONLY")})
	s.noteSignonStream([]byte("SYNTHETIC_ONLY"))
	s.unrelDump = []byte("SYNTHETIC_ONLY")
	s.unrelHead = []msgHead{{head: []byte("SYNTHETIC_ONLY")}}
	s.saveUnrel()
	if s.plainWant || !s.plainDone || !s.signonDone || len(s.plainBuf)+len(s.plainBin)+len(s.signonDump)+len(s.unrelDump)+len(s.unrelHead) != 0 {
		t.Fatal("retired diagnostic buffers retained data")
	}
	files, err := os.ReadDir(".")
	if err != nil || len(files) != 0 {
		t.Fatalf("diagnostic files: %v %v", files, err)
	}
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	gnsLogf("secret=%s", "SYNTHETIC_ONLY")
	w.Close()
	os.Stderr = old
	b, err := io.ReadAll(r)
	r.Close()
	if err != nil || len(b) != 0 {
		t.Fatalf("sensitive logger emitted bytes: %d %v", len(b), err)
	}
	cfg := DefaultConfig()
	cfg.DebugSlots = true
	if NewStore(cfg).Get("fixture").decoder.OnNewSlot != nil {
		t.Fatal("raw position callback enabled")
	}
}

// Guard the package, not only the current sink names, against accidentally
// restoring persistence or diagnostic-only payload accumulation later.
func TestProductionDiagnosticSourceBoundary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	protected := map[string]bool{"plainBuf": true, "plainBin": true, "signonDump": true, "unrelDump": true, "netchan": true, "msgFramed": true, "unrelHead": true, "msgHeads": true}
	for _, path := range files {
		if filepath.Ext(path) != ".go" || len(path) >= 8 && path[len(path)-8:] == "_test.go" {
			continue
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if id, ok := sel.X.(*ast.Ident); ok && id.Name == "os" && (sel.Sel.Name == "WriteFile" || sel.Sel.Name == "Create" || sel.Sel.Name == "OpenFile") {
					t.Errorf("%s: persistence API reintroduced: os.%s", path, sel.Sel.Name)
				}
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "append" && len(call.Args) != 0 {
				if sel, ok := call.Args[0].(*ast.SelectorExpr); ok && protected[sel.Sel.Name] {
					t.Errorf("%s: diagnostic retention reintroduced: %s", path, sel.Sel.Name)
				}
			}
			return true
		})
	}
}
