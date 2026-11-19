package dataauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// CommandAuthority invokes a fixed, root-owned PHP CLI adapter without a shell.
// Paths/app id are startup configuration, never selected by a network request.
type CommandAuthority struct {
	PHP, Script, Project string
	AppID                int
	slots                chan struct{}
	once                 sync.Once
}
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.limit {
		return 0, errors.New("adapter output limit")
	}
	return b.Buffer.Write(p)
}
func (a *CommandAuthority) call(ctx context.Context, in any) (Identity, error) {
	if !filepath.IsAbs(a.PHP) || !filepath.IsAbs(a.Script) || !filepath.IsAbs(a.Project) || a.AppID < 1 {
		return Identity{}, ErrUnavailable
	}
	a.once.Do(func() { a.slots = make(chan struct{}, 4) })
	select {
	case a.slots <- struct{}{}:
		defer func() { <-a.slots }()
	case <-ctx.Done():
		return Identity{}, ErrUnavailable
	}
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 8192 {
		return Identity{}, ErrDenied
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, a.PHP, a.Script, a.Project, strconv.Itoa(a.AppID))
	cmd.Stdin = bytes.NewReader(raw)
	out := &cappedBuffer{limit: 4096}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	if e = cmd.Run(); e != nil {
		return Identity{}, ErrUnavailable
	}
	var answer struct {
		OK       bool     `json:"ok"`
		Identity Identity `json:"identity"`
		Error    string   `json:"error"`
	}
	if strictJSON(out.Bytes(), &answer) != nil {
		return Identity{}, ErrUnavailable
	}
	if !answer.OK {
		if answer.Error == "denied" {
			return Identity{}, ErrDenied
		}
		return Identity{}, ErrUnavailable
	}
	return answer.Identity, nil
}
func (a *CommandAuthority) Enroll(ctx context.Context, e Enrollment) (Identity, error) {
	return a.call(ctx, map[string]any{"op": "enroll", "enrollment": e})
}
func (a *CommandAuthority) Check(ctx context.Context, i Identity, ip string) (Identity, error) {
	return a.call(ctx, map[string]any{"op": "check", "identity": i, "ip": ip})
}

func (a *CommandAuthority) Ready(ctx context.Context) error {
	_, e := a.call(ctx, map[string]string{"op": "probe"})
	return e
}
