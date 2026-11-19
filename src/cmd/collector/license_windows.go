package main

import (
	"context"
	"flag"
	"fmt"
	"local/cs2-radar/internal/dataauth"
	"local/cs2-radar/internal/guyi"
	"local/cs2-radar/internal/startupdiag"
	"local/cs2-radar/internal/uibridge"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
)

var flagLicenseConfig = flag.String("license-config", guyi.DefaultConfigPath(), "GuYi v2 公开授权配置文件")
var flagLicenseCheck = flag.Bool("license-check", false, "仅检查 GuYi 与设备绑定数据授权；不打开网卡、不访问游戏进程")
var flagViewOnly = flag.Bool("view-only", false, "授权后只启动原生回环像素视图，不提权、不开网卡、不访问游戏进程")

type authorizationError struct{ err error }

func (e *authorizationError) Error() string { return startupdiag.Format(e.err) }
func (e *authorizationError) Unwrap() error { return e.err }

type captureLicense struct {
	lease  *guyi.Lease
	remote *dataauth.Client
	ctx    context.Context
	cancel context.CancelFunc
}

func authorizeCapture() (*captureLicense, error) {
	return authorizeCaptureWithCard(context.Background(), "")
}

// The card stays in the native process; neither browser IPC nor argv carries it.
//garble:controlflow block_splits=2 junk_jumps=1 flatten_passes=1
func authorizeCaptureWithCard(parent context.Context, card string) (*captureLicense, error) {
	ctx, cancel := context.WithCancel(parent)
	var l *guyi.Lease
	var e error
	if card == "" {
		l, e = guyi.Open(ctx, *flagLicenseConfig)
	} else {
		l, e = guyi.ActivateAndSave(ctx, *flagLicenseConfig, card)
	}
	if e != nil {
		cancel()
		return nil, &authorizationError{e}
	}
	key, e := l.DataKey()
	if e != nil {
		cancel()
		return nil, &authorizationError{startupdiag.Wrap(startupdiag.DeviceKey, e)}
	}
	remote, e := dataauth.NewClient(*flagUplink, *flagCACert, key)
	if e != nil {
		cancel()
		return nil, &authorizationError{startupdiag.Wrap(startupdiag.DataConfig, e)}
	}
	if e = remote.Login(ctx, l.DataCredential()); e != nil {
		remote.Close()
		cancel()
		return nil, &authorizationError{e}
	}
	return &captureLicense{lease: l, remote: remote, ctx: ctx, cancel: cancel}, nil
}

func (l *captureLicense) watch(s *captureSession) {
	watchUplinkFailure(s, l.cancel)
	if s.ui != nil {
		go func() {
			select {
			case <-s.ui.Failed():
				s.recordDataStop(5, l.remote, nil)
				l.cancel()
				s.Stop()
			case <-s.stopCh:
			}
		}()
	}
	go func() {
		defer l.remote.Close()
		if e := l.remote.Maintain(l.ctx); e != nil {
			s.recordDataStop(3, l.remote, e)
			s.em.emit("data_authorization_denied", map[string]any{"message": "数据授权失效，已停止；需要重新认证"})
			l.cancel()
			s.Stop()
		}
	}()
	go func() {
		select {
		case <-s.stopCh:
			l.cancel()
		case <-l.ctx.Done():
		}
	}()
	go func() {
		defer l.cancel()
		if e := l.lease.Maintain(l.ctx); e != nil {
			s.recordErrorStop(4, e)
			fmt.Fprintln(os.Stderr, "GuYi 授权失效，正在停止：", e)
			s.em.emit("license_denied", map[string]any{"message": e.Error()})
			s.Stop()
		}
	}()
}

func watchUplinkFailure(s *captureSession, cancel context.CancelFunc) {
	// Any failed uplink terminates protected work. Recovery requires a new session;
	// it never instantiates a local parser or silently buffers a continuing stream.
	if remote, ok := s.sender.(interface {
		Failed() <-chan struct{}
		Err() error
	}); ok {
		go func() {
			select {
			case <-s.stopCh:
			case <-remote.Failed():
				s.recordErrorStop(2, remote.Err())
				s.em.emit("uplink_denied", map[string]any{"message": "远端不可用，已停止；不提供本地降级"})
				cancel()
				s.Stop()
			}
		}()
	}
}

func runLicenseCheck() int {
	l, e := authorizeCapture()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	defer l.cancel()
	defer l.remote.Close()
	fmt.Println("GuYi 授权成功，有效期：", l.lease.ExpireTime())
	return 0
}

func (l *captureLicense) send(req *http.Request, body []byte) (*http.Response, error) {
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(l.ctx, cancel)
	defer stop()
	defer cancel()
	if l.ctx.Err() != nil {
		cancel()
	}
	return l.remote.DoBody(req.WithContext(ctx), body)
}

func (s *captureSession) ViewURL() string {
	if s.ui == nil || s.stopped() {
		return ""
	}
	return s.ui.URL()
}

// Read-only native UI mode keeps all card/PoP operations outside the browser.
// It cannot create a local parser or begin packet/process work.
func runViewOnly() int {
	l, e := authorizeCapture()
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		return 1
	}
	defer l.cancel()
	defer l.remote.Close()
	ui, e := uibridge.StartWithLocalMaps(l.ctx, *flagUplink, l.remote, filepath.Join(exeDir(), "maps"))
	if e != nil {
		fmt.Fprintln(os.Stderr, "已授权像素视图不可用")
		return 1
	}
	defer ui.Close()
	go func() {
		if l.remote.Maintain(l.ctx) != nil {
			l.cancel()
		}
	}()
	go func() {
		if l.lease.Maintain(l.ctx) != nil {
			l.cancel()
		}
	}()
	fmt.Println(ui.URL())
	if *flagOpenBrowser {
		openBrowser(ui.URL())
	}
	ctx, stop := signal.NotifyContext(l.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	select {
	case <-ui.Failed():
		return 1
	case <-ctx.Done():
		if l.ctx.Err() != nil {
			return 1
		}
		return 0
	}
}
