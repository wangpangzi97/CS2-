// Package startupdiag exposes only allowlisted stage/reason codes. Raw server,
// proxy, URL, device, card and credential error text must never reach the UI.
package startupdiag

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
)

type Stage string

const (
	Config           Stage = "C01"
	Fingerprint      Stage = "C02"
	DeviceKey        Stage = "C03"
	SavedCard        Stage = "C04"
	SaveCard         Stage = "C05"
	TLSConfig        Stage = "C06"
	CardInput        Stage = "A00"
	LicenseConfig    Stage = "A01"
	Activation       Stage = "A02"
	LicenseHeartbeat Stage = "A03"
	DataConfig       Stage = "D01"
	DataChallenge    Stage = "D02"
	DataLogin        Stage = "D03"
	ViewMaps         Stage = "V01"
	ViewFrame        Stage = "V02"
	ViewListener     Stage = "V03"
	Sender           Stage = "U01"
	Policy           Stage = "P01"
	Capture          Stage = "P02"
)

var stages = map[Stage]string{
	Config:           "授权配置无效，请完整解压配套客户端。",
	Fingerprint:      "本机设备标识读取失败。",
	DeviceKey:        "本机设备凭据不可用，请运行设备凭据诊断查看具体原因。",
	SavedCard:        "尚未激活或凭据不可读，请在 gamesense 主程序登录界面输入卡密。",
	SaveCard:         "授权已通过，但本机加密保存失败。",
	TLSConfig:        "HTTPS 客户端配置无效，请检查配套配置与 CA 文件。",
	CardInput:        "卡密输入格式无效。",
	LicenseConfig:    "授权配置请求未通过。",
	Activation:       "卡密激活请求未通过。",
	LicenseHeartbeat: "首次授权心跳未通过。",
	DataConfig:       "数据服务配置或本机设备密钥无效。",
	DataChallenge:    "数据会话挑战未通过。",
	DataLogin:        "数据会话登录未通过。",
	ViewMaps:         "已授权，但地图目录请求未通过。",
	ViewFrame:        "已授权，但初始像素视图未通过。",
	ViewListener:     "本机回环视图端口启动失败。",
	Sender:           "已授权，但上行初始化失败。",
	Policy:           "启动参数不符合生产安全策略。",
	Capture:          "已授权，但本机采集未启动；请检查管理员权限和可用网卡。",
}

type Error struct {
	Stage Stage
	Cause error
}

func (e *Error) Error() string { return Format(e) }
func (e *Error) Unwrap() error { return e.Cause }
func Wrap(stage Stage, e error) error {
	if e == nil {
		return nil
	}
	return &Error{stage, e}
}

// HTTPFailure retains errors.Is semantics without returning the response body.
type HTTPFailure struct {
	Status int
	Cause  error
}

func (e *HTTPFailure) Error() string   { return fmt.Sprintf("HTTP %d", safeStatus(e.Status)) }
func (e *HTTPFailure) Unwrap() error   { return e.Cause }
func (e *HTTPFailure) HTTPStatus() int { return safeStatus(e.Status) }
func safeStatus(n int) int {
	if n >= 100 && n <= 599 {
		return n
	}
	return 0
}

type networkError struct {
	kind  string
	cause error
}

func (e *networkError) Error() string { return "network failure: " + e.kind }
func (e *networkError) Unwrap() error { return e.cause }

// Network classifies typed errors, never substrings of arbitrary messages.
func Network(err error) error {
	if err == nil {
		return nil
	}
	kind := "NETWORK"
	var op *net.OpError
	var ne net.Error
	var cv *tls.CertificateVerificationError
	var ua x509.UnknownAuthorityError
	var hn x509.HostnameError
	var ci x509.CertificateInvalidError
	var dns *net.DNSError
	switch {
	case errors.As(err, &op) && op.Op == "proxyconnect":
		kind = "PROXY"
	case errors.As(err, &cv) || errors.As(err, &ua) || errors.As(err, &hn) || errors.As(err, &ci):
		kind = "TLS"
	case errors.Is(err, context.Canceled):
		kind = "CANCEL"
	case errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()):
		kind = "TIMEOUT"
	case errors.As(err, &dns):
		kind = "DNS"
	}
	return &networkError{kind, err}
}
func Format(err error) string {
	if err == nil {
		return ""
	}
	stage := Stage("")
	text := "启动未通过，请反馈此错误码，不要发送卡密或密钥。"
	code := "X00"
	var se *Error
	if errors.As(err, &se) {
		if t, ok := stages[se.Stage]; ok {
			stage = se.Stage
			code = string(stage)
			text = t
		}
	}
	if stage == DeviceKey {
		var local interface{ LocalDeviceReason() string }
		reasons := map[string]string{
			"PROFILE":         "无法取得当前 Windows 账号的配置目录。",
			"READ":            "设备凭据读取失败，请检查同一 Windows 账号、权限及并发启动。",
			"FILE-TYPE":       "凭据或目录类型异常，拒绝自动重建。",
			"STATE-SIZE":      "设备凭据为空或大小异常；可显式备份后重建。",
			"DPAPI-OPEN":      "当前 Windows 账号无法解密设备凭据；不是卡密校验失败。",
			"KEY-FORMAT":      "解密后的设备密钥格式无效；可显式备份后重建。",
			"DPAPI-SEAL":      "Windows DPAPI 加密失败，请检查当前账号配置文件。",
			"DPAPI-ROUNDTRIP": "Windows DPAPI 自检失败，暂不重建设备凭据。",
			"DIR":             "无法创建设备凭据目录，请检查当前账号配置目录权限。",
			"CREATE":          "设备凭据创建失败，请退出重复客户端并检查目录写入权限。",
			"WRITE":           "设备凭据写入失败，请检查磁盘和当前账号权限。",
			"SYNC":            "设备凭据落盘失败，请检查磁盘或配置目录。",
			"CLOSE":           "设备凭据保存关闭失败，请检查磁盘或配置目录。",
			"RANDOM":          "安全随机数生成失败。",
			"VALID-REFUSED":   "现有设备密钥有效，拒绝重建；不应通过换卡来重置它。",
			"ARCHIVE":         "旧密文备份失败；未执行重建，请检查并发启动和权限。",
			"CHANGED":         "凭据在检查期间变化，已停止；请退出所有客户端后重试。",
		}
		if errors.As(err, &local) {
			if message, ok := reasons[local.LocalDeviceReason()]; ok {
				code += "/" + local.LocalDeviceReason()
				text = message
			}
		}
		var win interface{ Win32Code() uint32 }
		if errors.As(err, &win) && win.Win32Code() != 0 {
			code += fmt.Sprintf("/WIN32-%d", win.Win32Code())
		}
	}
	var n *networkError
	if errors.As(err, &n) {
		switch n.kind {
		case "PROXY":
			code += "/NET-PROXY"
			text = "代理连接失败，请检查本机代理是否运行及 HTTPS_PROXY/HTTP_PROXY 设置。"
		case "TLS":
			code += "/NET-TLS"
			text = "HTTPS 证书验证失败，请检查系统时间、Windows 根证书及网络拦截；不要关闭验证。"
		case "TIMEOUT":
			code += "/NET-TIMEOUT"
			text = "连接超时，请检查网络与服务器 443 端口。"
		case "CANCEL":
			code += "/NET-CANCEL"
			text = "请求已取消，请重新点击登录。"
		case "DNS":
			code += "/NET-DNS"
			text = "网络地址解析失败，请检查代理和 DNS。"
		default:
			code += "/NET-CONNECT"
			text = "连接失败，请检查网络、代理及服务器 443 端口。"
		}
	} else {
		var h interface{ HTTPStatus() int }
		if errors.As(err, &h) && safeStatus(h.HTTPStatus()) != 0 {
			status := h.HTTPStatus()
			code += fmt.Sprintf("/HTTP-%d", status)
			if stage == Activation || stage == LicenseHeartbeat {
				text = "授权服务器拒绝此阶段；检查卡密、应用、绑定、有效期和系统时间。"
			}
			if status == 429 {
				text = "请求过于频繁，请稍后再试。"
			}
		} else if stage == Capture && (errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.Errno(10013))) {
			code += "/ACCESS"
		}
	}
	return "[GS-" + code + "] " + text
}
