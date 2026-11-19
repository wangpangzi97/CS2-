package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"local/cs2-radar/internal/guyi"
	"local/cs2-radar/internal/startupdiag"
	"net/http"
	"os"
	"runtime"
	"time"
)

var flagConnectionCheck = flag.Bool("connection-check", false, "仅诊断公开授权配置的 HTTPS 连通性；不读卡密、设备凭据，不提权、不采集、不访问游戏")

func runConnectionCheck(w io.Writer) int {
	report := struct {
		Version         string `json:"diagnostic_version"`
		SystemTime      string `json:"system_time"`
		Platform        string `json:"platform"`
		StrictTLS       bool   `json:"strict_tls"`
		ProxyEnvPresent bool   `json:"proxy_environment_present"`
		ProxySelected   bool   `json:"proxy_selected"`
		CardUsed        bool   `json:"card_used"`
		CaptureStarted  bool   `json:"capture_started"`
		OK              bool   `json:"public_config_ok"`
		Result          string `json:"result"`
	}{Version: "gamesense-20261024-v8", SystemTime: time.Now().Format(time.RFC3339), Platform: runtime.GOOS + "/" + runtime.GOARCH, StrictTLS: true}
	for _, key := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		if os.Getenv(key) != "" {
			report.ProxyEnvPresent = true
		}
	}
	c, e := guyi.LoadConfig(*flagLicenseConfig)
	if e != nil {
		e = startupdiag.Wrap(startupdiag.Config, e)
	} else {
		if req, err := http.NewRequest("POST", c.Endpoint, nil); err == nil {
			p, err := http.ProxyFromEnvironment(req)
			report.ProxySelected = err == nil && p != nil
		}
		var client *guyi.Client
		client, e = guyi.New(c)
		if e != nil {
			e = startupdiag.Wrap(startupdiag.TLSConfig, e)
		} else {
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			e = client.CheckConnection(ctx)
			cancel()
		}
	}
	if e != nil {
		report.Result = startupdiag.Format(e)
	} else {
		report.OK = true
		report.Result = "[GS-A01/OK] 公开授权配置请求成功；不代表真实卡密或采集已通过。"
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if encoder.Encode(report) != nil {
		return 2
	}
	if e != nil {
		return 1
	}
	return 0
}
