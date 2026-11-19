package main

import (
	"encoding/json"
	"flag"
	"io"
	"local/cs2-radar/internal/guyi"
	"local/cs2-radar/internal/startupdiag"
)

var flagDeviceCheck = flag.Bool("device-check", false, "本机 DPAPI 与设备凭据诊断；不读取卡密、不联网、不采集")
var flagDeviceRepair = flag.Bool("archive-invalid-device-key", false, "显式备份损坏或当前账号无法解密的本机设备密文；拒绝有效密钥，不修改服务器绑定")

func runDeviceCheck(w io.Writer, repair bool) int {
	var report guyi.DeviceCheckReport
	c, e := guyi.LoadConfig(*flagLicenseConfig)
	if e != nil {
		report = guyi.DeviceCheckReport{Version: "gamesense-20261024-v8-device", State: "UNKNOWN", Result: startupdiag.Format(startupdiag.Wrap(startupdiag.Config, e))}
	} else if repair {
		report = guyi.ArchiveInvalidLocalDevice(c)
	} else {
		report = guyi.CheckLocalDevice(c)
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	encoder.SetEscapeHTML(false)
	if encoder.Encode(report) != nil {
		return 2
	}
	if report.State == "VALID" || report.State == "MISSING" || report.State == "ARCHIVED" {
		return 0
	}
	return 1
}
