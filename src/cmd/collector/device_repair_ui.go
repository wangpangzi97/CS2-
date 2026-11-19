package main

import (
	"local/cs2-radar/internal/guyi"
	"local/cs2-radar/internal/startupdiag"
	"runtime"
	"unsafe"
)

// Only the dedicated offline helper build sets this. No shell, account switching,
// elevation, card loading, server access or capture is needed for this path.
var defaultDeviceRepairMode = "false"

func deviceRepairFlow(check, archive func() guyi.DeviceCheckReport, confirm func() bool) guyi.DeviceCheckReport {
	r := check()
	if !r.CanArchiveInvalid {
		return r
	}
	if !confirm() {
		r.State = "CANCELLED"
		r.Result = "[GS-C03/CANCELLED] 已取消，现有设备凭据未更改。"
		return r
	}
	return archive()
}
func nativeRepairConfirm() bool {
	text := "无需切换 Windows 账号。请先关闭所有 gamesense 客户端。\n\n当前账号无法解密或验证现有设备凭据。是否仅将无效设备密文原样备份？\n\n不会删除已保存卡密，不会修改服务器绑定，也不会立即生成新密钥。有效设备密钥会被拒绝重建。\n\n设备密钥由本机同应用共用；后续生成新密钥后，已有卡密的服务器公钥绑定可能仍需管理员处理。\n\n选择“是”备份，选择“否”保持不动。"
	// MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND.
	r, _, _ := pMessageBoxW.Call(0, uintptr(unsafe.Pointer(utf16(text))), uintptr(unsafe.Pointer(utf16("gamesense · 设备凭据修复确认"))), 0x4|0x30|0x100|0x10000)
	return r == 6
}
func runDeviceRepairUI() int {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var r guyi.DeviceCheckReport
	c, e := guyi.LoadConfig(guyi.DefaultConfigPath())
	if e != nil {
		r = guyi.DeviceCheckReport{Version: "gamesense-20261024-v8-device", State: "UNKNOWN", Result: startupdiag.Format(startupdiag.Wrap(startupdiag.Config, e))}
	} else {
		r = deviceRepairFlow(func() guyi.DeviceCheckReport { return guyi.CheckLocalDevice(c) }, func() guyi.DeviceCheckReport { return guyi.ArchiveInvalidLocalDevice(c) }, nativeRepairConfirm)
	}
	note := "\n\n请截图此结果窗口发回；不要发送设备密文、备份、卡密或密钥。"
	switch r.State {
	case "ARCHIVED":
		note = "\n\n旧密文已保留。现在关闭本工具，运行 gamesense.exe，手动输入你要使用的新卡密。服务器绑定未改变。" + note
	case "VALID":
		note = "\n\n当前账号设备凭据有效，没有执行重建。请反馈客户端的新错误码。" + note
	case "MISSING":
		note = "\n\n当前账号没有旧设备凭据，无需重建。运行 gamesense.exe 并手动输入卡密。" + note
	}
	messageBox("gamesense · 设备凭据处理结果", r.Result+note, mbOK|0x10000)
	if r.State == "ARCHIVED" || r.State == "VALID" || r.State == "MISSING" || r.State == "CANCELLED" {
		return 0
	}
	return 1
}
