// Windows console activation helper. No application/management secret is used.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"local/cs2-radar/internal/guyi"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

func readCard() (string, error) {
	fmt.Print("请输入卡密（输入隐藏，回车确认）：")
	k := syscall.NewLazyDLL("kernel32.dll")
	get := k.NewProc("GetConsoleMode")
	set := k.NewProc("SetConsoleMode")
	h := os.Stdin.Fd()
	var mode uint32
	r, _, _ := get.Call(h, uintptr(unsafe.Pointer(&mode)))
	if r != 0 {
		ok, _, _ := set.Call(h, uintptr(mode&^4))
		if ok == 0 {
			return "", fmt.Errorf("无法隐藏卡密输入")
		}
		defer set.Call(h, uintptr(mode))
	}
	line, e := bufio.NewReaderSize(io.LimitReader(os.Stdin, 128), 128).ReadString('\n')
	fmt.Println()
	if e != nil {
		return "", e
	}
	return strings.TrimSpace(line), nil
}

func main() {
	fs := flag.NewFlagSet("guyi-license", flag.ExitOnError)
	path := fs.String("config", guyi.DefaultConfigPath(), "公开授权配置文件")
	args := os.Args[1:]
	action := "activate"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		action = args[0]
		args = args[1:]
	}
	fs.Parse(args)
	if fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "卡密只能通过交互输入，不接受位置参数。")
		os.Exit(2)
	}
	if _, e := guyi.LoadConfig(*path); e != nil {
		fmt.Fprintln(os.Stderr, "授权配置错误：", e)
		os.Exit(1)
	}
	ctx := context.Background()
	var l *guyi.Lease
	var e error
	switch action {
	case "activate":
		var card string
		card, e = readCard()
		if e == nil {
			l, e = guyi.ActivateAndSave(ctx, *path, card)
		}
	case "check", "unbind":
		l, e = guyi.Open(ctx, *path)
	default:
		fmt.Fprintln(os.Stderr, "用法: guyi-license.exe activate|check|unbind [-config license.json]")
		os.Exit(2)
	}
	if e == nil && action == "unbind" {
		e = l.Unbind(ctx)
		if e == nil {
			fmt.Println("已解绑并删除本机卡密；服务端按规则扣时/冷却。")
			return
		}
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "授权失败：", e)
		os.Exit(1)
	}
	fmt.Println("授权成功，有效期：", l.ExpireTime())
}
