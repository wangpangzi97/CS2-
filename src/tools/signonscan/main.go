// signonscan 离线重跑 signon 段解析，用来验证扫描规则。
//
// 用法：
//
//	signonscan.exe gns-signon-20261020-082739.bin
//
// 现场那份 283892 字节的 signon 落盘产物可以直接喂进来，
// 不用再打一局就知道「字符串表扫到了几张、哪几张、snappy 解出多少字节」。
package main

import (
	"fmt"
	"os"

	"local/cs2-radar/internal/radarsrv"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "用法: signonscan <gns-signon-*.bin>")
		os.Exit(2)
	}
	buf, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "读文件失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("文件 %s  %d 字节\n", os.Args[1], len(buf))
	fmt.Println(radarsrv.GNSSignonReport(buf))
}
