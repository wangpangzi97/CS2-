// Command keyscan 用重构出来的 keyfind 搜索指定进程里的 X25519 私钥。
//
// 用法：
//
//	keyscan.exe -pid 1234 -pub <64 位十六进制公钥> [-expect <64 位十六进制私钥>]
//
// 它走的是与原程序完全相同的路径：OpenProcess(0xC10) → VirtualQueryEx 枚举区域
// → scanHints / scanAnchors / scanWindows → verifyPriv(X25519 标量乘比对)。
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"time"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

var (
	flagPID    = flag.Int("pid", 0, "目标进程 PID")
	flagPub    = flag.String("pub", "", "目标 X25519 公钥（hex，32 字节）")
	flagExpect = flag.String("expect", "", "预期私钥（hex），用于自动判定 PASS/FAIL")
	flagBudget = flag.Uint64("budget", 4_000_000, "候选预算上限")
	flagLimit  = flag.Int("limit", 0, "只扫前 N 个可读区域（0=全部）")
)

func main() {
	flag.Parse()
	if *flagPID == 0 || *flagPub == "" {
		flag.Usage()
		os.Exit(2)
	}
	pub, err := hex.DecodeString(*flagPub)
	if err != nil || len(pub) != 32 {
		fmt.Fprintln(os.Stderr, "pub 必须是 64 位十六进制（32 字节）")
		os.Exit(2)
	}

	proc, err := memscan.OpenForRead(uint32(*flagPID))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer proc.Close()

	regions, err := proc.RegionsWithError(time.Now().Add(30*time.Second), 0)
	if err != nil && err != memscan.ErrRegionDeadline {
		fmt.Fprintf(os.Stderr, "regions: %v\n", err)
	}
	if *flagLimit > 0 && len(regions) > *flagLimit {
		regions = regions[:*flagLimit]
	}
	var total uint64
	for _, r := range regions {
		total += uint64(r.Size)
	}
	fmt.Printf("pid=%d readable_regions=%d readable_bytes=%d\n", *flagPID, len(regions), total)

	s := keyfind.New(proc, pub, time.Now().Add(5*time.Minute))
	s.MaxCandidates = *flagBudget
	start := time.Now()
	priv, tag, addr, err := s.FindPrivWithHints(regions)
	elapsed := time.Since(start)
	st := s.Stats()
	fmt.Printf("stats=%v\n", st)
	if err != nil {
		fmt.Printf("RESULT=NOT_FOUND err=%v elapsed=%s\n", err, elapsed)
		os.Exit(1)
	}
	fmt.Printf("FOUND tag=%s addr=%#x priv=%s elapsed=%s\n", tag, addr, hex.EncodeToString(priv), elapsed)
	if *flagExpect != "" {
		exp, _ := hex.DecodeString(*flagExpect)
		if string(exp) == string(priv) {
			fmt.Println("VERDICT=PASS 搜索到的私钥与预埋值逐字节一致")
			return
		}
		fmt.Println("VERDICT=FAIL 搜索到的私钥与预埋值不一致")
		os.Exit(1)
	}
}
