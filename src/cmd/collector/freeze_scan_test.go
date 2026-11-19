package main

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"local/cs2-radar/internal/keyfind"
	"local/cs2-radar/internal/memscan"
)

// plantEnv 用来把同一个测试二进制切成两种角色：
//
//	未设置  → 父进程：起子进程、冻结它、搜它的内存
//	设置为 1 → 子进程：埋一对 X25519 密钥、打印公钥、然后长睡
//
// 为什么不用 dist/plantkey.exe：那个 exe 是构建产物，路径随环境变；用自
// 执行（os.Args[0] + -test.run）能让这个测试在任何机器上独立跑通，不依赖
// 事先构建过什么。
const plantEnv = "CS2RADAR_TEST_PLANT"

// helperPrivOffset 是私钥在子进程堆缓冲里的偏移。
//
// 故意不用 0：真实进程里密钥不会正好落在缓冲开头，用一个非零、非对齐的
// 偏移能顺带验证扫描器没有"按 8 字节对齐步进"这类隐藏假设。
const helperPrivOffset = 12345

// TestFreezeScanHelper 只在被父进程以 helper 身份拉起时干活。
//
// 正常情况下（go test ./...）它会 Skip，不占时间。
func TestFreezeScanHelper(t *testing.T) {
	if os.Getenv(plantEnv) != "1" {
		t.Skip("仅作为子进程 helper 运行")
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("ERR=%v\n", err)
		os.Exit(1)
	}
	privB := priv.Bytes()
	pubB := priv.PublicKey().Bytes()

	// 埋进一个大一点的堆缓冲，模拟"密钥散落在堆里"。
	heap := make([]byte, 1<<16)
	copy(heap[helperPrivOffset:], privB)

	// 公钥打到 stdout，父进程据此搜索。必须先 flush 再睡。
	fmt.Printf("PUB=%x\n", pubB)
	os.Stdout.Sync()

	runtime.KeepAlive(heap)
	runtime.KeepAlive(privB)

	// 长睡：父进程冻结我们时不会有任何反应，解冻后继续睡。
	// 这个"被冻住也不影响正确性"正是冻结方案要保证的性质。
	time.Sleep(120 * time.Second)
}

// TestFreezeThenSearchRealProcess 是"真进程 + 真冻结 + 真搜索"的端到端验证。
//
// 覆盖的是用户实际会走的那条路：冻结目标 → 枚举区域 → 扫描 → 找到私钥 →
// 解冻。freeze_test.go 用 fake 只验证控制流，freeze_real_test.go 只验证
// 冻结本身有效；这个测试把两件事合起来，回答"冻结着搜能不能真的搜到"。
func TestFreezeThenSearchRealProcess(t *testing.T) {
	if os.Getenv(plantEnv) == "1" {
		t.Skip("父进程侧用例")
	}
	if runtime.GOOS != "windows" {
		t.Skip("依赖 Windows 的 NtSuspendProcess / ReadProcessMemory")
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestFreezeScanHelper$")
	cmd.Env = append(os.Environ(), plantEnv+"=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("取子进程 stdout: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("起子进程: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	// 读公钥。不用 -test.v，所以 stdout 里不会有 "=== RUN" 之类的行，
	// 但仍然逐行扫，避免 testing 包将来加输出把解析弄坏。
	pub, err := readPlantedPub(bufio.NewReader(stdout), 15*time.Second)
	if err != nil {
		t.Fatalf("读子进程公钥: %v（stderr: %s）", err, stderr.String())
	}
	t.Logf("子进程 pid=%d，公钥 %x…", cmd.Process.Pid, pub[:8])

	proc, err := memscan.OpenForRead(uint32(cmd.Process.Pid))
	if err != nil {
		t.Fatalf("OpenForRead: %v", err)
	}
	defer proc.Close()

	kf := keyfind.New(proc, pub, time.Now().Add(30*time.Second))
	kf.MaxCandidates = 8_000_000
	var (
		foundPriv []byte
		foundTag  string
		foundAddr uintptr
	)
	kf.OnFound = func(p []byte, tag string, a uintptr) {
		foundPriv = append([]byte(nil), p...)
		foundTag, foundAddr = tag, a
	}

	st := new(scanStat)
	fo := freezeRun(proc, 25*time.Second, func() {
		regions, rerr := proc.RegionsWithError(time.Now().Add(10*time.Second), 0)
		if rerr != nil && rerr != memscan.ErrRegionDeadline && rerr != memscan.ErrRegionLimit {
			t.Logf("枚举区域: %v", rerr)
		}
		ordered := sortRegionsForScan(regions)
		scanRangesStat(kf, proc, writableRanges(ordered), time.Now().Add(25*time.Second), st)
	})

	t.Logf("冻结情况：%s", fo)
	t.Logf("扫描统计：%s", st.summary())

	// ── 安全断言（比"找到没"更重要）──
	if !fo.Froze {
		t.Errorf("没冻上：%v —— 冻结链路本身失效", fo.FreezeErr)
	}
	if fo.ThawErr != nil {
		t.Errorf("解冻失败：%v —— 这在实际使用中意味着用户的游戏会一直卡住", fo.ThawErr)
	}
	if fo.Forced {
		t.Errorf("被看门狗强制解冻（持有 %s）—— 说明扫描没在 25 秒内跑完", fo.Hold)
	}
	if fo.Panicked {
		t.Error("fn panic 了")
	}

	// ── 功能断言 ──
	if len(foundPriv) != 32 {
		t.Fatalf("没找到私钥（校验 %d 次，读 %d 字节）", kf.Stats()["checks"], st.bytes.Load())
	}
	got, err := ecdh.X25519().NewPrivateKey(foundPriv)
	if err != nil {
		t.Fatalf("找到的 32 字节不是合法 X25519 私钥: %v", err)
	}
	if !bytes.Equal(got.PublicKey().Bytes(), pub) {
		t.Fatalf("找到的私钥推导出的公钥不匹配")
	}
	t.Logf("命中：tag=%s addr=%#x（冻结状态下搜到）", foundTag, foundAddr)
}

// readPlantedPub 从子进程 stdout 里读出 PUB=<hex> 那一行。
func readPlantedPub(r *bufio.Reader, timeout time.Duration) ([]byte, error) {
	type res struct {
		pub []byte
		err error
	}
	ch := make(chan res, 1)
	go func() {
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				ch <- res{nil, err}
				return
			}
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ERR=") {
				ch <- res{nil, fmt.Errorf("子进程报错: %s", line)}
				return
			}
			hexStr, ok := strings.CutPrefix(line, "PUB=")
			if !ok {
				continue
			}
			pub, derr := hex.DecodeString(hexStr)
			if derr != nil {
				ch <- res{nil, derr}
				return
			}
			ch <- res{pub, nil}
			return
		}
	}()
	select {
	case v := <-ch:
		return v.pub, v.err
	case <-time.After(timeout):
		return nil, fmt.Errorf("等 PUB 行超时（%s）", timeout)
	}
}
