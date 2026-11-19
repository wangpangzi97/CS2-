// Command plantkey 是验证用靶标：把一个已知的 32 字节 X25519 私钥放进自己的内存，
// 打印公钥与 PID 后挂起等待，供 keyscan 去搜索。
//
// 它不依赖任何逆向知识，只是"被搜的进程"。
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

func main() {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	privBytes := priv.Bytes()
	pubBytes := priv.PublicKey().Bytes()

	// 把私钥埋进一个较大的堆缓冲，模拟真实进程里"密钥散落在堆中"的情形
	heap := make([]byte, 8<<20)
	if _, err := rand.Read(heap); err != nil {
		panic(err)
	}
	off := 3<<20 + 4096
	copy(heap[off:], privBytes)
	// 再散落一份到另一个位置（走 hint 之外的路径）
	copy(heap[off+1<<20:], privBytes)
	// 防止编译器把 heap 优化掉
	sink = heap

	fmt.Printf("pid=%d\n", os.Getpid())
	fmt.Printf("pub=%s\n", hex.EncodeToString(pubBytes))
	fmt.Printf("priv=%s\n", hex.EncodeToString(privBytes))
	fmt.Printf("heap_off=%#x\n", off)
	os.Stdout.Sync()

	// 保持存活，等待外部扫描
	time.Sleep(120 * time.Second)
}

var sink []byte
