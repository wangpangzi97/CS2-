# 数据授权缓存与有界本机负载验收

这是候选源码的本机合成验收，**未部署、不是生产容量或延迟承诺**。没有真实游戏包、采集、生产数据库、SSH或外部压测流量。完整原始结果在外层阶段记录中，测试源码为 `internal/dataauth/resource_limits_test.go`。

## 已修复的缓存策略

1. 固定分钟数据配额仍为1800次，签名、时间戳和nonce重放校验不变。旧nonce上限1024会提前拒绝本应在配额内的请求。nonce保存 `2*ProofSkew`（当前60秒），可能横跨两个分钟配额桶，因此容量由保留期和分钟配额推导为3600；不通过提前删除nonce来放宽重放检查。心跳也计入配额，不能每分钟先用满1800次数据请求再额外要求心跳。
2. 认证IP表最多4096项。只有**新IP**需要剩余容量；满表时已存在的IP仍按自己的20次/分钟限额处理。未知IP仍被拒绝；多个用户共用NAT时仍共享这个认证限额，本轮不擅自取消或提高它。
3. 每秒Sweep也清理过期IP限速桶，空闲时不再保留最多4096条过期记录。已有session/token/challenge到期清理和一次性撤销回调保持不变；活跃会话的过期nonce在下一次签名请求时清理，无请求时会随访问/租期过期清除。

数据会话默认64、可配置上限1024；challenge默认512、可配置上限4096。每会话nonce上限3600意味着默认最多230400条、最大配置最多3686400条记录，**不等于已经测出这些满载配置的RSS或能够在现有服务器承受**。部署前应结合真实Linux内存限制与有界负载重新配置会话数、服务并发和内存预算；没有自动无限扩容。

## 实际测试边界

在源码目录运行（仅Go httptest回环TLS，使用测试CA，不关闭TLS校验）：

```powershell
go test -mod=vendor -count=1 -timeout 60s -v ./internal/dataauth -run '^TestDataResource'
```

- `BoundaryProbe`：固定测试时钟，1800个独立有效签名；同时测满表已知IP和空闲清理。探针exit0只表示成功测量；旧版本会输出提前拒绝，不能把它误读为旧版本通过新策略。
- `NonceWindows`：模拟连续分钟边界，合计5400次配额内请求（含3个签名心跳），峰值3600nonce；超配额、重放和旧token仍拒绝，过期后下一请求只保留新nonce。不是1800RPS实测；测试中的elapsed/HeapAlloc差值不是生产延迟、RSS或安全内存清零证明。
- `RateTable`：最多4096个合成键；新键拒绝、已知键仅允许20次；空闲Sweep归零并恢复容量。该表容量边界测试不向这些键对应地址发包。
- `TLSChallengeBurst`：32个并发回环TLS请求，夹具challenge上限8；观察8个200、12个503容量拒绝、12个429限速；到期清理为0。
- `TLSEnrollmentSlots`：8个有效设备签名并发登记，阻塞型合成Authority同时最多4个；夹具会话上限3，观察3个200、5个503，已消耗challenge重放403；到期清理session/token/challenge/IP状态，3个回调各一次。
- `PermitConcurrency`：32个并发争用同会话仅1个获准工作，释放后可再次取得。
- `TLSAuthorityOutage`：两秒权益检查缓存边界后Authority不可用，真实TLS客户端拒绝并清除凭据；Authority恢复不会自动复活旧客户端；撤销与Sweep清除状态且回调一次。

身份/权益Authority在本阶段是**合成实现**，用于可控的容量和失联测试；不是重新执行上一阶段的MariaDB/PHP完整HTTP链路。没有Go race detector、全量SAST/SCA、真实解码压力、Linux cgroup/eBPF、生产Nginx/TLS或服务器重启验收。所列数量是有界夹具结果，不是生产恶意洪泛防护能力或零缓存窗口撤销承诺。
