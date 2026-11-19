package main

import (
	"flag"
	"fmt"
	"local/cs2-radar/internal/runtimereport"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"
)

// Only counters and fixed enums. No peer, process identifier, key or free text.
type safeObservationCounters struct {
	ownedUDP, heuristicUDP, unmatchedUDP, unfilteredUDP     atomic.Uint64
	gnsAttempts, gnsCandidate, gnsParsed, gnsRejected       atomic.Uint64
	helloAttempts, helloParsed, autoAdmittedPorts           atomic.Uint64
	filterState                                             atomic.Uint32
	stopPacked                                              atomic.Uint32
	directionUnknown, ownershipRejected, ownershipRefreshes atomic.Uint64
}

func (s *captureSession) observeSafeFlow(localPort uint16) {
	if s.cfilter == nil {
		s.diag.unfilteredUDP.Add(1)
		return
	}
	switch s.cfilter.ClassifyLocal(localPort) {
	case 0:
		s.diag.unfilteredUDP.Add(1)
	case 1:
		s.diag.ownedUDP.Add(1)
	case 2:
		s.diag.heuristicUDP.Add(1)
	default:
		s.diag.unmatchedUDP.Add(1)
	}
}
func (s *captureSession) observeSafeGNS(candidate, parsed bool) {
	s.diag.gnsAttempts.Add(1)
	if candidate {
		s.diag.gnsCandidate.Add(1)
	}
	if parsed {
		s.diag.gnsParsed.Add(1)
	} else if candidate {
		s.diag.gnsRejected.Add(1)
	}
}

var flagDiagnosticSelftest = flag.Bool("diagnostic-selftest", false, "仅生成合成计数的安全日志/BIN示例；不授权、不采集、不访问进程或真实数据")

func safeKeyPhase(raw string, ready bool) uint8 {
	if ready {
		return runtimereport.Ready
	}
	switch {
	case strings.Contains(raw, "禁用"):
		return runtimereport.Disabled
	case strings.Contains(raw, "失败") || strings.Contains(raw, "错误") || strings.Contains(raw, "超时") || strings.Contains(raw, "拒绝"):
		return runtimereport.Failed
	case strings.Contains(raw, "等待握手"):
		return runtimereport.Waiting
	case strings.Contains(raw, "冻结"):
		return runtimereport.Freezing
	case strings.Contains(raw, "校验"):
		return runtimereport.Checking
	case strings.Contains(raw, "反查"):
		return runtimereport.Pointer
	case strings.Contains(raw, "搜索"):
		return runtimereport.Searching
	}
	return runtimereport.Unknown
}
func safeCounter(m map[string]any, k string) uint64 {
	switch v := m[k].(type) {
	case uint64:
		return v
	case uint32:
		return uint64(v)
	case int:
		if v > 0 {
			return uint64(v)
		}
	case int64:
		if v > 0 {
			return uint64(v)
		}
	}
	return 0
}
func (s *captureSession) safeDiagnosticSample() runtimereport.Sample {
	p := runtimereport.Sample{Packets: atomic.LoadUint64(&s.pkts), Bytes: atomic.LoadUint64(&s.bytes), C2S: atomic.LoadUint64(&s.dirC2S), S2C: atomic.LoadUint64(&s.dirS2C), Filtered: atomic.LoadUint64(&s.filteredOut), FilterDropGNS: atomic.LoadUint64(&s.filterDropGNS), Throttled: s.throttledOut.Load()}
	phase, _ := s.keyPhase.Load().(string)
	p.Phase = safeKeyPhase(phase, s.keyReady.Load())
	if !s.stopped() {
		p.Flags |= runtimereport.Running
	}
	if s.keyReady.Load() {
		p.Flags |= runtimereport.KeyReady
	}
	if s.keyAttached.Load() {
		p.Flags |= runtimereport.KeyAttached
	}
	if s.keySearching.Load() {
		p.Flags |= runtimereport.KeySearching
	}
	if s.gnsMu.TryLock() {
		p.PeerSnapshot = 1
		if s.gnsClient != nil {
			p.Flags |= runtimereport.ClientHandshake
		}
		if s.gnsServer != nil {
			p.Flags |= runtimereport.ServerHandshake
		}
		s.gnsMu.Unlock()
	} else {
		p.PeerSnapshot = 2
	}
	if s.cfilter != nil {
		if s.cfilter.Active() {
			p.Flags |= runtimereport.FilterActive
		}
		p.FilterPorts = uint16(len(s.cfilter.Ports()))
		p.OwnedPorts = uint16(s.cfilter.OwnedPortCount())
	}
	if s.h != nil {
		p.Interfaces = uint16(s.h.InterfaceCount())
		m := s.h.Stats()
		p.CaptureReceived = safeCounter(m, "udp_received")
		p.CaptureDropped = safeCounter(m, "queue_dropped")
		p.CaptureQueueDepth = uint32(safeCounter(m, "queue_depth"))
		p.CaptureQueueCapacity = uint32(safeCounter(m, "queue_capacity"))
	}
	if s.sender != nil {
		m := s.sender.Stats()
		p.UpPackets = safeCounter(m, "packets")
		p.UpBatches = safeCounter(m, "batches")
		p.UpFailed = safeCounter(m, "failed")
		p.UpDropped = safeCounter(m, "dropped_packets")
		p.SendRejected = safeCounter(m, "queue_rejected")
		p.SendQueueDepth = uint32(safeCounter(m, "queue_depth"))
		p.SendQueueBytes = uint32(safeCounter(m, "queue_bytes"))
	}
	if s.ui != nil {
		mapID, state, players, sounds := s.ui.ViewState()
		if players > 0 {
			p.Players = uint32(players)
		}
		if sounds > 0 {
			p.Sounds = uint32(sounds)
		}
		switch {
		case state == "map_required":
			p.View = 2
		case mapID != "":
			p.View = 3
		default:
			p.View = 1
		}
	}
	p.DirectionUnknown = s.diag.directionUnknown.Load()
	p.OwnershipRejected = s.diag.ownershipRejected.Load()
	p.OwnershipRefreshes = s.diag.ownershipRefreshes.Load()
	p.FilterState = uint8(s.diag.filterState.Load())
	p.OwnedUDP = s.diag.ownedUDP.Load()
	p.HeuristicUDP = s.diag.heuristicUDP.Load()
	p.UnmatchedUDP = s.diag.unmatchedUDP.Load()
	p.UnfilteredUDP = s.diag.unfilteredUDP.Load()
	p.GNSAttempts = s.diag.gnsAttempts.Load()
	p.GNSCandidate = s.diag.gnsCandidate.Load()
	p.GNSParsed = s.diag.gnsParsed.Load()
	p.GNSRejected = s.diag.gnsRejected.Load()
	p.HelloAttempts = s.diag.helloAttempts.Load()
	p.HelloParsed = s.diag.helloParsed.Load()
	p.AutoAdmittedPorts = s.diag.autoAdmittedPorts.Load()
	v := s.diag.stopPacked.Load()
	p.StopReason = uint8(v)
	p.FailureKind = uint8(v >> 8)
	p.HTTPStatus = uint16(v >> 16)
	return p
}
func (s *captureSession) startSafeDiagnostics() {
	j, e := runtimereport.New(filepath.Join(exeDir(), "diagnostics"), false)
	if e != nil {
		return
	}
	s.report = j
	s.reportDone = make(chan struct{})
	go func() {
		defer close(s.reportDone)
		tick := time.NewTicker(time.Second)
		defer tick.Stop()
		n := 0
		j.Record(s.safeDiagnosticSample())
		_ = j.Flush()
		for {
			select {
			case <-s.stopCh:
				<-s.doneCh
				j.Record(s.safeDiagnosticSample())
				_ = j.Flush()
				return
			case <-tick.C:
				j.Record(s.safeDiagnosticSample())
				n++
				if n%5 == 0 {
					_ = j.Flush()
				}
			}
		}
	}()
}
func (a *guiApp) exportSafeDiagnostics() {
	if a.sess == nil || a.sess.report == nil {
		messageBox("安全诊断", "[GS-DIAG/UNAVAILABLE] 诊断未启动。请完整解压到可写目录，重新登录运行。", mbOK)
		return
	}
	a.sess.report.Record(a.sess.safeDiagnosticSample())
	p, e := a.sess.report.Export()
	if e != nil {
		messageBox("安全诊断", "[GS-DIAG/WRITE] 无法保存诊断包。请检查客户端目录写权限和可用磁盘空间。", mbOK|mbIconError)
		return
	}
	messageBox("诊断包已导出", "请将此 ZIP 发回：\n"+p+"\n\n包含白名单计数日志、阶段BIN、摘要和校验。不是原始抓包或内存转储；不含卡密、Token、私钥。", mbOK)
}
func runDiagnosticSelftest() int {
	j, e := runtimereport.New(filepath.Join(exeDir(), "diagnostics-selftest"), true)
	if e == nil {
		j.Record(runtimereport.Sample{Phase: runtimereport.Waiting, Flags: runtimereport.Running})
		j.Record(runtimereport.Sample{Packets: 10, UpPackets: 8, Phase: runtimereport.Freezing, Flags: runtimereport.Running | runtimereport.KeySearching})
		j.Record(runtimereport.Sample{Packets: 20, UpPackets: 18, Phase: runtimereport.Ready, Flags: runtimereport.Running | runtimereport.KeyReady, OwnedUDP: 12, HeuristicUDP: 5, UnmatchedUDP: 2, UnfilteredUDP: 1, GNSAttempts: 20, GNSCandidate: 2, GNSParsed: 1, GNSRejected: 1, HelloAttempts: 20, HelloParsed: 1, AutoAdmittedPorts: 2, OwnedPorts: 3, FilterState: 8, DirectionUnknown: 2, OwnershipRejected: 7, OwnershipRefreshes: 1, PeerSnapshot: 1, CaptureReceived: 23, CaptureDropped: 3, CaptureQueueCapacity: 4096, StopReason: 2, FailureKind: 2, HTTPStatus: 403})
		e = j.Flush()
	}
	if e != nil {
		fmt.Fprintln(os.Stderr, "[GS-DIAG/WRITE] synthetic diagnostic unavailable")
		return 1
	}
	p, e := j.Export()
	if e != nil {
		fmt.Fprintln(os.Stderr, "[GS-DIAG/WRITE] synthetic archive unavailable")
		return 1
	}
	fmt.Println("SAFE_DIAGNOSTIC_SELFTEST=OK; SYNTHETIC_ONLY=true; CARD_USED=false; CAPTURE_STARTED=false")
	fmt.Println(p)
	return 0
}
