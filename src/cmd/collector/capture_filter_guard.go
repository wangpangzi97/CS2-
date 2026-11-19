package main

import (
	"errors"
	"fmt"
	"local/cs2-radar/internal/memscan"
	"os"
)

const (
	filterAvailable         uint8 = 1
	filterResolveUnknown    uint8 = 2 // legacy v8
	filterDiscoverFailed    uint8 = 3
	filterPortsEmpty        uint8 = 4
	filterForbidden         uint8 = 5
	filterTargetAbsent      uint8 = 6
	filterEnumerationFailed uint8 = 7
	filterSafetyBlocked     uint8 = 8
)

type targetResolveError struct {
	state uint8
	cause error
}

func (e *targetResolveError) Error() string { return e.cause.Error() }
func (e *targetResolveError) Unwrap() error { return e.cause }

// lookupTargetPID performs only process-name enumeration. Guard precedence stays
// in resolvePID; no fallback or alternate process access is introduced here.
func lookupTargetPID(name string, lookup func(string) (uint32, error)) (uint32, error) {
	pid, err := lookup(name)
	if err == nil && pid != 0 {
		return pid, nil
	}
	code := filterEnumerationFailed
	if errors.Is(err, memscan.ErrProcessNotFound) {
		code = filterTargetAbsent
	}
	if err == nil {
		err = errors.New("invalid process enumeration result")
	}
	return 0, &targetResolveError{state: code, cause: err}
}

func filterFailureState(err error) uint8 {
	var e *targetResolveError
	if errors.As(err, &e) && e.state >= filterTargetAbsent && e.state <= filterSafetyBlocked {
		return e.state
	}
	return filterResolveUnknown
}

func (s *captureSession) publishFilterState(state uint8) {
	old := s.diag.filterState.Swap(uint32(state))
	if old != uint32(state) {
		fmt.Fprintf(os.Stderr, "[GS-FILTER %d]\n", state)
	}
}

func (s *captureSession) refreshCaptureFilter(resolve func() (uint32, error), discover func(uint32) ([]uint16, error)) bool {
	s.filterMu.Lock()
	defer s.filterMu.Unlock()
	unavailable := func(state uint8) bool {
		// Publish denial first. Strict Match also denies when ownership is cleared.
		s.publishFilterState(state)
		if s.cfilter != nil {
			s.cfilter.Clear()
		}
		return false
	}
	if s.noFilter || s.cfilter == nil {
		return unavailable(filterForbidden)
	}
	pid, err := resolve()
	if err != nil {
		return unavailable(filterFailureState(err))
	}
	if pid == 0 {
		return unavailable(filterEnumerationFailed)
	}
	ports, err := discover(pid)
	if err != nil {
		return unavailable(filterDiscoverFailed)
	}
	valid := make([]uint16, 0, len(ports))
	for _, port := range ports {
		if port != 0 {
			valid = append(valid, port)
		}
	}
	if len(valid) == 0 {
		return unavailable(filterPortsEmpty)
	}
	s.cfilter.Set(pid, valid)
	s.publishFilterState(filterAvailable)
	return true
}

func (s *captureSession) captureFilterAvailable() bool {
	return !s.noFilter && s.cfilter != nil && s.diag.filterState.Load() == uint32(filterAvailable) && s.cfilter.OwnedPortCount() > 0
}

func filterStatusText(state uint8) string {
	switch state {
	case filterTargetAbsent:
		return "[GS-FILTER 6] 未找到目标进程；等待目标启动，未上行数据。"
	case filterEnumerationFailed:
		return "[GS-FILTER 7] 无法枚举目标进程；请导出诊断包，未上行数据。"
	case filterSafetyBlocked:
		return "[GS-FILTER 8] 安全策略阻止访问目标；已阻止上行，不要关闭或绕过保护。"
	case filterDiscoverFailed:
		return "[GS-FILTER 3] 无法读取目标端口表；请导出诊断包，未上行数据。"
	case filterPortsEmpty:
		return "[GS-FILTER 4] 等待目标 UDP 端口；未上行数据。"
	case filterForbidden:
		return "[GS-FILTER 5] 目标过滤不可用；生产版不允许关闭保护。"
	case filterResolveUnknown:
		return "[GS-FILTER 2] 无法解析目标；请导出诊断包，未上行数据。"
	default:
		return "[GS-FILTER 0] 正在确认目标进程与端口；未上行数据。"
	}
}
