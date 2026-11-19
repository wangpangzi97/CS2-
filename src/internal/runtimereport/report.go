// Package runtimereport is a deliberately narrow declassification boundary:
// Samples have ONLY numeric counters, booleans encoded as flags, and fixed enums.
// There is no string/payload/error/memory/credential input or generic log writer.
package runtimereport

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const MaxSamples = 1200
const (
	Unknown uint8 = iota
	Waiting
	Freezing
	Checking
	Searching
	Pointer
	Failed
	Disabled
	Ready
)
const (
	Running uint8 = 1 << iota
	KeyReady
	KeyAttached
	KeySearching
	ClientHandshake
	ServerHandshake
	FilterActive
)

// No byte arrays, free text, peers, positions, process IDs or memory addresses.
type Sample struct {
	Sequence             uint64 `json:"sequence"`
	ElapsedMS            uint64 `json:"elapsed_ms"`
	Packets              uint64 `json:"packets"`
	Bytes                uint64 `json:"bytes"`
	C2S                  uint64 `json:"c2s"`
	S2C                  uint64 `json:"s2c"`
	Filtered             uint64 `json:"filtered"`
	FilterDropGNS        uint64 `json:"filter_drop_gns"`
	UpPackets            uint64 `json:"uplink_packets"`
	UpBatches            uint64 `json:"uplink_batches"`
	UpFailed             uint64 `json:"uplink_failed"`
	UpDropped            uint64 `json:"uplink_dropped"`
	Throttled            uint64 `json:"throttled_handshakes"`
	Players              uint32 `json:"player_count"`
	Sounds               uint32 `json:"sound_count"`
	Phase                uint8  `json:"key_phase"`
	Flags                uint8  `json:"flags"`
	View                 uint8  `json:"view_state"` // 0 unknown,1 no map,2 map required,3 mapped,4 unavailable
	Reserved             uint8  `json:"reserved"`
	FilterPorts          uint16 `json:"filter_port_count"`
	Interfaces           uint16 `json:"interface_count"`
	OwnedUDP             uint64 `json:"owned_udp"`
	HeuristicUDP         uint64 `json:"admitted_udp"`
	UnmatchedUDP         uint64 `json:"unmatched_udp"`
	UnfilteredUDP        uint64 `json:"unfiltered_udp"`
	GNSAttempts          uint64 `json:"gns_attempts"`
	GNSCandidate         uint64 `json:"gns_candidates"`
	GNSParsed            uint64 `json:"gns_parsed"`
	GNSRejected          uint64 `json:"gns_candidate_rejected"`
	HelloAttempts        uint64 `json:"hello_attempts"`
	HelloParsed          uint64 `json:"hello_parsed"`
	AutoAdmittedPorts    uint64 `json:"auto_admitted_ports_total"`
	FilterState          uint8  `json:"filter_state"`
	PeerSnapshot         uint8  `json:"peer_snapshot"`
	OwnedPorts           uint16 `json:"owned_port_count"`
	CaptureReceived      uint64 `json:"capture_received"`
	CaptureDropped       uint64 `json:"capture_queue_dropped"`
	SendRejected         uint64 `json:"send_queue_rejected"`
	CaptureQueueDepth    uint32 `json:"capture_queue_depth"`
	CaptureQueueCapacity uint32 `json:"capture_queue_capacity"`
	SendQueueDepth       uint32 `json:"send_queue_depth"`
	SendQueueBytes       uint32 `json:"send_queue_charged_bytes"`
	StopReason           uint8  `json:"stop_reason"`
	FailureKind          uint8  `json:"failure_kind"`
	HTTPStatus           uint16 `json:"http_status"`
	DirectionUnknown     uint64 `json:"direction_unknown"`
	OwnershipRejected    uint64 `json:"ownership_rejected"`
	OwnershipRefreshes   uint64 `json:"ownership_refreshes"`
}
type header struct {
	Magic         [8]byte
	Version       uint16
	RecordSize    uint16
	Count         uint32
	StartedUnixMS int64
}
type Journal struct {
	mu      sync.Mutex
	dir     string
	start   time.Time
	fixture bool
	total   uint64
	samples []Sample
}

func New(base string, fixture bool) (*Journal, error) {
	abs, e := filepath.Abs(base)
	if e != nil {
		return nil, e
	}
	if e = os.MkdirAll(abs, 0700); e != nil {
		return nil, e
	}
	dir, e := os.MkdirTemp(abs, "run-"+time.Now().UTC().Format("20060102T150405Z")+"-")
	if e != nil {
		return nil, e
	}
	return &Journal{dir: dir, start: time.Now(), fixture: fixture}, nil
}
func (j *Journal) Record(s Sample) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.total++
	s.Sequence = j.total
	s.ElapsedMS = uint64(time.Since(j.start).Milliseconds())
	if s.Phase > Ready {
		s.Phase = Unknown
	}
	s.Flags &= 127
	if s.View > 4 {
		s.View = 0
	}
	s.Reserved = 0
	if s.StopReason > 6 {
		s.StopReason = 0
	}
	if s.FailureKind > 9 {
		s.FailureKind = 1
	}
	if s.HTTPStatus != 0 && (s.HTTPStatus < 100 || s.HTTPStatus > 599) {
		s.HTTPStatus = 0
	}
	if s.FilterState > 8 {
		s.FilterState = 0
	}
	if s.PeerSnapshot > 2 {
		s.PeerSnapshot = 0
	}
	if s.Players > 512 {
		s.Players = 512
	}
	if s.Sounds > 4096 {
		s.Sounds = 4096
	}
	if len(j.samples) == MaxSamples {
		copy(j.samples, j.samples[1:])
		j.samples[len(j.samples)-1] = s
	} else {
		j.samples = append(j.samples, s)
	}
}
func (j *Journal) files() (map[string][]byte, error) {
	j.mu.Lock()
	samples := append([]Sample(nil), j.samples...)
	total, start, fixture := j.total, j.start, j.fixture
	j.mu.Unlock()
	var wire, log bytes.Buffer
	h := header{Magic: [8]byte{'G', 'S', 'D', 'I', 'A', 'G', '0', '4'}, Version: 4, RecordSize: uint16(binary.Size(Sample{})), Count: uint32(len(samples)), StartedUnixMS: start.UnixMilli()}
	if e := binary.Write(&wire, binary.LittleEndian, h); e != nil {
		return nil, e
	}
	enc := json.NewEncoder(&log)
	for _, s := range samples {
		if e := binary.Write(&wire, binary.LittleEndian, s); e != nil {
			return nil, e
		}
		if e := enc.Encode(s); e != nil {
			return nil, e
		}
	}
	var last Sample
	if len(samples) > 0 {
		last = samples[len(samples)-1]
	}
	summary := struct {
		Schema      int      `json:"schema"`
		Client      string   `json:"client"`
		Started     string   `json:"started_utc"`
		Fixture     bool     `json:"fixture_only"`
		Total       uint64   `json:"total_samples"`
		Retained    int      `json:"retained_samples"`
		Limit       int      `json:"max_samples"`
		RecordBytes int      `json:"binary_record_bytes"`
		Last        Sample   `json:"last"`
		Phases      []string `json:"phase_names"`
		Scope       string   `json:"scope"`
	}{4, "gamesense-v13", start.UTC().Format(time.RFC3339Nano), fixture, total, len(samples), MaxSamples, binary.Size(Sample{}), last, []string{"unknown", "waiting_handshake", "freezing", "checking", "searching", "pointer", "failed", "disabled", "ready"}, "numeric/enums only; not packet replay, memory dump, keys or credentials; no server decoder internals"}
	meta, e := json.MarshalIndent(summary, "", "  ")
	if e != nil {
		return nil, e
	}
	files := map[string][]byte{"runtime.log": log.Bytes(), "diagnostic.bin": wire.Bytes(), "summary.json": append(meta, '\n'), "README.txt": []byte("GSDIAG04 safe telemetry v4. NOT raw capture or memory.\nLittle-endian header: magic[8],u16 schema,u16 record_size,u32 count,i64 started_unix_ms.\nRecord size 280 bytes: v3 prefix256, then3u64 direction_unknown/ownership_rejected/ownership_refreshes. Ownership rejection excludes unknown-direction and unavailable-filter packets. Refreshes are bounded guarded process-port rediscovery attempts, not peer authentication. Stop_reason0none,1unspecified/user,2uplink,3data session,4license,5view,6duration. Failure_kind0none,1unknown,2HTTP,3cancel,4timeout,5TLS,6DNS,7network,8backpressure,9denied/invalid data session. HTTP status0unknown or100..599; codes describe first observed stop request, not a proven external root cause. Order follows Sample in source.\nFlags: running=1,key_ready=2,key_attached=4,key_searching=8,client_handshake=16,server_handshake=32,filter_active=64.\nView: 0 unknown,1 no map,2 map required,3 mapped,4 unavailable.\nFilter_state: 0 unpolled,1 discovered process ports,2 resolve failed/blocked,3 discover error,4 empty ports,5 filter disabled (rejected in production),6 target absent,7 process enumeration failed,8 safety blocked. v9 waits without uplink while unavailable.\nPeer_snapshot: 0 unknown/legacy,1 lock acquired,2 busy (handshake flags unavailable).\nowned_udp uses last discovered local-port snapshot; admitted_udp is not proof of process ownership or protocol.\nGNS candidates are fixed recognized type headers, rejected means candidate parse failed; attempts include non-handshake UDP. Counters do not contain byte values.\nAt most 1200 samples (~20min at 1Hz); total_samples can exceed retained_samples.\nNo card,token,device identity,IP,raw payload,positions,key bytes or process memory.\nA sample can locate a stalled stage; it cannot prove protocol decoding correctness.\n")}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	var sums bytes.Buffer
	for _, n := range names {
		h := sha256.Sum256(files[n])
		fmt.Fprintf(&sums, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	files["SHA256SUMS.txt"] = sums.Bytes()
	return files, nil
}
func writeAtomic(path string, b []byte) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".safe-report-*.tmp")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func (j *Journal) Flush() error {
	files, e := j.files()
	if e != nil {
		return e
	}
	for n, b := range files {
		if e = writeAtomic(filepath.Join(j.dir, n), b); e != nil {
			return e
		}
	}
	return nil
}
func (j *Journal) Export() (string, error) {
	files, e := j.files()
	if e != nil {
		return "", e
	}
	var out bytes.Buffer
	w := zip.NewWriter(&out)
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		f, e := w.Create(n)
		if e != nil {
			return "", e
		}
		if _, e = f.Write(files[n]); e != nil {
			return "", e
		}
	}
	if e = w.Close(); e != nil {
		return "", e
	}
	path := filepath.Join(j.dir, "runtime-diagnostic.zip")
	if e = writeAtomic(path, out.Bytes()); e != nil {
		return "", e
	}
	return path, nil
}
func (j *Journal) Dir() string { return j.dir }
func ReadBinary(b []byte) ([]Sample, error) {
	fail := func() ([]Sample, error) { return nil, errors.New("invalid safe diagnostic binary") }
	if len(b) > 1<<20 {
		return fail()
	}
	r := bytes.NewReader(b)
	var h header
	if binary.Read(r, binary.LittleEndian, &h) != nil {
		return fail()
	}
	legacy := string(h.Magic[:]) == "GSDIAG01" && h.Version == 1 && h.RecordSize == 120
	v2 := string(h.Magic[:]) == "GSDIAG02" && h.Version == 2 && h.RecordSize == 212
	v3 := string(h.Magic[:]) == "GSDIAG03" && h.Version == 3 && h.RecordSize == 256
	current := string(h.Magic[:]) == "GSDIAG04" && h.Version == 4 && int(h.RecordSize) == binary.Size(Sample{})
	if (!legacy && !v2 && !v3 && !current) || h.Count > MaxSamples || r.Len() != int(h.Count)*int(h.RecordSize) {
		return fail()
	}
	samples := make([]Sample, int(h.Count))
	var seq, elapsed uint64
	for i := range samples {
		record := make([]byte, binary.Size(Sample{}))
		if _, e := io.ReadFull(r, record[:int(h.RecordSize)]); e != nil {
			return fail()
		}
		if binary.Read(bytes.NewReader(record), binary.LittleEndian, &samples[i]) != nil {
			return fail()
		}
		s := samples[i]
		if s.Sequence <= seq || s.ElapsedMS < elapsed || s.Phase > Ready || s.View > 4 || s.Reserved != 0 || s.Flags&128 != 0 || s.FilterState > 8 || s.PeerSnapshot > 2 || s.StopReason > 6 || s.FailureKind > 9 || s.HTTPStatus != 0 && (s.HTTPStatus < 100 || s.HTTPStatus > 599) || s.Players > 512 || s.Sounds > 4096 {
			return fail()
		}
		seq, elapsed = s.Sequence, s.ElapsedMS
	}
	if _, e := r.ReadByte(); e != io.EOF {
		return fail()
	}
	return samples, nil
}
