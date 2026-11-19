// Package entitycodec decodes typed Source2 entity states, never sound-derived guesses.
package entitycodec

import (
	"embed"
	"encoding/json"
	"fmt"
	c "github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/constants"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	st "github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/sendtables"
	"google.golang.org/protobuf/proto"
	"local/cs2-radar/internal/cs2proto"
	"local/cs2-radar/internal/perfstat"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"
)

//go:embed assets/*
var assets embed.FS

type historicalFrame struct {
	checkpoint *st.RadarCheckpoint
	departed   map[int]time.Time
	acceptedAt time.Time
}
type Decoder struct {
	episode                                                                    FaultEpisode
	perfPacket, perfLock, perfRestore, perfApply, perfCheckpoint, perfSnapshot perfstat.Timer
	ttl                                                                        time.Duration
	mu                                                                         sync.Mutex
	parser                                                                     *st.Parser
	info                                                                       *msg.CSVCMsg_ServerInfo
	ents                                                                       map[int]*st.Entity
	departed                                                                   map[int]time.Time
	ready                                                                      bool
	fault                                                                      string
	last                                                                       time.Time
	lastTick                                                                   uint32
	history                                                                    map[uint32]historicalFrame
	historyOrder                                                               []uint32
	historyBytes                                                               int
	packets                                                                    uint64
	tables                                                                     []connectionTable
	baselines                                                                  map[int][]byte
	liveBaselines                                                              bool
	classOK                                                                    bool
	classMode                                                                  string
	metadataFault                                                              string
	syncFault                                                                  string
	syncFaultCode                                                              uint8
	activeBase                                                                 uint32
	cacheTrace                                                                 historyDiagnostics
	inputTrace                                                                 entityInputTrace
	origin                                                                     ingressOrigin
}

func New() *Decoder { return NewWithTTL(10 * time.Second) }
func NewWithTTL(ttl time.Duration) *Decoder {
	if ttl <= 0 {
		ttl = 10 * time.Second
	}
	return &Decoder{ttl: ttl, fault: "等待 ServerInfo 和完整实体帧"}
}
func (d *Decoder) bootstrap() error {
	if e := verifyProfileAssets(); e != nil {
		return e
	}
	d.parser = st.NewParser()
	d.ents = map[int]*st.Entity{}
	d.departed = map[int]time.Time{}
	raw, e := assets.ReadFile("assets/sendtables.bin")
	if e != nil {
		return e
	}
	if e = d.parser.ParsePacket(raw); e != nil {
		return e
	}
	raw, e = assets.ReadFile("assets/classinfo.pb")
	if e != nil {
		return e
	}
	ci := &msg.CDemoClassInfo{}
	if e = proto.Unmarshal(raw, ci); e != nil {
		return e
	}
	if e = d.parser.OnDemoClassInfo(ci); e != nil {
		return e
	}
	if d.liveBaselines {
		for id, b := range d.baselines {
			d.parser.SetInstanceBaseline(id, b)
		}
	} else if d.info.GetMapName() == "de_dust2" {
		// Compatibility fallback only for the previously verified DEM fixtures.
		raw, e = assets.ReadFile("assets/baselines.json")
		if e != nil {
			return e
		}
		var base map[string][]byte
		if e = json.Unmarshal(raw, &base); e != nil {
			return e
		}
		for k, b := range base {
			id, e := strconv.Atoi(k)
			if e != nil {
				return e
			}
			d.parser.SetInstanceBaseline(id, b)
		}
	}
	if e = d.parser.OnServerInfo(d.info); e != nil {
		return e
	}
	d.parser.OnEntity(func(e *st.Entity, op st.EntityOp) error {
		if op.Flag(st.EntityOpDeleted) {
			delete(d.ents, e.ID())
			delete(d.departed, e.ID())
		} else {
			d.ents[e.ID()] = e
		}
		if op.Flag(st.EntityOpLeft) {
			d.departed[e.ID()] = d.last
		}
		if op.Flag(st.EntityOpEntered) {
			delete(d.departed, e.ID())
		}
		return nil
	})
	return nil
}
func (d *Decoder) ServerInfo(body []byte) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("schema initialization: %v", p)
			d.ready = false
			d.fault = err.Error()
		}
	}()
	m := &msg.CSVCMsg_ServerInfo{}
	if err = proto.Unmarshal(body, m); err != nil {
		return err
	}
	d.tables = nil
	d.baselines = nil
	d.liveBaselines = false
	d.classOK = false
	d.classMode = ""
	d.metadataFault = ""
	d.syncFault = ""
	d.syncFaultCode = 0
	d.parser = nil
	d.ents = nil
	d.info = m
	d.ready = false
	d.lastTick = 0
	d.last = time.Time{}
	d.packets = 0
	d.history = nil
	d.historyOrder = nil
	d.historyBytes = 0
	d.activeBase = 0
	d.cacheTrace = historyDiagnostics{}
	d.inputTrace = entityInputTrace{}
	d.origin = ingressOrigin{}
	d.episode = FaultEpisode{}
	if _, ok := entityProfile(m.GetProtocol(), m.GetMaxClasses()); !ok {
		d.parser = nil
		d.fault = fmt.Sprintf("没有匹配的实体profile：protocol=%d classes=%d map=%s；保持未同步", m.GetProtocol(), m.GetMaxClasses(), m.GetMapName())
		return fmt.Errorf("%s", d.fault)
	}
	if err = d.bootstrap(); err != nil {
		d.fault = err.Error()
		return err
	}
	d.fault = "已载入已验证schema " + profileLabel(d.info) + "，等待当前连接类表、基线和完整实体帧"
	return nil
}
func (d *Decoder) PacketEntities(body []byte, now time.Time) (err error) {
	waiting := time.Now()
	d.mu.Lock()
	d.cacheTrace.inputPackets++
	d.perfLock.Observe(time.Since(waiting))
	started := time.Now()
	defer func() { d.perfPacket.Observe(time.Since(started)) }()
	defer d.mu.Unlock()
	readyAtEntry, attemptedDecode := d.ready, false
	var traceTick, traceFrom uint32
	var traceBaseKnown uint8
	failureCode := uint8(1) // malformed envelope/payload
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("entity decode: %v", p)
		}
		if err != nil {
			d.cacheTrace.rejectedPackets++
			if readyAtEntry || attemptedDecode {
				d.inputTrace.firstFault(failureCode, d.cacheTrace.inputPackets, traceTick, d.lastTick, traceFrom, traceBaseKnown)
				d.startFaultEpisode(failureCode, traceFrom, traceBaseKnown)
				d.syncFault = err.Error()
				d.syncFaultCode = failureCode
			}
			d.ready = false
			d.fault = err.Error()
		}
		outcome, code := uint8(3), uint8(0)
		if err != nil {
			outcome, code = 2, failureCode
		} else if h, ok := d.history[traceTick]; ok && h.checkpoint != nil {
			outcome = 1
		}
		d.inputTrace.remember(traceTick, outcome, code)
	}()
	if len(body) > 16<<20 {
		return fmt.Errorf("entity payload limit")
	}
	if d.parser == nil {
		return fmt.Errorf("%s", d.fault)
	}
	if d.metadataFault != "" {
		return fmt.Errorf("%s", d.metadataFault)
	}
	if d.info.GetMapName() != "de_dust2" && (!d.classOK || !d.liveBaselines || d.baselines[44] == nil || d.baselines[45] == nil) {
		return fmt.Errorf("等待当前连接ClassInfo/instancebaseline，缓存schema不按地图解锁")
	}
	m := &msg.CSVCMsg_PacketEntities{}
	if err = proto.Unmarshal(body, m); err != nil {
		return err
	}
	if m.GetServerTick() == 0 {
		d.origin.zeroBodies++
	}
	traceTick = m.GetServerTick()
	if m.GetLegacyIsDelta() && m.GetDeltaFrom() > 0 {
		traceFrom = uint32(m.GetDeltaFrom())
		if h, ok := d.history[traceFrom]; ok && h.checkpoint != nil {
			traceBaseKnown = 1
		}
	}
	if m.GetLegacyIsDelta() && m.GetDeltaFrom() > 0 &&
		m.GetServerTick() > uint32(m.GetDeltaFrom()) &&
		m.GetUpdatedEntries() == 0 && len(m.GetEntityData()) == 0 {
		d.cacheTrace.emptyDeltas++
	}
	if m.GetUpdatedEntries() < 0 || m.GetUpdatedEntries() > 16384 {
		failureCode = 2
		return fmt.Errorf("entity update count limit")
	}
	tick := m.GetServerTick()
	if tick != 0 && d.lastTick != 0 && tick < d.lastTick {
		failureCode = 4
		return d.cacheLateDelta(m, now)
	} // cache a valid late dependency without publishing or rewinding it
	recovering := false
	if m.GetLegacyIsDelta() && !d.ready {
		// A failed packet may have partially mutated the parser. Never reuse
		// that state or merely flip ready. A newer delta can recover ONLY by
		// restoring its exact, successful, unexpired checkpoint from this
		// signon generation. Full frames/ServerInfo clear this history.
		if d.syncFault != "" && tick > d.lastTick && m.GetDeltaFrom() > 0 {
			base, ok := d.history[uint32(m.GetDeltaFrom())]
			age := now.Sub(base.acceptedAt)
			recovering = ok && base.checkpoint != nil && !base.acceptedAt.IsZero() && age >= 0 && age <= d.ttl
		}
		if !recovering {
			if d.syncFault != "" {
				// Account for blocked missing dependencies as well; this changes
				// diagnostics only, never the exact-base recovery decision.
				if m.GetDeltaFrom() > 0 {
					from := uint32(m.GetDeltaFrom())
					if _, ok := d.history[from]; !ok {
						d.recordMissingBase(from)
					}
				}
				return fmt.Errorf("等待完整实体帧；上次失步：%s", d.syncFault)
			}
			return fmt.Errorf("等待完整实体帧，拒绝无基线delta")
		}
	}
	attemptedDecode = true
	// Live snapshots reference the acknowledged tick, not necessarily the last
	// received tick. Restore that exact entity state before applying the delta.
	if m.GetLegacyIsDelta() && tick != 0 && m.GetDeltaFrom() > 0 {
		from := uint32(m.GetDeltaFrom())
		if from != d.lastTick || recovering {
			failureCode = 3 // exact acknowledged checkpoint unavailable
			base, ok := d.history[from]
			if !ok {
				d.recordMissingBase(from)
				return fmt.Errorf("缺少delta指定基线 from=%d last=%d cache_frames=%d cache_bytes=%d，等待完整帧", from, d.lastTick, len(d.history), d.historyBytes)
			}
			restoring := time.Now()
			failureCode = 4 // checkpoint restoration
			err = d.parser.RestoreRadarCheckpoint(base.checkpoint)
			d.perfRestore.Observe(time.Since(restoring))
			if err != nil {
				return err
			}
			d.ents = d.parser.RadarEntities()
			d.departed = copyDeparted(base.departed)
		}
	}
	if !m.GetLegacyIsDelta() {
		d.history = nil
		d.historyOrder = nil
		d.historyBytes = 0
		d.activeBase = 0
		d.cacheTrace.evicted = [256]uint32{}
		d.cacheTrace.evictedNext = 0
		if err = d.bootstrap(); err != nil {
			return err
		}
	}
	d.last = now
	applying := time.Now()
	failureCode = 5 // entity parser rejected this update
	err = d.parser.OnPacketEntities(m)
	d.perfApply.Observe(time.Since(applying))
	if err != nil {
		return err
	}
	if tick != 0 {
		saving := time.Now()
		failureCode = 6 // checkpoint creation
		checkpoint, e := d.parser.RadarCheckpoint()
		d.perfCheckpoint.Observe(time.Since(saving))
		if e != nil {
			return e
		}
		if d.history == nil {
			d.history = make(map[uint32]historicalFrame)
		}
		if old, ok := d.history[tick]; ok {
			d.historyBytes -= old.checkpoint.Bytes()
		} else {
			d.historyOrder = append(d.historyOrder, tick)
		}
		d.history[tick] = historicalFrame{checkpoint: checkpoint, departed: copyDeparted(d.departed), acceptedAt: now}
		d.historyBytes += checkpoint.Bytes()
		// Keep the exact acknowledged base used by this incoming snapshot.
		// A large map reaches the byte budget long before 128 frames. FIFO
		// must not evict a still-referenced older base merely because it is old.
		protected := uint32(0)
		if m.GetLegacyIsDelta() && m.GetDeltaFrom() > 0 {
			protected = uint32(m.GetDeltaFrom())
		}
		failureCode = 7 // unchanged bounded history pruning
		if err = d.pruneHistory(protected, tick); err != nil {
			return err
		}
	}
	if !m.GetLegacyIsDelta() {
		d.inputTrace = entityInputTrace{}
		d.origin.reanchor()
	} // successful full reanchor only
	d.episode.Active = 0
	d.ready = true
	d.fault = ""
	d.syncFault = ""
	d.syncFaultCode = 0
	d.lastTick = tick
	d.activeBase = 0
	if m.GetLegacyIsDelta() && m.GetDeltaFrom() > 0 {
		d.activeBase = uint32(m.GetDeltaFrom())
	}
	d.packets++
	return nil
}
func prop(e *st.Entity, name string) any {
	if e == nil {
		return nil
	}
	v, ok := e.PropertyValue(name)
	if !ok {
		return nil
	}
	return v.Any
}
func number(v any) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint32:
		return uint64(x)
	case int32:
		return uint64(x)
	case int64:
		return uint64(x)
	case int:
		return uint64(x)
	}
	return 0
}
func (d *Decoder) Snapshot(now time.Time) (out []cs2proto.Player, synced bool, status string) {
	started := time.Now()
	defer func() { d.perfSnapshot.Observe(time.Since(started)) }()
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		if p := recover(); p != nil {
			out = nil
			synced = false
			status = fmt.Sprintf("实体快照字段不兼容：%v", p)
		}
	}()
	if !d.ready {
		return nil, false, d.fault
	}
	if now.Sub(d.last) > d.ttl {
		return nil, false, "实体流超过TTL未更新；不显示旧人物"
	}
	for _, ctrl := range d.ents {
		if ctrl.ServerClass().Name() != "CCSPlayerController" {
			continue
		}
		if prop(ctrl, "m_iConnected") == nil || number(prop(ctrl, "m_iConnected")) != 0 {
			continue
		}
		team := int(number(prop(ctrl, "m_iTeamNum")))
		if team != 2 && team != 3 {
			continue
		}
		handle := number(prop(ctrl, "m_hPlayerPawn"))
		pawn := d.ents[int(handle&c.EntityHandleIndexMaskSource2)]
		if pawn == nil || pawn.ServerClass().Name() != "CCSPlayerPawn" || uint64(pawn.SerialNum())&((1<<c.EntityHandleSerialNumberBits)-1) != (handle>>c.MaxEdictBitsSource2)&((1<<c.EntityHandleSerialNumberBits)-1) {
			continue
		}
		stale := !pawn.InPVS() || now.Sub(d.last) > time.Second
		age := now.Sub(d.last)
		if t, ok := d.departed[pawn.ID()]; ok {
			age = now.Sub(t)
			if age > d.ttl {
				continue
			}
		}
		// Missing fields must never turn into a plausible (0,0,0) player.
		have := true
		for _, n := range []string{"CBodyComponent.m_cellX", "CBodyComponent.m_cellY", "CBodyComponent.m_cellZ", "CBodyComponent.m_vecX", "CBodyComponent.m_vecY", "CBodyComponent.m_vecZ"} {
			if prop(pawn, n) == nil {
				have = false
				break
			}
		}
		if !have {
			continue
		}
		pos := pawn.Position()
		if math.IsNaN(pos.X) || math.IsNaN(pos.Y) || math.IsNaN(pos.Z) || math.IsInf(pos.X, 0) || math.IsInf(pos.Y, 0) || math.IsInf(pos.Z, 0) || math.Abs(pos.X) > 32768 || math.Abs(pos.Y) > 32768 || math.Abs(pos.Z) > 32768 {
			continue
		}
		name, _ := prop(ctrl, "m_iszPlayerName").(string)
		health := int(int64(number(prop(pawn, "m_iHealth"))))
		if health < 0 || health > 1000 {
			continue
		}
		if age < 0 {
			age = 0
		}
		out = append(out, cs2proto.Player{ID: ctrl.ID(), Team: team, Pos: cs2proto.Vec3{X: float32(pos.X), Y: float32(pos.Y), Z: float32(pos.Z)},
			Source: profileSource(d.info), UpdatedAt: d.last, AgeMS: age.Milliseconds(), Stale: stale,
			Name: name, SteamID: fmt.Sprint(prop(ctrl, "m_steamID")), PawnID: pawn.ID(), Serial: pawn.SerialNum(), Health: health, Alive: health > 0 && number(prop(pawn, "m_lifeState")) == 0})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, true, fmt.Sprintf("实体已同步：%d名已连接T/CT；schema=%s class=%s live_baselines=%v；PVS外仅显示限时旧位置", len(out), profileLabel(d.info), d.classMode, d.liveBaselines)
}

func copyDeparted(in map[int]time.Time) map[int]time.Time {
	out := make(map[int]time.Time, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

// pruneHistory keeps the active dependency and newest snapshot within the SAME
// 128-frame / 128MiB budget. Each individual checkpoint remains <=32MiB.
func (d *Decoder) pruneHistory(protected, current uint32) error {
	return d.pruneHistoryKeeping(protected, current)
}

// Performance exposes timings only, never field values or account identifiers.
// Percentiles are histogram bucket upper bounds, not exact sample percentiles.
func (d *Decoder) Performance() map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	return map[string]any{"packet": d.perfPacket.Snapshot(), "lock_wait": d.perfLock.Snapshot(), "restore": d.perfRestore.Snapshot(), "apply": d.perfApply.Snapshot(), "checkpoint": d.perfCheckpoint.Snapshot(), "snapshot": d.perfSnapshot.Snapshot(), "cache_bytes": d.historyBytes, "cache_frames": len(d.history)}
}
