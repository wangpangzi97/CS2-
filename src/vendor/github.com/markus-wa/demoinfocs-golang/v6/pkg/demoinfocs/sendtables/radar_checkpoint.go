package sendtables

// Local adapter for CS2 radar live snapshots. Not an upstream demoinfocs API.
// Schema objects are immutable; shared field states are frozen until readFields detaches.
// This adapter intentionally supports parsers without per-entity callbacks.
import "fmt"

type RadarCheckpoint struct {
	entities map[int32]*Entity
	full     int
	budget   entityBudget
	bytes    int
}

func radarValue(v any) (any, int) {
	switch x := v.(type) {
	case *fieldState:
		if x == nil {
			return (*fieldState)(nil), 0
		}
		out := &fieldState{state: make([]any, len(x.state), cap(x.state))}
		n := 32 + cap(x.state)*24
		for i, v := range x.state {
			var extra int
			out.state[i], extra = radarValue(v)
			n += extra
		}
		return out, n
	case []float32:
		return append([]float32(nil), x...), 24 + len(x)*4
	case []float64:
		return append([]float64(nil), x...), 24 + len(x)*8
	case []uint64:
		return append([]uint64(nil), x...), 24 + len(x)*8
	case []byte:
		return append([]byte(nil), x...), 24 + len(x)
	case []any:
		out := make([]any, len(x))
		n := 24 + len(x)*24
		for i, v := range x {
			var extra int
			out[i], extra = radarValue(v)
			n += extra
		}
		return out, n
	case string:
		return x, len(x)
	default:
		return v, 0 // decoded primitive scalars / fixed-size value arrays
	}
}
func radarClone(e *Entity) (*Entity, int, error) {
	if e.hasHandlers || len(e.onCreateFinished)+len(e.onUpdateFinished)+len(e.onDestroy)+len(e.onLeavePVS)+len(e.onEnterPVS) > 0 {
		return nil, 0, fmt.Errorf("radar checkpoints do not support entity callbacks")
	}
	// Freeze the current state. Mutable parser entities detach before readFields.
	// Metadata is copied by value and property caches are never shared.
	n := e.radarBytes
	if n == 0 {
		n = radarEstimate(e.state) + 512 + len(e.polySerializers)*8
		e.radarBytes = n
	}
	e.radarShared = true
	c := *e
	c.fpCache = make(map[string]*fieldPath)
	c.fpNoop = make(map[string]bool)
	c.propCache = make(map[string]*Property)
	return &c, n, nil
}
func (p *Parser) RadarCheckpoint() (*RadarCheckpoint, error) {
	c := &RadarCheckpoint{entities: make(map[int32]*Entity, len(p.entities)), full: p.entityFullPackets, budget: p.entityBudget, bytes: 128}
	for id, e := range p.entities {
		v, n, err := radarClone(e)
		if err != nil {
			return nil, err
		}
		c.entities[id] = v
		c.bytes += n + 32
		if c.bytes > 32<<20 {
			return nil, fmt.Errorf("radar checkpoint exceeds 32MiB")
		}
	}
	return c, nil
}
func (c *RadarCheckpoint) Bytes() int {
	if c == nil {
		return 0
	}
	return c.bytes
}
func (p *Parser) RestoreRadarCheckpoint(c *RadarCheckpoint) error {
	if c == nil {
		return fmt.Errorf("missing radar checkpoint")
	}
	ents := make(map[int32]*Entity, len(c.entities))
	for id, e := range c.entities {
		v, _, err := radarClone(e)
		if err != nil {
			return err
		}
		ents[id] = v
	}
	p.entities = ents
	p.entityFullPackets = c.full
	p.entityBudget = c.budget
	p.tuplesCache = nil
	return nil
}
func (p *Parser) RadarEntities() map[int]*Entity {
	ents := make(map[int]*Entity, len(p.entities))
	for id, e := range p.entities {
		if e.active {
			ents[int(id)] = e
		}
	}
	return ents
}
