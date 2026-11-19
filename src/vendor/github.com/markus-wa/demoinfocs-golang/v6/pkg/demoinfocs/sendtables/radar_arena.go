package sendtables

// Bulk allocation only: keep every value, slice capacity and budget unchanged.
// Each clone owns its arena; no mutable state is shared across checkpoints.
type radarArena struct {
	states              []fieldState
	slots               []any
	nextState, nextSlot int
}

func radarArenaShape(v any) (states, slots int) {
	switch x := v.(type) {
	case *fieldState:
		if x == nil {
			return
		}
		states = 1
		slots = cap(x.state)
		for _, v := range x.state {
			n, m := radarArenaShape(v)
			states += n
			slots += m
		}
	case []any:
		slots = len(x)
		for _, v := range x {
			n, m := radarArenaShape(v)
			states += n
			slots += m
		}
	}
	return
}
func radarArenaValue(v any) (any, int) {
	n, m := radarArenaShape(v)
	a := radarArena{states: make([]fieldState, n), slots: make([]any, m)}
	return a.clone(v)
}
func (a *radarArena) clone(v any) (any, int) {
	switch x := v.(type) {
	case *fieldState:
		if x == nil {
			return (*fieldState)(nil), 0
		}
		out := &a.states[a.nextState]
		a.nextState++
		off := a.nextSlot
		a.nextSlot += cap(x.state)
		// Full slice expression isolates each state's spare capacity.
		out.state = a.slots[off : off+len(x.state) : off+cap(x.state)]
		n := 32 + cap(x.state)*24
		for i, v := range x.state {
			var extra int
			out.state[i], extra = a.clone(v)
			n += extra
		}
		return out, n
	case []any:
		off := a.nextSlot
		a.nextSlot += len(x)
		out := a.slots[off : off+len(x) : off+len(x)]
		n := 24 + len(x)*24
		for i, v := range x {
			var extra int
			out[i], extra = a.clone(v)
			n += extra
		}
		return out, n
	default:
		return radarValue(v)
	}
}

// readFields is the only mutator of existing entity state and polymorphic slices.
// Enter/leave/delete metadata lives on each separate Entity struct.
func (e *Entity) radarDetach() {
	if !e.radarShared {
		return
	}
	state, _ := radarArenaValue(e.state)
	e.state = state.(*fieldState)
	e.polySerializers = append([]*serializer(nil), e.polySerializers...)
	e.radarShared = false
}
func radarEstimate(v any) int {
	switch x := v.(type) {
	case *fieldState:
		if x == nil {
			return 0
		}
		n := 32 + cap(x.state)*24
		for _, v := range x.state {
			n += radarEstimate(v)
		}
		return n
	case []any:
		n := 24 + len(x)*24
		for _, v := range x {
			n += radarEstimate(v)
		}
		return n
	case []float32:
		return 24 + len(x)*4
	case []float64:
		return 24 + len(x)*8
	case []uint64:
		return 24 + len(x)*8
	case []byte:
		return 24 + len(x)
	case string:
		return len(x)
	default:
		return 0
	}
}
