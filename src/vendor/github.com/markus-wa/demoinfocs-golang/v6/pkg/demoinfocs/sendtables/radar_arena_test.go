package sendtables

import (
	"reflect"
	"testing"
)

func TestRadarArenaIsolation(t *testing.T) {
	child := &fieldState{state: make([]any, 2, 8)}
	child.state[0] = []byte{1, 2}
	child.state[1] = []any{[]float32{3, 4}, "name"}
	root := &fieldState{state: make([]any, 3, 16)}
	root.state[0] = child
	root.state[1] = []uint64{5, 6}
	root.state[2] = (*fieldState)(nil)
	old, n := radarValue(root)
	bulk, m := radarArenaValue(root)
	if n != m || !reflect.DeepEqual(old, bulk) {
		t.Fatal("clone value or budget changed")
	}
	a := bulk.(*fieldState)
	if cap(a.state) != 16 || cap(a.state[0].(*fieldState).state) != 8 {
		t.Fatal("capacity changed")
	}
	a.state[0].(*fieldState).state[0].([]byte)[0] = 99
	a.state[0].(*fieldState).state[1].([]any)[0].([]float32)[0] = 88
	a.state[1].([]uint64)[0] = 77
	a.state[0].(*fieldState).state = append(a.state[0].(*fieldState).state, 123)
	if !reflect.DeepEqual(root, old) {
		t.Fatal("clone aliases original")
	}
	newer, _ := radarArenaValue(root)
	if !reflect.DeepEqual(newer, old) {
		t.Fatal("checkpoint mutated")
	}
}

func TestRadarCheckpointCopyOnWrite(t *testing.T) {
	e := &Entity{state: &fieldState{state: make([]any, 2, 8)}}
	e.state.state[0] = []any{[]byte{1, 2}, "initial"}
	e.state.state[1] = []uint64{5, 6}
	frozen, n, err := radarClone(e)
	if err != nil {
		t.Fatal(err)
	}
	if frozen.state != e.state || !e.radarShared {
		t.Fatal("checkpoint did not freeze")
	}
	detached := *frozen
	detached.radarDetach()
	if detached.state == frozen.state || detached.radarShared {
		t.Fatal("restore did not detach")
	}
	detached.state.state[0].([]any)[0].([]byte)[0] = 99
	e.radarDetach()
	e.state.state[1].([]uint64)[0] = 77
	if frozen.state.state[0].([]any)[0].([]byte)[0] != 1 || frozen.state.state[1].([]uint64)[0] != 5 {
		t.Fatal("frozen checkpoint aliased mutable state")
	}
	if n != radarEstimate(frozen.state)+512 {
		t.Fatal("budget changed")
	}
	second, _, err := radarClone(frozen)
	if err != nil || second.state != frozen.state {
		t.Fatal("unchanged state copied")
	}
}
