package capturefilter

import "testing"

func TestTelemetryDistinguishesOwnedAndAdmittedWithoutChangingMatch(t *testing.T) {
	f := New()
	if f.ClassifyLocal(10) != 0 {
		t.Fatal("empty")
	}
	f.Set(123, []uint16{10})
	if f.ClassifyLocal(10) != 1 || f.ClassifyLocal(20) != 3 || f.OwnedPortCount() != 1 {
		t.Fatal("ownership snapshot")
	}
	f.AutoAdmit(20, 30)
	if !f.Match(20, 30) || f.ClassifyLocal(20) != 2 || f.OwnedPortCount() != 1 {
		t.Fatal("admission contaminated ownership")
	}
	f.AddPort(40)
	if f.ClassifyLocal(40) != 2 {
		t.Fatal("add is not ownership")
	}
	f.Set(123, []uint16{20})
	if f.ClassifyLocal(20) != 1 || f.ClassifyLocal(10) != 3 {
		t.Fatal("refresh")
	}
	f.Clear()
	if f.ClassifyLocal(20) != 0 || f.OwnedPortCount() != 0 || !f.Match(10, 20) {
		t.Fatal("clear")
	}
}
