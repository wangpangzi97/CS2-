package radarsrv

import "bytes"

// Called only after both complete candidates pass the existing strict score
// validation. Ignore only empty net_NOPs, whose command and body are both zero.
// Every other command, body byte and message order must be identical. Do not
// normalize protobuf fields, ignore unknown commands, or guess between two
// different entity payloads. The caller also requires identical tail lengths.
func gnsUnrelEquivalentMessages(a, b []gnsUnrelMsg) bool {
	i, j := 0, 0
	for {
		for i < len(a) && a[i].Cmd == 0 && len(a[i].Body) == 0 {
			i++
		}
		for j < len(b) && b[j].Cmd == 0 && len(b[j].Body) == 0 {
			j++
		}
		if i == len(a) || j == len(b) {
			return i == len(a) && j == len(b)
		}
		if a[i].Cmd != b[j].Cmd || !bytes.Equal(a[i].Body, b[j].Body) {
			return false
		}
		i++
		j++
	}
}
