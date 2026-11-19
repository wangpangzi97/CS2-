package entitycodec

// Live string-table decoding follows the LSB/key-history/UBitInt wire format in
// demoinfocs-golang v6.0.0-alpha.2/stringtables.go (MIT; vendored LICENSE).
// Unlike the DEM fallback, these baselines belong to this connection generation.
import (
	"fmt"
	"github.com/golang/snappy"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	"google.golang.org/protobuf/proto"
	"strconv"
	"strings"
)

const tableLimit = 16 << 20

type connectionTable struct {
	spec *msg.CSVCMsg_CreateStringTable
	keys map[int]string
}
type tableBits struct {
	b   []byte
	pos int
}

func (r *tableBits) read(n int) uint32 {
	if n < 0 || n > 32 || n > len(r.b)*8-r.pos {
		panic("truncated string-table bits")
	}
	var v uint32
	for i := 0; i < n; i++ {
		v |= uint32((r.b[r.pos/8]>>uint(r.pos%8))&1) << uint(i)
		r.pos++
	}
	return v
}
func (r *tableBits) varint() uint32 {
	var v uint32
	for i := 0; i < 5; i++ {
		b := r.read(8)
		if i == 4 && b > 15 {
			panic("string-table varint overflow")
		}
		v |= (b & 127) << uint(i*7)
		if b < 128 {
			return v
		}
	}
	panic("string-table varint overflow")
}
func (r *tableBits) ubitint() uint32 {
	v := r.read(6)
	switch v & 48 {
	case 16:
		return v&15 | r.read(4)<<4
	case 32:
		return v&15 | r.read(8)<<4
	case 48:
		return v&15 | r.read(28)<<4
	}
	return v
}
func (r *tableBits) text() string {
	b := make([]byte, 0, 32)
	for len(b) <= 4096 {
		c := r.read(8)
		if c == 0 {
			return string(b)
		}
		b = append(b, byte(c))
	}
	panic("string-table key limit")
}
func boundedSnappy(b []byte) ([]byte, error) {
	n, e := snappy.DecodedLen(b)
	if e != nil {
		return nil, e
	}
	if n > tableLimit {
		return nil, fmt.Errorf("string-table snappy size limit")
	}
	return snappy.Decode(nil, b)
}
func readTable(t connectionTable, b []byte, count int32) (keys map[int]string, values map[string][]byte, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("string-table: %v", p)
		}
	}()
	if len(b) > tableLimit || count < 0 || count > 16384 {
		return nil, nil, fmt.Errorf("string-table limits")
	}
	keys = make(map[int]string, len(t.keys))
	for i, k := range t.keys {
		keys[i] = k
	}
	values = map[string][]byte{}
	r := tableBits{b: b}
	history := []string{}
	index := -1
	for i := int32(0); i < count; i++ {
		if r.read(1) != 0 {
			index++
		} else {
			skip := r.varint()
			if skip > 16384 {
				return nil, nil, fmt.Errorf("string-table index limit")
			}
			index += int(skip) + 2
		}
		if index < 0 || index >= 16384 {
			return nil, nil, fmt.Errorf("string-table index limit")
		}
		key := keys[index]
		if r.read(1) != 0 {
			key = ""
			if r.read(1) != 0 {
				pos, n := int(r.read(5)), int(r.read(5))
				if pos >= len(history) || n > len(history[pos]) {
					return nil, nil, fmt.Errorf("string-table invalid key history")
				}
				key = history[pos][:n]
			}
			key += r.text()
			if len(key) > 4096 {
				return nil, nil, fmt.Errorf("string-table key limit")
			}
			keys[index] = key
			history = append(history, key)
			if len(history) > 32 {
				history = history[1:]
			}
		}
		if r.read(1) != 0 {
			compressed := false
			var bits uint32
			if t.spec.GetUserDataFixedSize() {
				n := t.spec.GetUserDataSize()
				if n < 0 || n > tableLimit*8 {
					return nil, nil, fmt.Errorf("string-table fixed size limit")
				}
				bits = uint32(n)
			} else {
				if t.spec.GetFlags()&1 != 0 {
					compressed = r.read(1) != 0
				}
				if t.spec.GetUsingVarintBitcounts() {
					n := r.ubitint()
					if n > tableLimit {
						return nil, nil, fmt.Errorf("string-table item size limit")
					}
					bits = n * 8
				} else {
					bits = r.read(17) * 8
				}
			}
			if uint64(bits) > uint64(len(b)*8-r.pos) || bits > tableLimit*8 {
				return nil, nil, fmt.Errorf("string-table item size limit")
			}
			value := make([]byte, (bits+7)/8)
			for j := 0; j < len(value); j++ {
				n := 8
				if left := int(bits) - j*8; left < 8 {
					n = left
				}
				value[j] = byte(r.read(n))
			}
			if compressed {
				value, err = boundedSnappy(value)
				if err != nil {
					return nil, nil, err
				}
			}
			if key == "" {
				return nil, nil, fmt.Errorf("string-table missing entry key")
			}
			values[key] = value
		}
	}
	return keys, values, nil
}

// SignonMessage consumes only typed metadata messages, not entity/sound guesses.
func (d *Decoder) SignonMessage(cmd uint32, body []byte) (err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("connection metadata: %v", p)
		}
		if err != nil {
			d.metadataFault = err.Error()
			d.fault = d.metadataFault
			d.ready = false
		}
	}()
	if d.info == nil || d.parser == nil {
		return nil
	}
	if len(body) > tableLimit {
		return fmt.Errorf("connection metadata size limit")
	}
	switch cmd {
	case 42:
		m := &msg.CSVCMsg_ClassInfo{}
		if err = proto.Unmarshal(body, m); err != nil {
			return err
		}
		b, e := assets.ReadFile("assets/classinfo.pb")
		if e != nil {
			return e
		}
		want := &msg.CDemoClassInfo{}
		if e = proto.Unmarshal(b, want); e != nil {
			return e
		}
		// CreateOnClient explicitly omits the class list on these captures.
		// This is a negotiated cached-class mode, NOT a wire schema fingerprint.
		if m.GetCreateOnClient() && len(m.GetClasses()) == 0 {
			d.classOK = true
			d.classMode = "client-cache"
			return nil
		}
		expected := map[int32]string{}
		for _, c := range want.GetClasses() {
			expected[c.GetClassId()] = c.GetNetworkName()
		}
		if len(m.GetClasses()) != len(expected) {
			return fmt.Errorf("当前连接ClassInfo与缓存schema不匹配：classes=%d", len(m.GetClasses()))
		}
		seen := map[int32]bool{}
		for _, c := range m.GetClasses() {
			id := c.GetClassId()
			if c.ClassId == nil || seen[id] || expected[id] == "" || expected[id] != c.GetClassName() {
				return fmt.Errorf("当前连接ClassInfo映射不匹配：class=%d", id)
			}
			seen[id] = true
		}
		d.classOK = true
		d.classMode = "wire-verified"
	case 44:
		if len(d.tables) >= 64 {
			return fmt.Errorf("connection string-table count limit")
		}
		m := &msg.CSVCMsg_CreateStringTable{}
		if err = proto.Unmarshal(body, m); err != nil {
			return err
		}
		tab := connectionTable{spec: m, keys: map[int]string{}}
		if m.GetName() == "instancebaseline" {
			if d.liveBaselines {
				return fmt.Errorf("duplicate instancebaseline table")
			}
			data := m.StringData
			if m.GetDataCompressed() {
				data, err = boundedSnappy(data)
				if err != nil {
					return err
				}
			}
			keys, values, e := readTable(tab, data, m.GetNumEntries())
			if e != nil {
				return e
			}
			tab.keys = keys
			d.baselines = map[int][]byte{}
			if e = d.applyBaselines(values); e != nil {
				return e
			}
			d.liveBaselines = true
		}
		// Payloads of unrelated tables are not retained.
		m.StringData = nil
		d.tables = append(d.tables, tab)
	case 45:
		m := &msg.CSVCMsg_UpdateStringTable{}
		if err = proto.Unmarshal(body, m); err != nil {
			return err
		}
		id := int(m.GetTableId())
		if m.TableId == nil || id < 0 || id >= len(d.tables) {
			return fmt.Errorf("unknown string-table id=%d", id)
		}
		tab := d.tables[id]
		if tab.spec.GetName() != "instancebaseline" {
			return nil
		}
		keys, values, e := readTable(tab, m.StringData, m.GetNumChangedEntries())
		if e != nil {
			return e
		}
		if e = d.applyBaselines(values); e != nil {
			return e
		}
		d.tables[id].keys = keys
	}
	return nil
}
func (d *Decoder) applyBaselines(values map[string][]byte) error {
	// Validate the entire update before committing any bytes.
	total := 0
	for id, b := range d.baselines {
		if _, replaced := values[strconv.Itoa(id)]; !replaced {
			total += len(b)
		}
	}
	for _, b := range values {
		total += len(b)
	}
	if total > 32<<20 {
		return fmt.Errorf("connection baseline memory limit")
	}
	for key := range values {
		if strings.Contains(key, ":") {
			parts := strings.Split(key, ":")
			if len(parts) != 2 {
				return fmt.Errorf("invalid alternate baseline key")
			}
			for _, p := range parts {
				if _, e := strconv.ParseUint(p, 10, 16); e != nil {
					return e
				}
			}
			continue
		}
		id, e := strconv.Atoi(key)
		if e != nil || id < 0 || id >= 222 {
			return fmt.Errorf("invalid baseline class id")
		}
	}
	for key, b := range values {
		if strings.Contains(key, ":") {
			continue
		} // Alternate baseline sets are not selected here.
		id, _ := strconv.Atoi(key)
		d.baselines[id] = b
		if d.parser != nil {
			d.parser.SetInstanceBaseline(id, b)
		}
	}
	return nil
}

func (d *Decoder) InvalidateMetadata(reason string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.metadataFault = reason
	d.fault = reason
	d.ready = false
}
func (d *Decoder) MetadataStatus() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return fmt.Sprintf("class_mode=%s tables=%d current_baselines=%d live=%v fault=%s", d.classMode, len(d.tables), len(d.baselines), d.liveBaselines, d.metadataFault)
}
