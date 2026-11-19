package main

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/golang/snappy"
	"github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/msg"
	st "github.com/markus-wa/demoinfocs-golang/v6/pkg/demoinfocs/sendtables"
	"google.golang.org/protobuf/proto"
	"io"
	"local/cs2-radar/internal/entitycodec"
	"math"
	"os"
	"sort"
	"time"
)

type bits struct {
	b []byte
	p int
}

func (r *bits) read(n int) (uint32, error) {
	if n < 0 || r.p+n > len(r.b)*8 {
		return 0, io.ErrUnexpectedEOF
	}
	var v uint32
	for j := 0; j < n; j++ {
		v |= uint32((r.b[r.p>>3]>>uint(r.p&7))&1) << uint(j)
		r.p++
	}
	return v, nil
}
func (r *bits) ubit() (uint32, error) {
	v, e := r.read(6)
	if e != nil {
		return 0, e
	}
	n := map[uint32]int{0: 0, 16: 4, 32: 8, 48: 28}[v&48]
	if n == 0 {
		return v, nil
	}
	x, e := r.read(n)
	return (v & 15) | (x << 4), e
}
func (r *bits) vint() (uint32, error) {
	var v uint32
	for k := 0; k < 5; k++ {
		c, e := r.read(8)
		if e != nil {
			return 0, e
		}
		v |= (c & 127) << uint(7*k)
		if c < 128 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("varint")
}

type player struct {
	ID      int
	Pawn    int
	Serial  int
	Name    string
	Steam   string
	Team    int
	Health  int
	Alive   bool
	X, Y, Z float64
}

func val(e *st.Entity, k string) any {
	if e == nil {
		return nil
	}
	v, ok := e.PropertyValue(k)
	if !ok {
		return nil
	}
	return v.Any
}
func uintVal(v any) uint64 {
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
func players(ents map[int]*st.Entity) []player {
	out := []player{}
	for _, c := range ents {
		if c.ServerClass().Name() != "CCSPlayerController" {
			continue
		}
		if val(c, "m_iConnected") == nil || uintVal(val(c, "m_iConnected")) != 0 {
			continue
		}
		team := int(uintVal(val(c, "m_iTeamNum")))
		if team != 2 && team != 3 {
			continue
		}
		h := uintVal(val(c, "m_hPlayerPawn"))
		p := ents[int(h&16383)]
		if p == nil || p.ServerClass().Name() != "CCSPlayerPawn" || (uint64(p.SerialNum())&1023) != (h>>14)&1023 {
			continue
		}
		pos := p.Position()
		if math.IsNaN(pos.X) || math.IsInf(pos.X, 0) {
			continue
		}
		name, _ := val(c, "m_iszPlayerName").(string)
		out = append(out, player{c.ID(), p.ID(), p.SerialNum(), name, fmt.Sprint(val(c, "m_steamID")), team, int(uintVal(val(p, "m_iHealth"))), uintVal(val(p, "m_lifeState")) == 0, pos.X, pos.Y, pos.Z})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
func must(e error) {
	if e != nil {
		panic(e)
	}
}
func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "用法: demoreplay.exe 录像.dem 输出.json")
		os.Exit(2)
	}
	defer func() {
		if p := recover(); p != nil {
			fmt.Fprintln(os.Stderr, "离线解析失败:", p)
			os.Exit(1)
		}
	}()

	f, e := os.Open(os.Args[1])
	must(e)
	defer f.Close()
	r := bufio.NewReader(f)
	head := make([]byte, 16)
	_, e = io.ReadFull(r, head)
	must(e)
	if string(head[:8]) != "PBDEMS2\x00" {
		panic("header")
	}
	parser := st.NewParser()
	ents := map[int]*st.Entity{}
	parser.OnEntity(func(e *st.Entity, op st.EntityOp) error {
		if op.Flag(st.EntityOpDeleted) {
			delete(ents, e.ID())
		} else {
			ents[e.ID()] = e
		}
		return nil
	})
	codec := entitycodec.New()
	codecFaults := 0
	codecMax := 0
	codecFinal := 0
	coordinateMismatches := 0
	packets := 0
	hist := map[int]int{}
	samples := []map[string]any{}
	maxPlayers := 0
	minPlayers := 100
	empty := 0
	final := []player{}
	classes := 0
	schema := false
	tables := func(m *msg.CDemoStringTables) {
		for _, t := range m.GetTables() {
			if t.GetTableName() == "instancebaseline" {
				for _, i := range t.GetItems() {
					var id int
					_, e := fmt.Sscan(i.GetStr(), &id)
					if e == nil {
						parser.SetInstanceBaseline(id, i.GetData())
					}
				}
			}
		}
	}
	feed := func(data []byte, tick uint64) {
		br := &bits{b: data}
		for len(data)*8-br.p > 8 {
			cmd, e := br.ubit()
			if e != nil {
				return
			}
			n, e := br.vint()
			if e != nil || int(n) > (len(data)*8-br.p)/8 {
				return
			}
			body := make([]byte, n)
			for i := range body {
				v, e := br.read(8)
				must(e)
				body[i] = byte(v)
			}
			switch cmd {
			case 40:
				m := &msg.CSVCMsg_ServerInfo{}
				must(proto.Unmarshal(body, m))
				must(parser.OnServerInfo(m))
				must(codec.ServerInfo(body))
			case 55:
				if !schema || classes == 0 {
					continue
				}
				m := &msg.CSVCMsg_PacketEntities{}
				must(proto.Unmarshal(body, m))
				must(parser.OnPacketEntities(m))
				packets++
				tm := time.Unix(0, 0).Add(time.Duration(tick) * time.Second / 64)
				if err := codec.PacketEntities(body, tm); err != nil {
					codecFaults++
					if codecFaults < 4 {
						fmt.Printf("CODEC_FAULT %v\n", err)
					}
				}
				decoded, syncd, _ := codec.Snapshot(tm)
				if !syncd {
					codecFaults++
				}
				codecFinal = len(decoded)
				if len(decoded) > codecMax {
					codecMax = len(decoded)
				}

				ps := players(ents)
				byID := map[int]player{}
				for _, p := range ps {
					byID[p.ID] = p
				}
				if len(decoded) != len(ps) {
					coordinateMismatches++
				}
				for _, p := range decoded {
					ref, ok := byID[p.ID]
					if !ok || p.PawnID != ref.Pawn || p.Name != ref.Name || p.Team != ref.Team || p.Health != ref.Health || p.Alive != ref.Alive || math.Abs(float64(p.Pos.X)-ref.X) > 0.001 || math.Abs(float64(p.Pos.Y)-ref.Y) > 0.001 || math.Abs(float64(p.Pos.Z)-ref.Z) > 0.001 {
						coordinateMismatches++
					}
				}

				hist[len(ps)]++
				if len(ps) > maxPlayers {
					maxPlayers = len(ps)
				}
				if len(ps) > 0 && len(ps) < minPlayers {
					minPlayers = len(ps)
				}
				if len(ps) == 0 {
					empty++
				}
				final = ps
				if packets%1000 == 0 || (len(ps) == 10 && len(samples) == 0) {
					samples = append(samples, map[string]any{"tick": tick, "packet": packets, "players": ps})
				}
			}
		}
	}
	commands := 0
	for {
		c, e := binary.ReadUvarint(r)
		if e == io.EOF {
			break
		}
		must(e)
		tick, e := binary.ReadUvarint(r)
		must(e)
		n, e := binary.ReadUvarint(r)
		must(e)
		if n > 64<<20 {
			panic("size")
		}
		b := make([]byte, n)
		_, e = io.ReadFull(r, b)
		must(e)
		if c&64 != 0 {
			if size, err := snappy.DecodedLen(b); err != nil || size > 64<<20 {
				panic("snappy output limit")
			}
			b, e = snappy.Decode(nil, b)
			must(e)
		}
		c &= 63
		commands++
		switch c {
		case 0:
			goto done
		case 1:
			m := &msg.CDemoFileHeader{}
			must(proto.Unmarshal(b, m))
			fmt.Printf("HEADER protocol=%d build=%d map=%s\n", m.GetPatchVersion(), m.GetBuildNum(), m.GetMapName())
		case 4:
			m := &msg.CDemoSendTables{}
			must(proto.Unmarshal(b, m))
			must(parser.ParsePacket(m.GetData()))
			schema = true
		case 5:
			m := &msg.CDemoClassInfo{}
			must(proto.Unmarshal(b, m))
			must(parser.OnDemoClassInfo(m))
			classes = len(m.GetClasses())
		case 6:
			m := &msg.CDemoStringTables{}
			must(proto.Unmarshal(b, m))
			tables(m)
		case 7, 8:
			m := &msg.CDemoPacket{}
			must(proto.Unmarshal(b, m))
			feed(m.GetData(), tick)
		case 13:
			m := &msg.CDemoFullPacket{}
			must(proto.Unmarshal(b, m))
			tables(m.GetStringTable())
			if m.GetPacket() != nil {
				feed(m.GetPacket().GetData(), tick)
			}
		}
	}
done:
	result := map[string]any{"commands": commands, "entity_packets": packets, "classes": classes, "schema": schema, "min_nonzero_players": minPlayers, "max_players": maxPlayers, "empty_snapshots": empty, "player_count_histogram": hist, "final_players": final, "samples": samples, "production_codec_faults": codecFaults, "coordinate_or_identity_mismatches": coordinateMismatches, "production_codec_max_players": codecMax, "production_codec_final_players": codecFinal}
	out, e := json.MarshalIndent(result, "", "  ")
	must(e)
	must(os.WriteFile(os.Args[2], out, 0600))
	fmt.Printf("PRODUCTION_CODEC faults=%d max=%d final=%d coordinate_identity_mismatches=%d\n", codecFaults, codecMax, codecFinal, coordinateMismatches)
	fmt.Printf("RESULT entity_packets=%d classes=%d min_nonzero=%d max=%d final=%d samples=%d\n", packets, classes, minPlayers, maxPlayers, len(final), len(samples))
}
