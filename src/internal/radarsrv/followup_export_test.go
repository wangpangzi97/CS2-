package radarsrv
import("os";"path/filepath";"testing";"encoding/binary";"fmt")
func TestFollowupExportFixtures(t *testing.T){
 out:=os.Getenv("CS2_FOLLOWUP_EXPORT");if out==""{t.Skip("explicit export only")}
 write:=func(name string,b []byte){if e:=os.WriteFile(filepath.Join(out,name),b,0600);e!=nil{t.Fatal(e)}}
 raw:=followupRead(t,"gns-signon-20261020-164427.bin");all,_,_:=gnsSplitReliable(raw)
 for _,m:=range all{list,_,e:=gnsParseNetMsgs(m);if e!=nil{t.Fatal(e)};for _,nm:=range list{if nm.Cmd==40{write("live-serverinfo.pb",nm.Body)};if nm.Cmd==55{p:=gnsDecodePacketEnts(nm.Body);if p!=nil&&!p.IsDelta{write("live-full.pb",nm.Body)}}}}
 files,_:=filepath.Glob(filepath.Join(os.Getenv("CS2_FOLLOWUP_DIR"),"gns-unrel-*.bin"));found:=map[uint64]bool{};compressed:=false
 for _,file:=range files{b,e:=os.ReadFile(file);if e!=nil{t.Fatal(e)};for len(b)>0{n:=int(binary.LittleEndian.Uint32(b));b=b[4:];m:=b[:n];b=b[n:];d:=gnsDecodeUnrel(m);if d==nil{continue};if m[0]==4&&!compressed{write("live-compressed04.bin",m);compressed=true};for _,nm:=range d.Msgs{if nm.Cmd!=55{continue};var tick uint64;gnsWalkPB(nm.Body,func(f,w int,v uint64,_ []byte){if f==12{tick=v}});if tick==74522||tick==74523{if !found[tick]{write(fmt.Sprintf("live-%d.pb",tick),nm.Body);found[tick]=true}}}}}
 if len(found)!=2||!compressed{t.Fatal("missing live fixtures")};fmt.Println("EXPORTED real live ServerInfo/full/74522/74523/compressed04 fixtures")
}
