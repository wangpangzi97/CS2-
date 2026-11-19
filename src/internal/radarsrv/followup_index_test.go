package radarsrv
import("os";"testing";"fmt";"path/filepath";"encoding/binary";"time";"local/cs2-radar/internal/cs2snp")
func TestFollowupIndex(t *testing.T){
 root:=os.Getenv("CS2_FOLLOWUP_DIR");if root==""{t.Skip()}
 show:=func(label string,m []byte){d:=gnsDecodeUnrel(m);if d==nil{return};for _,nm:=range d.Msgs{if nm.Cmd!=55{continue};var tick,from uint64;gnsWalkPB(nm.Body,func(f,w int,v uint64,_ []byte){if f==12{tick=v};if f==6{from=v}});if tick>=75030&&tick<=75050{fmt.Printf("INDEX %s tick=%d from=%d flag=%d seq=%d bytes=%d\n",label,tick,from,m[0],d.Seq,len(m))}}}
 files,_:=filepath.Glob(filepath.Join(root,"gns-unrel-*.bin"));for _,f:=range files{b,_:=os.ReadFile(f);k:=0;for len(b)>0{n:=int(binary.LittleEndian.Uint32(b));b=b[4:];m:=b[:n];b=b[n:];show(fmt.Sprintf("%s:%d",filepath.Base(f),k),m);k++}}
 b:=followupRead(t,"gns-plainbin-20261020-164520.bin")[12:];parser:=cs2snp.NewParser();r:=cs2snp.NewUnrelReassembler();k:=0;stream:=cs2snp.NewStream();split:=cs2snp.NewMsgSplit()
 for len(b)>0{n:=int(binary.LittleEndian.Uint32(b));b=b[4:];m:=b[:n];b=b[n:];k++;segs,un,st:=parser.Parse(m);if st.Bad!=0{continue};for _,sg:=range segs{stream.Add(sg.Pos,sg.Data)};for _,rel:=range split.Feed(stream.Take()){list,_,e:=gnsParseNetMsgs(rel);if e==nil{for _,nm:=range list{if nm.Cmd==55{var tick,from,delta uint64;gnsWalkPB(nm.Body,func(f,w int,v uint64,_ []byte){if f==12{tick=v};if f==6{from=v};if f==3{delta=v}});if tick>=75030&&tick<=75050{fmt.Printf("RELIABLE_PE frame=%d tick=%d from=%d delta=%d\n",k,tick,from,delta)}}}}};for _,u:=range un{if m,ok:=r.Feed(u,time.Now());ok{show(fmt.Sprintf("GNPB:%d",k),m)}}}
}
