package radarsrv
import("testing";"strings";"crypto/sha256";"fmt";"net/http/httptest")
func TestGamesenseReleaseUI(t *testing.T){
 if !strings.Contains(RadarPage,"gamesense")||!strings.Contains(RadarPage,"conic-gradient"){t.Fatal("theme missing")}
 a:=strings.Index(RadarPage,"<script>")+len("<script>");b:=strings.Index(RadarPage,"</script>");if a<len("<script>")||b<a{t.Fatal("script delimiters")}
 if fmt.Sprintf("%x",sha256.Sum256([]byte(RadarPage[a:b])))!="90be37c9918173d51ad31b4fdc3f268c9fe8ee74359b49f4a097d61abb2001bc"{t.Fatal("runtime JS changed")}
 h:=NewStore(DefaultConfig()).fixtureHandler("ui-release-test");r:=httptest.NewRequest("GET","http://localhost/radar?token=ui-release-test",nil);v:=httptest.NewRecorder();h.ServeHTTP(v,r)
 if v.Code!=200||v.Body.String()!=RadarPage{t.Fatalf("template handler %d",v.Code)}
}
