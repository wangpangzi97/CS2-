package radarsrv

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Handler is retained only to fail closed for old integrations. Static, empty,
// Bearer and URL tokens never enable production business routes.
func (s *Store) Handler(_ string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" && r.Method == "GET" {
			writeJSON(w, map[string]bool{"ok": true})
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "legacy data credentials disabled", http.StatusForbidden)
	})
}

// handleMapImage 提供底图字节。
//
// 路径形如 /mapimg/de_dust2/density.png。安全性靠两层：
//  1. 这里只允许「一个 id + 一个文件名」，出现多余的 "/" 或 ".." 直接拒；
//  2. mapdata.Registry.ImageBytes 只认 overview.png / density.png 两个固定名，
//     id 必须在注册表里 —— 即使第一层被绕过，也拼不出任意路径。
func (s *Store) handleMapImage(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/mapimg/")
	if rest == "" || strings.Contains(rest, "..") {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		http.NotFound(w, r)
		return
	}
	if s.mapReg == nil {
		http.Error(w, "map assets not loaded", http.StatusServiceUnavailable)
		return
	}
	b, ctype, ok := s.mapReg.ImageBytes(parts[0], parts[1])
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Cache-Control", "private, max-age=3600")
	_, _ = w.Write(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(v)
}

// RadarPage uses a single-flight 100ms poll and an independent animation loop.
const RadarPage = `<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>gamesense · 雷达</title>
<style>

 @property --gs-angle{syntax:'<angle>';initial-value:0deg;inherits:false}
 :root{color-scheme:dark;--gs-base:#101412;--gs-surface:#151b17;--gs-line:#2b3830;--gs-ink:#e2ebe5;--gs-soft:#93a59a;--gs-green:#b9d9c2}
 *{box-sizing:border-box}
 html{min-height:100%;background:#090c0a}
 body{margin:28px auto;min-height:calc(100dvh - 56px);height:auto;max-width:1392px;position:relative;isolation:isolate;background:var(--gs-base);color:var(--gs-ink);font:13px/1.7 'Segoe UI Variable','Segoe UI','Microsoft YaHei UI',sans-serif;border:1px solid #3c4d41;border-radius:14px;box-shadow:0 28px 80px #0008}
 body:before{content:'';position:absolute;inset:-2px;z-index:-2;border-radius:15px;background:conic-gradient(from var(--gs-angle),#cf9da3,#d3b479,#aaca8b,#83c1ad,#83afcf,#aaa0cd,#cf9da3);animation:gs-border 14s linear infinite;opacity:.75;pointer-events:none}
 body:after{content:'';position:absolute;inset:0;z-index:-1;background:var(--gs-base);border-radius:13px;pointer-events:none}
 @keyframes gs-border{to{--gs-angle:360deg}}
 header{padding:21px 27px;background:linear-gradient(100deg,#1c251e55,transparent);border-bottom:1px solid #2b3830;display:flex;gap:7px 12px;align-items:center;flex-wrap:wrap;border-radius:13px 13px 0 0}
 h1{font-size:22px;line-height:1.3;font-weight:600;letter-spacing:-1px;margin:0 24px 0 0;color:#edf4ef}
 h1 span{font-size:10px;letter-spacing:2px;font-weight:400;color:#82978a;display:block;line-height:1.5;margin-top:5px;text-transform:uppercase}
 .k{font-size:10px;color:#8da294;letter-spacing:.15px}
 .v{font-size:11px;color:#c1ddca;font-family:'Cascadia Code',Consolas,monospace;margin-right:7px}
 main{display:grid;grid-template-columns:minmax(0,1fr) 355px;gap:22px;padding:24px;align-items:start}
 canvas{background:#0c110e;border:1px solid #34473a;border-radius:10px;display:block;width:100%;max-width:100%;height:auto;min-width:0;box-shadow:0 8px 30px #0002}
 .panel{background:linear-gradient(145deg,#1d2a2055,transparent 55%),var(--gs-surface);border:1px solid #2e4033;border-radius:10px;padding:19px;min-width:0;max-width:100%;box-shadow:inset 0 1px #ffffff03}
 pre{margin:13px 0 0;white-space:pre-wrap;word-break:break-all;font:10px/1.9 'Cascadia Code',Consolas,monospace;color:#a9bdb1;background:#101812;padding:13px;border:1px solid #293d2f;border-radius:6px;max-height:245px;overflow:auto;scrollbar-width:thin;scrollbar-color:#3c5344 #17221b}
 .ct{color:#9bbdce}.t{color:#cfb88e}.unk{color:#bbd9c2}.snd{color:#8da294}
 #warn{display:none;margin:16px 24px 0;padding:11px 15px;border-radius:7px;background:#2d281b;border:1px solid #685b38;color:#d4c29a;font-size:12px}
 #warn b{color:#ead3a4}
 #mapwarn{display:none;margin:10px 24px 0;padding:10px 15px;border-radius:7px;background:#1a2723;border:1px solid #3a5348;color:#a4bfb0;font-size:11px}
 #mapwarn b{color:#c3decf}
 select{background:#111a14;color:#c7d9cd;border:1px solid #3a5041;border-radius:6px;padding:6px 8px;font-family:inherit;font-size:11px;min-height:30px;max-width:100%;outline-offset:3px}
 .badge{display:inline-block;padding:2px 7px;border-radius:4px;font-size:9px;border:1px solid #3b5343;color:#a0b7a7;white-space:nowrap}
 .badge.ok{border-color:#59765f;color:#c2dfca;background:#25392b}.badge.warn{border-color:#7a6945;color:#d6bf93;background:#302a1c}
 .settings{margin:19px 0;border-top:1px solid #314436;padding-top:19px}
 .settings h2{font-size:13px;font-weight:500;color:#d9e9df;margin:0 0 18px;letter-spacing:.3px}
 .settings-grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);gap:16px 13px}
 .settings label{display:flex;flex-direction:column;gap:7px;font-size:10px;color:#a9c1b1;min-width:0;line-height:1.7}
 .settings output{color:#d3e8da;font:10px 'Cascadia Code',Consolas,monospace}
 .settings input[type=range]{width:100%;min-width:0;margin:5px 0;accent-color:#a6cbb1;cursor:pointer;height:4px}
 .settings input[type=color]{width:100%;height:28px;padding:3px;box-sizing:border-box;border:1px solid #3d5646;border-radius:5px;background:#111b14;cursor:pointer}
 .settings input[type=checkbox]{accent-color:#a6cbb1;width:13px;height:13px;margin:0 5px 0 0;flex-shrink:0;cursor:pointer}
 .settings .check{flex-direction:row;align-items:center;gap:3px;font-size:10px}
 .settings button{background:#243b2d;border:1px solid #4a6854;color:#c4dfce;border-radius:6px;padding:8px 12px;cursor:pointer;font:11px inherit;transition:background .2s,border-color .2s}
 .settings button:hover{background:#304d3b;border-color:#6b9277}
 .settings .note{font-size:10px;color:#8da697;line-height:1.9;margin:13px 0}
 #legend{font-size:10px;color:#a5bcad;line-height:2;border-bottom:1px solid #2a3c2e;padding-bottom:10px}
 #legend span{display:inline-block;margin-right:4px}
 #perfinfo{border-top:1px solid #304536;padding-top:13px;margin-bottom:9px;font-family:'Cascadia Code',Consolas,monospace;font-size:9px;color:#87a18e}
 :focus-visible{outline:2px solid #b4d8be;outline-offset:3px}
 @media(min-width:1450px){body{max-width:1392px}}
 @media(max-width:1450px){body{margin:22px;max-width:none}}
 @media(max-width:1050px){main{grid-template-columns:minmax(0,1fr) 305px;gap:16px;padding:18px}.panel{padding:15px}.settings-grid{gap:13px 10px}header{padding:18px 22px;gap:6px 10px}h1{margin-right:14px}.v{margin-right:3px}}
 @media(max-width:800px){body{margin:13px;min-height:calc(100dvh - 26px)}main{grid-template-columns:minmax(0,1fr);padding:14px;gap:15px}header{padding:18px;gap:7px 9px}h1{flex-basis:100%;margin:0 0 8px;font-size:23px}h1 span{display:inline-block;margin-left:12px}.panel{padding:19px}.settings-grid{grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}#warn,#mapwarn{margin-left:14px;margin-right:14px}}
 @media(prefers-reduced-motion:reduce){*,*:before,*:after{animation:none!important;transition:none!important}}
</style></head><body>
<header>
 <h1>gamesense<span>Radar workspace</span></h1>
 <span class="k">会话</span><span class="v" id="sess">-</span>
 <span class="k">方案</span><span class="v" id="scheme">搜索中…</span>
 <span class="k">已解消息</span><span class="v" id="decoded">0</span>
 <span class="k">可解帧</span><span class="v" id="enc">0</span>
 <span class="k">可信人物</span><span class="v" id="n">0</span>
 <span class="k">声音事件</span><span class="v" id="ns">0</span>
 <span class="k">地图</span><span class="v" id="mapname">未知</span>
 <span class="badge" id="mapstate">-</span>
 <span class="k">手动指定</span><select id="mapsel"><option value="">（自动）</option></select>
</header>
<div id="warn"></div>
<div id="mapwarn"></div>
<main>
 <canvas id="cv" width="760" height="760"></canvas>
 <div class="panel">
  <div id="legend"></div>
  <section class="settings" aria-label="标记显示设置">
   <h2>标记显示设置</h2>
   <div class="settings-grid">
    <label for="myteam">我方阵营
     <select id="myteam"><option value="0">未指定（仅区分 T / CT）</option><option value="2">我方 T</option><option value="3">我方 CT</option></select></label>
    <label for="playerSize">人物大小（半径） <output id="playerSizeValue"></output>
     <input id="playerSize" type="range" min="4" max="16" step="1"></label>
    <label for="playerOpacity">人物不透明度 <output id="playerOpacityValue"></output>
     <input id="playerOpacity" type="range" min="35" max="100" step="5"></label>
    <label for="soundSize">声音圈大小 <output id="soundSizeValue"></output>
     <input id="soundSize" type="range" min="4" max="20" step="1"></label>
    <label for="soundOpacity">声音不透明度 <output id="soundOpacityValue"></output>
     <input id="soundOpacity" type="range" min="35" max="100" step="5"></label>
    <label for="soundColor">声音颜色<input id="soundColor" type="color"></label>
    <label for="tColor">T 颜色<input id="tColor" type="color"></label>
    <label for="ctColor">CT 颜色<input id="ctColor" type="color"></label>
    <label for="friendColor">友军颜色（指定我方后）<input id="friendColor" type="color"></label>
    <label for="enemyColor">敌军颜色（指定我方后）<input id="enemyColor" type="color"></label>
    <label class="check" for="showPlayers"><input id="showPlayers" type="checkbox">显示人物</label>
    <label class="check" for="showSounds"><input id="showSounds" type="checkbox">显示声音</label>
    <label class="check" for="showNames"><input id="showNames" type="checkbox">显示昵称</label>
    <label for="nameLength">昵称最大长度 <output id="nameLengthValue"></output><input id="nameLength" type="range" min="4" max="32" step="1"></label>
    <label class="check" for="smoothPlayers"><input id="smoothPlayers" type="checkbox">平滑移动（最多60ms，可关闭）</label>
   </div>
   <p class="note" id="relationnote"></p>
   <p class="note">设置仅保存在本浏览器。虚线圈和“旧”字表示旧位置，不是实时位置；空心声圈不是人物。</p>
   <button id="resetMarkers" type="button">恢复默认标记</button>
  </section>
  <p class="k" id="perfinfo">100ms非重叠刷新 · 等待性能数据</p>
  <pre id="list">等待数据…</pre>
 </div>
</main>
<script>
const q=new URLSearchParams(location.search), session=q.get('session')||'default';
const token=q.get('token')||'';
const cv=document.getElementById('cv'), ctx=cv.getContext('2d');
document.getElementById('sess').textContent=session;

const MARKER_KEY='cs2radar.markerStyle.v1';
const MARKER_DEFAULTS=Object.freeze({myteam:0,playerSize:8,playerOpacity:100,soundSize:9,soundOpacity:100,
 tColor:'#ffb020',ctColor:'#4aa3ff',friendColor:'#34d399',enemyColor:'#fb5267',soundColor:'#d1d5db',showPlayers:true,showSounds:true,showNames:true,nameLength:12,smoothPlayers:true});
function normalizeMarkerStyle(raw){
 const r=raw&&typeof raw==='object'?raw:{},o={};
 const ranges={playerSize:[4,16],playerOpacity:[35,100],soundSize:[4,20],soundOpacity:[35,100],nameLength:[4,32]};
 for(const k of Object.keys(ranges)){const n=Number(r[k]),v=Number.isFinite(n)?Math.round(n):MARKER_DEFAULTS[k];o[k]=Math.max(ranges[k][0],Math.min(ranges[k][1],v));}
 for(const k of ['tColor','ctColor','friendColor','enemyColor','soundColor'])o[k]=typeof r[k]==='string'&&/^#[0-9a-f]{6}$/i.test(r[k])?r[k]:MARKER_DEFAULTS[k];
 o.myteam=[2,3].includes(Number(r.myteam))?Number(r.myteam):0;
 for(const k of ['showPlayers','showSounds','showNames','smoothPlayers'])o[k]=typeof r[k]==='boolean'?r[k]:MARKER_DEFAULTS[k];
 return o;
}
function loadMarkerStyle(){try{return normalizeMarkerStyle(JSON.parse(localStorage.getItem(MARKER_KEY)||'null'));}catch(e){return normalizeMarkerStyle(null);}}
let markerStyle=loadMarkerStyle(), latestPlayers=[],latestSounds=[];
function teamColor(team){
 if(team!==2&&team!==3)return '#b6c2cf';
 if(markerStyle.myteam)return team===markerStyle.myteam?markerStyle.friendColor:markerStyle.enemyColor;
 return team===2?markerStyle.tColor:markerStyle.ctColor;
}
function teamLabel(team){
 const name=team===2?'T':(team===3?'CT':'阵营未知');
 if(!markerStyle.myteam||team!==2&&team!==3)return name;
 return (team===markerStyle.myteam?'友军 ':'敌军 ')+name;
}
function syncMarkerControls(){
 for(const k of Object.keys(MARKER_DEFAULTS)){
  const el=document.getElementById(k);if(!el)continue;
  if(typeof MARKER_DEFAULTS[k]==='boolean')el.checked=markerStyle[k];else el.value=String(markerStyle[k]);
  const out=document.getElementById(k+'Value');if(out)out.textContent=markerStyle[k]+(k==='nameLength'?' 字':(k.indexOf('Opacity')>=0?'%':' px'));
 }
 document.getElementById('relationnote').textContent=markerStyle.myteam?'当前以我方 '+(markerStyle.myteam===2?'T':'CT')+' 判断敌我。此项由您选择，不是自动识别本机玩家；换边后请更新。':'尚未指定我方阵营：仅按实体字段区分 T / CT，不自动判定敌我。';
 const legend=document.getElementById('legend');legend.replaceChildren();
 for(const team of [2,3]){const tag=document.createElement('span');tag.textContent='● '+teamLabel(team)+'  ';tag.style.color=teamColor(team);legend.appendChild(tag);}
 const note=document.createElement('span');note.textContent='× 死亡 · 虚线圈 = 旧位置 · 空心圈 = 声音（非人物）';legend.appendChild(note);
}
function initMarkerControls(){
 syncMarkerControls();
 for(const k of Object.keys(MARKER_DEFAULTS)){
  const el=document.getElementById(k);if(!el)continue;
  el.addEventListener('input',function(){
   const next={...markerStyle};next[k]=typeof MARKER_DEFAULTS[k]==='boolean'?el.checked:el.value;
   markerStyle=normalizeMarkerStyle(next);try{localStorage.setItem(MARKER_KEY,JSON.stringify(markerStyle));}catch(e){}
   if(k==='smoothPlayers')tracks.clear();syncMarkerControls();refreshPlayerLabels();refreshList();paintPending=true;
  });
 }
 document.getElementById('resetMarkers').addEventListener('click',function(){markerStyle=normalizeMarkerStyle(MARKER_DEFAULTS);try{localStorage.removeItem(MARKER_KEY);}catch(e){};syncMarkerControls();refreshPlayerLabels();refreshList();paintPending=true;});
}

// ---- 地图投影 ----
// 世界坐标 → 底图像素 → 画布。参数**全部来自服务端标定**（snapshot.map），
// 前端不再有任何硬编码的地图范围。
// 旧的 const R=8000 已删除：它把世界坐标硬塞进一个方框，既不是地图也没有标定，
// 看的人只能靠猜。现在没有地图定义时画的是**明确标注「不是地图」**的示意网格。
let MAP=null, mapImg=null, mapImgURI='', mapImgOK=false;
let mapImgRequest=0, mapImgLoading=false, mapImgRetryAt=0;
const FALLBACK_R=8000; // 仅用于「无地图」时的示意网格

function fit(){
  if(MAP && MAP.ref_width>0 && MAP.ref_height>0 && MAP.units_per_pixel>0){
    const s=Math.min(cv.width/MAP.ref_width, cv.height/MAP.ref_height);
    return {s:s, ox:(cv.width-MAP.ref_width*s)/2, oy:(cv.height-MAP.ref_height*s)/2,
            w:MAP.ref_width, h:MAP.ref_height};
  }
  return null;
}
function toPx(x,y){
  const f=fit();
  if(!f) return [cv.width/2 + x/FALLBACK_R*cv.width/2, cv.height/2 - y/FALLBACK_R*cv.height/2];
  const ix=(x-MAP.origin_world_x)/MAP.units_per_pixel;
  const iy=(MAP.origin_world_y-y)/MAP.units_per_pixel;
  return [f.ox+ix*f.s, f.oy+iy*f.s];
}
function loadMapImg(uri){
  const next=uri||'';
  if(next===mapImgURI && (mapImgOK || mapImgLoading || Date.now()<mapImgRetryAt)) return;
  const generation=++mapImgRequest;
  mapImgURI=next; mapImgOK=false; mapImg=null; mapImgLoading=false;
  if(!next) return;
  mapImgLoading=true;
  const im=new Image();
  im.onload=function(){
    if(generation!==mapImgRequest || next!==mapImgURI) return;
    mapImg=im; mapImgOK=true; mapImgLoading=false; mapImgRetryAt=0;paintPending=true;
  };
  im.onerror=function(){
    if(generation!==mapImgRequest || next!==mapImgURI) return;
    mapImgOK=false; mapImgLoading=false; mapImgRetryAt=Date.now()+1000;
  };
  im.src=next+(next.indexOf('?')>=0?'&':'?')+'token='+encodeURIComponent(token);
}
function drawMapLayer(){
  const f=fit();
  if(!f){
    ctx.fillStyle='#0d1117';ctx.fillRect(0,0,cv.width,cv.height);
    ctx.strokeStyle='#1f2937'; ctx.lineWidth=1;
    for(let i=0;i<=8;i++){const p=i/8*cv.width;
      ctx.beginPath();ctx.moveTo(p,0);ctx.lineTo(p,cv.height);ctx.stroke();
      ctx.beginPath();ctx.moveTo(0,p);ctx.lineTo(cv.width,p);ctx.stroke();}
    ctx.strokeStyle='#30363d';ctx.beginPath();
    ctx.arc(cv.width/2,cv.height/2,cv.width/2-2,0,Math.PI*2);ctx.stroke();
    ctx.fillStyle='#6b7785';ctx.font='12px system-ui';
    ctx.fillText('无底图：这是示意网格，不是地图',12,20);
    return;
  }
  ctx.fillStyle='#0a0e13';ctx.fillRect(0,0,cv.width,cv.height);
  if(mapImgOK&&mapImg){
    ctx.globalAlpha=0.92;
    ctx.drawImage(mapImg, f.ox, f.oy, f.w*f.s, f.h*f.s);
    ctx.globalAlpha=1;
  }
  ctx.strokeStyle='#24344d';ctx.lineWidth=1;
  ctx.strokeRect(f.ox+0.5,f.oy+0.5,f.w*f.s-1,f.h*f.s-1);

  // 坐标格：每 512 世界单位一条（dust2 约 4.4 单位/像素 ⇒ 约 116 像素一格）
  const step=512, wb=MAP.world_bounds||{};
  ctx.strokeStyle='rgba(120,150,190,.15)';ctx.lineWidth=1;
  if(wb.max_x>wb.min_x && wb.max_y>wb.min_y){
    for(let wx=Math.ceil(wb.min_x/step)*step; wx<=wb.max_x; wx+=step){
      const px=toPx(wx,0)[0];
      ctx.beginPath();ctx.moveTo(px,f.oy);ctx.lineTo(px,f.oy+f.h*f.s);ctx.stroke();
    }
    for(let wy=Math.ceil(wb.min_y/step)*step; wy<=wb.max_y; wy+=step){
      const py=toPx(0,wy)[1];
      ctx.beginPath();ctx.moveTo(f.ox,py);ctx.lineTo(f.ox+f.w*f.s,py);ctx.stroke();
    }
  }
  // 地标：只画 overview txt 里**真实存在**的锚点，不画猜的
  for(const a of (MAP.anchors||[])){
    const px=f.ox+a.norm_x*f.w*f.s, py=f.oy+a.norm_y*f.h*f.s;
    ctx.strokeStyle='rgba(74,163,255,.55)';ctx.lineWidth=1.2;
    ctx.beginPath();ctx.arc(px,py,5,0,Math.PI*2);ctx.stroke();
    ctx.fillStyle='rgba(159,180,204,.9)';ctx.font='10px monospace';
    ctx.fillText(a.name,px+7,py+3);
  }
  if(!mapImgOK){
    ctx.fillStyle='#6b7785';ctx.font='12px system-ui';
    ctx.fillText('标定已就绪，底图未加载（只画了坐标格与地标）',12,20);
  }
}
function draw(players,sounds){
  ctx.clearRect(0,0,cv.width,cv.height);drawMapLayer();
  // Source sounds remain hollow rings; opacity never makes them player dots.
  if(markerStyle.showSounds)for(const s of sounds){
    const [px,py]=toPx(s.pos.x,s.pos.y),age=Math.max(0,(s.age_ms||0)/1000);
    const radius=markerStyle.soundSize+Math.min(5,age*0.8);
    ctx.save();ctx.globalAlpha=markerStyle.soundOpacity/100*Math.max(0.4,1-age/7);
    ctx.beginPath();ctx.arc(px,py,radius,0,Math.PI*2);ctx.strokeStyle='#0b0f14';ctx.lineWidth=4;ctx.stroke();
    ctx.strokeStyle=markerStyle.soundColor;ctx.lineWidth=2;ctx.stroke();ctx.restore();
  }
  if(markerStyle.showPlayers)for(const p of players){
    const [px,py]=toPx(p.pos.x,p.pos.y),col=teamColor(p.team),stale=!!p.stale,r=markerStyle.playerSize;
    const dead=p.alive===false&&String(p.source||'').indexOf('packet_entities/')===0;
    ctx.save();ctx.globalAlpha=markerStyle.playerOpacity/100;ctx.lineJoin='round';ctx.font='12px monospace';
    if(dead){
      ctx.beginPath();ctx.moveTo(px-r,py-r);ctx.lineTo(px+r,py+r);ctx.moveTo(px+r,py-r);ctx.lineTo(px-r,py+r);
      ctx.strokeStyle='#0b0f14';ctx.lineWidth=6;ctx.stroke();ctx.strokeStyle=col;ctx.lineWidth=3;ctx.stroke();
    }else{
      ctx.beginPath();ctx.arc(px,py,r,0,Math.PI*2);ctx.fillStyle=col;ctx.fill();ctx.strokeStyle='#0b0f14';ctx.lineWidth=2;ctx.stroke();
    }
    if(stale){ctx.setLineDash([4,3]);ctx.beginPath();ctx.arc(px,py,r+4,0,Math.PI*2);ctx.strokeStyle='#f8fafc';ctx.lineWidth=2;ctx.stroke();ctx.setLineDash([]);}
    const age=Math.max(0,(p.age_ms||0)/1000);
    const label=teamLabel(p.team)+' '+displayName(p)+(dead?' 死亡':'')+(stale?' 旧 '+age.toFixed(0)+'s':'');
    const measured=ctx.measureText(label),tw=measured&&measured.width||Array.from(label).length*7;
    let tx=px+r+5;if(tx+tw>cv.width-4)tx=px-r-5-tw;tx=Math.max(4,Math.min(cv.width-tw-4,tx));
    const ty=Math.max(14,Math.min(cv.height-4,py+4));
    if(px>=0&&px<=cv.width&&py>=0&&py<=cv.height){ctx.strokeStyle='#0b0f14';ctx.lineWidth=3;ctx.strokeText(label,tx,ty);ctx.fillStyle='#f8fafc';ctx.fillText(label,tx,ty);}
    ctx.restore();
  }
}

// Nicknames are untrusted text, never HTML. Clamp by Unicode graphemes where supported.
const graphemes=typeof Intl!=='undefined'&&Intl.Segmenter?new Intl.Segmenter(undefined,{granularity:'grapheme'}):null;
function cleanNickname(v){
 return typeof v==='string'?v.slice(0,1024).normalize('NFC').replace(/\s+/g,' ').replace(/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069]/g,'').replace(/\s+/g,' ').trim():'';
}
function clippedNickname(v){
 const chars=graphemes?Array.from(graphemes.segment(v),x=>x.segment):Array.from(v);
 return chars.length>markerStyle.nameLength?chars.slice(0,markerStyle.nameLength).join('')+'…':v;
}
function playerKey(p){return (p.steam_id&&p.steam_id!=='0'?p.steam_id:'id:'+p.id)+':'+p.id+':'+p.pawn_id+':'+p.serial;}
let playerLabels=new Map();
function refreshPlayerLabels(){
 const groups=new Map(),bases=new Map();playerLabels=new Map();
 for(const p of latestPlayers){
  const name=markerStyle.showNames?cleanNickname(p.name):'';
  const base=name?clippedNickname(name):'#'+p.id;
  bases.set(playerKey(p),base);groups.set(base,(groups.get(base)||0)+1);
 }
 for(const p of latestPlayers){
  const base=bases.get(playerKey(p));
  // Disambiguate both actual duplicates and different long names that truncate alike.
  playerLabels.set(playerKey(p),base+(groups.get(base)>1?' [#'+p.id+']':''));
 }
}
function displayName(p){return playerLabels.get(playerKey(p))||'#'+p.id;}
const POLL_MS=100,SMOOTH_MS=60;
let latestSnapshot=null,receivedAt=0,paintPending=true,tracks=new Map();
let running=false,pollInFlight=false,pollTimer=null,animationID=null,activeAbort=null,lastPaint=0,pollEpoch=0;
const uiPerf={requests:0,errors:0,fetchMS:0,drawMS:0,receiveToPaintMS:0,receivedAt:0,paintedAt:-1};
function trackPosition(t,now){
 const a=Math.max(0,Math.min(1,(now-t.at)/SMOOTH_MS));
 return {x:t.from.x+(t.to.x-t.from.x)*a,y:t.from.y+(t.to.y-t.from.y)*a,z:t.from.z+(t.to.z-t.from.z)*a};
}
function updateTracks(players,now,mapChanged){
 const next=new Map();
 for(const p of players){
  const key=playerKey(p),old=mapChanged?null:tracks.get(key),pos={...p.pos};
  const canSmooth=markerStyle.smoothPlayers&&old&&!p.stale&&p.alive!==false&&old.alive===p.alive&&old.team===p.team&&!old.stale&&old.source===p.source;
  const dx=old?pos.x-old.to.x:0,dy=old?pos.y-old.to.y:0,dz=old?pos.z-old.to.z:0;
  const moved=old&&(dx!==0||dy!==0||dz!==0);
  let at=now,from=pos;
  if(canSmooth&&dx*dx+dy*dy+dz*dz<=256*256){
   if(!moved){at=old.at;from=old.from;}else{from=trackPosition(old,now);}
  }
  next.set(key,{at,from,to:pos,alive:p.alive,stale:p.stale,team:p.team,source:p.source});
 }
 tracks=next;
}
function renderPlayers(now){
 const elapsed=Math.max(0,now-receivedAt);
 return latestPlayers.map(p=>{
  const t=tracks.get(playerKey(p)),age=Math.max(0,Number(p.age_ms)||0)+elapsed;
  const stale=!!p.stale||age>1000;
  return {...p,pos:t&&markerStyle.smoothPlayers&&!stale&&p.alive!==false?trackPosition(t,now):p.pos,stale,age_ms:age};
 }).filter(p=>p.age_ms<=10000);
}
function acceptSnapshot(s,now){
 const previousMap=latestSnapshot&&latestSnapshot.map&&latestSnapshot.map.id;
 const mapChanged=previousMap!==(s.map&&s.map.id)||!s.synced;
 latestSnapshot=s;receivedAt=now;uiPerf.receivedAt=now;
 latestPlayers=Array.isArray(s.players)?s.players:[];latestSounds=Array.isArray(s.sounds)?s.sounds:[];
 updateTracks(latestPlayers,now,mapChanged);refreshPlayerLabels();
    document.getElementById('scheme').textContent=s.scheme||'搜索中…';
    document.getElementById('decoded').textContent=s.decoded_msgs;
    document.getElementById('enc').textContent=s.encrypted_frames;
    const ps=latestPlayers, snds=latestSounds;
    document.getElementById('n').textContent=ps.length;
    document.getElementById('ns').textContent=snds.length;
    // ---- 地图层 ----
    MAP = s.map || null;
    document.getElementById('mapsel').disabled = s.map_source==='serverinfo';
    loadMapImg(MAP && MAP.image_uri ? MAP.image_uri : '');
    const mn=document.getElementById('mapname'), ms=document.getElementById('mapstate');
    if(MAP){
      mn.textContent=(MAP.display_name||MAP.id)+' ('+MAP.id+')';
      ms.textContent = s.map_state==='ready' ? (s.map_source==='inferred' ? '反推' : '就绪') : s.map_state;
      ms.className = 'badge ' + (s.map_state==='ready' ? (s.map_source==='inferred'?'warn':'ok') : 'warn');
    } else {
      mn.textContent='未知'; ms.textContent=s.map_state||'unknown'; ms.className='badge warn';
    }
    // 地图不可靠时单独提示：底图是猜的 / 是数据轮廓图 / 根本没有。
    const mw=document.getElementById('mapwarn');
    if(MAP && MAP.image_kind==='data-outline'){
      mw.style.display='block';
      mw.textContent='底图是数据轮廓图｜'+(MAP.image_note||'')+' '+(s.map_status||'');
    } else if(MAP && MAP.calibration && !MAP.calibration.verified){
      mw.style.display='block';mw.textContent='底图已加载；参数尚未通过独立控制点/留出点精确标定。';
    } else if(!MAP){
      mw.style.display='block';
      mw.textContent='没有底图｜'+(s.map_status||'地图未知')+'；当前仅为世界坐标示意网格。';
    } else { mw.style.display='none'; }
    // 未同步时把原因写在最显眼的地方 —— 不要让人对着一堆点猜那是不是敌人。
    const warn=document.getElementById('warn');
    if(!s.synced){
      warn.style.display='block';
      warn.innerHTML='<b>未同步</b>｜'+(s.status||'没有可信的人物状态')+
        '<br><span class="snd">画面上的灰色空心圈是**声音事件**，不是人物当前位置。'+
        '人物位置需要等实体表（svc_PacketEntities delta）接通。</span>';
    } else { warn.style.display='none'; }
    paintPending=true;

 refreshList();
}
function refreshList(){
 const s=latestSnapshot;if(!s)return;
 const ps=latestPlayers,snds=latestSounds;
    const lines=[];
    if(ps.length){
      lines.push('【人物】');
      lines.push(...ps.map(p=>displayName(p)+' '+teamLabel(p.team)+' team='+p.team+'  x='+p.pos.x.toFixed(1)+
        ' y='+p.pos.y.toFixed(1)+' z='+p.pos.z.toFixed(1)+
        (p.stale?('  ['+(p.age_ms/1000).toFixed(0)+'s 前]'):'')));
    }
    if(snds.length){
      lines.push('【声音事件（非人物位置）】');
      lines.push(...snds.slice(0,20).map(s=>'ent='+s.ent+
        '  x='+s.pos.x.toFixed(1)+' y='+s.pos.y.toFixed(1)+' z='+s.pos.z.toFixed(1)+
        '  ['+(s.age_ms/1000).toFixed(1)+'s 前]'));
    }
    if(MAP){
      lines.unshift('【地图】'+(MAP.display_name||'')+' '+MAP.id+
        '  origin=('+MAP.origin_world_x+','+MAP.origin_world_y+') 每像素 '+MAP.units_per_pixel+' 单位'+
        '  底图='+MAP.image_kind+(s.map_source?('  来源='+s.map_source):''));
    }
    document.getElementById('list').textContent=lines.join('\n')||'（暂无）';

}
function renderFrame(now){
 if(!running)return;
 const active=markerStyle.smoothPlayers&&Array.from(tracks.values()).some(t=>now-t.at<SMOOTH_MS);
 if(paintPending||active||now-lastPaint>=100){
  const start=performance.now(),elapsed=Math.max(0,now-receivedAt);
  draw(renderPlayers(now),latestSounds.map(s=>({...s,age_ms:Math.max(0,Number(s.age_ms)||0)+elapsed})).filter(s=>s.age_ms<=10000));
  uiPerf.drawMS=performance.now()-start;
  if(uiPerf.paintedAt!==uiPerf.receivedAt){uiPerf.receiveToPaintMS=Math.max(0,now-uiPerf.receivedAt);uiPerf.paintedAt=uiPerf.receivedAt;}
  paintPending=false;lastPaint=now;
  const perf=latestSnapshot&&latestSnapshot.performance;
  const entity=perf&&perf.entity;
  const timing=entity?' · 实体均值 '+entity.packet.mean_ms.toFixed(2)+'ms · 缓存 '+(entity.cache_bytes/1048576).toFixed(1)+'MiB':'';
  document.getElementById('perfinfo').textContent='100ms非重叠刷新 · 请求 '+uiPerf.fetchMS.toFixed(1)+'ms · 绘制 '+uiPerf.drawMS.toFixed(1)+'ms'+timing;
 }
 animationID=requestAnimationFrame(renderFrame);
}
async function tick(){
 if(!running||pollInFlight)return;
 if(pollTimer!==null){clearTimeout(pollTimer);pollTimer=null;}
 pollInFlight=true;uiPerf.requests++;
 const start=performance.now(),controller=new AbortController(),epoch=pollEpoch;activeAbort=controller;
 const timeout=setTimeout(()=>controller.abort(),5000);
 try{
  const r=await fetch('/api/v1/radar?session='+encodeURIComponent(session)+'&token='+encodeURIComponent(token),{cache:'no-store',signal:controller.signal});
  if(!r.ok)throw new Error('HTTP '+r.status);
  const s=await r.json();if(!running||epoch!==pollEpoch)return;
  uiPerf.fetchMS=performance.now()-start;acceptSnapshot(s,performance.now());
 }catch(e){if(running){uiPerf.errors++;document.getElementById('list').textContent='请求失败，旧位置将标记并过期: '+e;}}
 finally{
  clearTimeout(timeout);activeAbort=null;pollInFlight=false;
  // Start-to-start cadence >=100ms, and only schedule after the previous request settles.
  if(running)pollTimer=setTimeout(tick,Math.max(0,POLL_MS-(performance.now()-start)));
 }
}
function resizeRadarCanvas(){
 const width=typeof cv.getBoundingClientRect==='function'?Math.round(cv.getBoundingClientRect().width):cv.width;
 if(width>0&&width!==cv.width){cv.width=width;cv.height=width;paintPending=true;}
}
window.addEventListener('resize',resizeRadarCanvas);
function startRadar(){
 if(running)return;running=true;paintPending=true;resizeRadarCanvas();
 if(animationID===null)animationID=requestAnimationFrame(renderFrame);
 tick();
}
function stopRadar(){
 running=false;pollEpoch++;clearTimeout(pollTimer);pollTimer=null;
 if(animationID!==null)cancelAnimationFrame(animationID);animationID=null;
 if(activeAbort)activeAbort.abort();
}
window.addEventListener('pagehide',stopRadar);
window.addEventListener('pageshow',startRadar);
// ---- 手动选图 ----
// ServerInfo.map_name 还没接通，所以给一个下拉框：选了就调 /api/v1/map，
// 服务端把它记成「manual」来源，压过坐标反推。
async function initMaps(){
  try{
    const r=await fetch('/api/v1/maps?token='+encodeURIComponent(token));
    const j=await r.json();
    const sel=document.getElementById('mapsel');
    for(const id of (j.ids||[])){
      const o=document.createElement('option'); o.value=id; o.textContent=id; sel.appendChild(o);
    }
    sel.addEventListener('change',async function(){
      try{
        const r=await fetch('/api/v1/map?token='+encodeURIComponent(token),{
          method:'POST',headers:{'Content-Type':'application/json'},
          body:JSON.stringify({session:session,name:sel.value})});
        if(!r.ok) throw new Error('地图设置失败 '+r.status);
      }catch(e){document.getElementById('list').textContent=String(e);return;}
      loadMapImg('');

      tick();
    });
  }catch(e){}
}
initMarkerControls();
initMaps();
startRadar();
</script></body></html>`
