'use strict';
(()=>{
 const $=id=>document.getElementById(id),cv=$('radar'),ctx=cv.getContext('2d'),screen=$('screen'),A=window.GameAtlas,L=window.GameViewerCore.lease(),v=A.viewport(),follow=A.follow();
 let bg=null,bgKey='',imageTicket=0,retryAt=0,selectionKey='',ready=false,ticket=0,lastGeneration='',lastMap='';
 // Fragments are not sent to HTTP servers. Never store or log the invitation.
 let invitation=location.hash.slice(1);history.replaceState(null,'',location.pathname);
 function stop(message){follow.stop(message);$('hint').textContent=message;}
 function clear(message='观看中断或权限失效，画面已清空'){
  L.clear();imageTicket++;bg=null;bgKey='';retryAt=0;selectionKey='';$('target').replaceChildren(new Option('选择人物',''));$('map').textContent='等待地图';$('count').textContent='人物 0 / 声音 0';$('empty').hidden=false;$('empty').textContent=message;$('status').textContent='已暂停';stop(message);
 }
 async function api(path,body){
  const c=new AbortController(),timer=setTimeout(()=>c.abort(),800);
  try{const r=await fetch(path,{method:body?'POST':'GET',credentials:'same-origin',mode:'same-origin',cache:'no-store',redirect:'error',signal:c.signal,headers:{'X-Gamesense-Viewer':'1',...(body?{'Content-Type':'application/json'}:{})},...(body?{body:JSON.stringify(body)}:{})});if(!r.ok)throw new Error('viewer denied');return await r.json();}finally{clearTimeout(timer);}
 }
 function accept(r,start){
  if(!L.accept(r,start,performance.now()))throw new Error('invalid view');const f=L.frame;
  if(lastGeneration!==f.generation||lastMap!==f.map_id){stop('地图或会话已变化，请重新选择跟随');bg=null;bgKey='';retryAt=0;imageTicket++;v.mw=f.width;v.mh=f.height;v.reset();lastGeneration=f.generation;lastMap=f.map_id;}
  $('status').textContent='只读 · 已连接';$('map').textContent=f.map_id||'等待地图';$('count').textContent=`人物 ${f.players.length} / 声音 ${f.sounds.length}`;$('empty').hidden=!!f.map_id;
  const signature=JSON.stringify([f.generation,f.map_id,f.players.map(p=>[p.id,p.name,p.team])]);
  if(signature!==selectionKey){const previous=$('target').value;$('target').replaceChildren(new Option('选择人物',''));for(const p of f.players)$('target').append(new Option((p.team===2?'T · ':p.team===3?'CT · ':'')+(p.name||'玩家')+' · '+p.id.slice(0,5),p.id));$('target').value=f.players.some(p=>p.id===previous)?previous:'';selectionKey=signature;}
  if(f.image&&bgKey!==f.image&&performance.now()>retryAt){retryAt=performance.now()+2000;const im=new Image(),stamp=++imageTicket;bgKey=f.image;im.onload=()=>{if(stamp===imageTicket&&L.current(performance.now()))bg=im;};im.onerror=()=>{if(stamp===imageTicket){bgKey='';$('hint').textContent='主机本地底图暂不可用';}};im.src=f.image;}
 }
 async function poll(){const mark=ticket,start=performance.now();try{if(ready&&!document.hidden){const r=await api('/view');if(mark===ticket&&!document.hidden)accept(r,start);}}catch{if(mark===ticket)clear();}setTimeout(poll,100);}
 function paint(now){
  const rect=screen.getBoundingClientRect(),ratio=Math.min(2,devicePixelRatio||1);if(cv.width!==Math.round(rect.width*ratio)||cv.height!==Math.round(rect.height*ratio)){v.resize(rect.width,rect.height);cv.width=Math.round(rect.width*ratio);cv.height=Math.round(rect.height*ratio);}ctx.setTransform(ratio,0,0,ratio,0,0);ctx.clearRect(0,0,rect.width,rect.height);
  const before=L.frame,f=L.current(now);if(before&&!f)clear('画面已过期，等待主机恢复');
  if(f){const points=f.players.map(p=>({id:p.id,x:p.px/f.width*100,y:p.py/f.height*100}));if(follow.id&&!follow.update(points,f.generation,f.map_id,v))$('hint').textContent=follow.reason;
   const a=v.toScreen(0,0),b=v.toScreen(100,100);if(bg)ctx.drawImage(bg,a[0],a[1],b[0]-a[0],b[1]-a[1]);
   ctx.lineWidth=1.5;ctx.strokeStyle='#9ca3a0';for(const p of f.sounds){const q=v.toScreen(p.px/f.width*100,p.py/f.height*100);ctx.beginPath();ctx.arc(...q,10,0,Math.PI*2);ctx.stroke();}
   const labels=[],obstacles=[];for(const p of f.players){const q=v.toScreen(p.px/f.width*100,p.py/f.height*100),color=p.team===2?'#e8ad51':p.team===3?'#65b6ef':'#b9d9c2';ctx.fillStyle=color;ctx.beginPath();ctx.arc(...q,7,0,Math.PI*2);ctx.fill();if(follow.id===p.id){ctx.strokeStyle='#fff';ctx.beginPath();ctx.arc(...q,11,0,Math.PI*2);ctx.stroke();}if($('names').checked)labels.push({text:p.name||'玩家 · '+p.id.slice(0,5),x:q[0],y:q[1],color});obstacles.push({x:q[0]-9,y:q[1]-9,w:18,h:18});}
   ctx.font='12px Segoe UI, Microsoft YaHei';ctx.textAlign='left';ctx.textBaseline='middle';for(const t of A.labels(labels,t=>ctx.measureText(t).width,rect.width,rect.height,obstacles)){ctx.fillStyle='#0c151cdd';ctx.fillRect(t.box.x,t.box.y,t.box.w,t.box.h);ctx.fillStyle=t.color;ctx.fillText(t.text,t.box.x+6,t.box.y+11,t.box.w-12);}
  }
  $('zoom').textContent=Math.round(v.z*100)+'%';requestAnimationFrame(paint);
 }
 $('plus').onclick=()=>v.zoom(1.25);$('minus').onclick=()=>v.zoom(.8);$('center').onclick=()=>{stop('已居中，跟随停止');v.reset();};$('stop').onclick=()=>stop('已停止跟随');$('target').onchange=()=>stop('已选择人物，点击跟随');
 $('follow').onclick=()=>{const f=L.current(performance.now()),id=$('target').value;if(f&&f.players.some(p=>p.id===id)){follow.select(id,f.generation,f.map_id);v.z=Math.max(v.z,2);$('hint').textContent='正在跟随所选人物；拖动或居中可退出';}};
 screen.addEventListener('wheel',e=>{e.preventDefault();const r=screen.getBoundingClientRect();v.zoom(Math.exp(-e.deltaY*.0015),e.clientX-r.left,e.clientY-r.top);},{passive:false});
 const pointers=new Map();let pinch=null,moved=0;
 screen.addEventListener('pointerdown',e=>{screen.setPointerCapture(e.pointerId);pointers.set(e.pointerId,{x:e.clientX,y:e.clientY});moved=0;pinch=null;});
 screen.addEventListener('pointermove',e=>{const prev=pointers.get(e.pointerId);if(!prev)return;const dx=e.clientX-prev.x,dy=e.clientY-prev.y;pointers.set(e.pointerId,{x:e.clientX,y:e.clientY});moved+=Math.abs(dx)+Math.abs(dy);if(moved>5)stop('已手动移动视口，跟随停止');if(pointers.size===2){const [a,b]=[...pointers.values()],d=Math.hypot(a.x-b.x,a.y-b.y),r=screen.getBoundingClientRect();if(pinch>0&&d>0)v.zoom(d/pinch,(a.x+b.x)/2-r.left,(a.y+b.y)/2-r.top);pinch=d;}else if(pointers.size===1)v.pan(dx,dy);});
 for(const type of ['pointerup','pointercancel','lostpointercapture'])screen.addEventListener(type,e=>{pointers.delete(e.pointerId);pinch=null;});
 window.addEventListener('keydown',e=>{if(e.target instanceof HTMLInputElement||e.target instanceof HTMLSelectElement)return;if(e.key==='0'){$('center').click();}if(e.key==='Escape')stop('已停止跟随');});
 document.addEventListener('visibilitychange',()=>{ticket++;if(document.hidden)clear('页面已隐藏，旧画面已清空');});window.addEventListener('pagehide',()=>{ticket++;ready=false;clear();});
 v.resize(screen.clientWidth,screen.clientHeight);v.reset();requestAnimationFrame(paint);
 (async()=>{try{if(invitation){if(!/^[A-Za-z0-9_-]{43}$/.test(invitation))throw new Error('invalid invitation');await api('/session',{invite:invitation});}ready=true;}catch{clear('观看链接无效、已过期或人数已满；请联系主机重新分享');}finally{invitation='';poll();}})();
})();
