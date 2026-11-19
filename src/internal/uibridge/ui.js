'use strict';
(() => {
 const byID=id=>document.getElementById(id),cv=byID('cv'),ctx=cv.getContext('2d');
 let frame=null,deadline=0,tracks=new Map(),image=null,imageKey='',ticket=0,changing=false,imageRetryAt=0;
 const safeID=/^[A-Za-z0-9_-]{22}$/,mapID=/^[a-z0-9_]{1,64}$/;
 function keys(o,expected){return o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===expected.slice().sort().join(',');}
 function validName(s){return typeof s==='string'&&Array.from(s).length<=32&&!/[\p{Cc}\p{Cf}]/u.test(s)&&!Array.from(s).some(c=>c.codePointAt(0)>=0xD800&&c.codePointAt(0)<=0xDFFF)&&s.replace(/\s+/gu,' ').trim()===s;}
 function valid(f){
  if(!keys(f,['v','generation','width','height','map_id','image','state','players','sounds'])||![1,2,3].includes(f.v)||!safeID.test(f.generation)||!Number.isInteger(f.width)||!Number.isInteger(f.height)||f.width<1||f.height<1||f.width>4096||f.height>4096||!['ready','sounds_only','waiting','map_required'].includes(f.state))return false;
  if(typeof f.map_id!=='string'||typeof f.image!=='string'||(f.map_id!==''&&!mapID.test(f.map_id))||(f.image!==''&&f.image!=='/mapimg/'+f.map_id+'/overview.png'&&f.image!=='/mapimg/'+f.map_id+'/density.png'))return false;
  const seen=new Set();
  for(const [name,max] of [['players',128],['sounds',512]]){
   if(!Array.isArray(f[name])||f[name].length>max)return false;
   for(const p of f[name]){const pointKeys=name==='players'&&f.v>=2?['id','px','py','team']:['id','px','py'];if(name==='players'&&f.v===3&&Object.hasOwn(p,'name'))pointKeys.push('name');if(!keys(p,pointKeys)||(name==='players'&&f.v>=2&&p.team!==2&&p.team!==3)||(Object.hasOwn(p,'name')&&!validName(p.name))||!safeID.test(p.id)||seen.has(p.id)||!Number.isInteger(p.px)||!Number.isInteger(p.py)||p.px<0||p.py<0||p.px>=f.width||p.py>=f.height)return false;seen.add(p.id);}
  }
  return !(f.state!=='ready'&&f.players.length)&&!(f.map_id===''&&(f.players.length||f.sounds.length||f.image!==''));
 }
 function clear(message='远端连接中断，画面已清空'){
  stopFollow(message);playerHits=[];renderPlayerControls(null);frame=null;deadline=0;tracks.clear();image=null;imageKey='';byID('players').textContent='0';byID('sounds').textContent='0';byID('layer').textContent='未连接';byID('connection').textContent='已暂停';byID('connection').className='badge warn';byID('mapname').textContent='等待有效视图';byID('teamStatus').textContent='等待阵营分类';byID('notice').textContent=message;paint(performance.now());
 }
 function accept(f,until){
  if(!valid(f))throw new Error('invalid frame');
  const now=performance.now();if(until<=now){clear();return;}
  if(!frame||frame.generation!==f.generation||frame.map_id!==f.map_id){stopFollow('地图或会话已变化，请重新选择人物');tracks.clear();image=null;imageKey='';}
  const next=new Map();for(const p of f.players){const old=tracks.get(p.id);const previous=old?position(old,now):[p.px,p.py];next.set(p.id,{from:previous,to:[p.px,p.py],at:now,team:p.team||0,name:p.name||''});}tracks=next;
  frame=f;deadline=until;renderPlayerControls(f);
  byID('players').textContent=String(f.players.length);byID('sounds').textContent=String(f.sounds.length);byID('connection').textContent='已授权';byID('connection').className='badge ok';byID('layer').textContent=f.state==='ready'?'可信人物 + 声音层':f.state==='map_required'?'等待地图':'仅声音层';byID('mapname').textContent=f.map_id||'请选择地图 / 等待服务端识别';
  byID('teamStatus').textContent=f.v>=2?'T / CT 阵营分类已同步':'服务器尚未提供阵营分类；人物仍可显示';
  byID('notice').textContent=f.state==='ready'?'已同步；仅使用远端像素视图':f.state==='map_required'?'地图尚未确定，不绘制未经标定的位置':'人物状态尚未同步；灰圈仅代表声音事件';
  if(f.image&&imageKey!==f.image&&now>=imageRetryAt){imageRetryAt=now+2000;const generation=f.generation,path=f.image;imageKey=path;image=null;const candidate=new Image();candidate.onload=()=>{if(frame&&frame.generation===generation&&frame.image===path)image=candidate;};candidate.onerror=()=>{if(frame&&frame.generation===generation){image=null;imageKey='';byID('notice').textContent='本地底图缺失；当前只绘制有效像素，请检查 maps 目录。';}};candidate.src=path;}
 }
 function position(t,now){const a=Math.max(0,Math.min(1,(now-t.at)/80));return [t.from[0]+(t.to[0]-t.from[0])*a,t.from[1]+(t.to[1]-t.from[1])*a];}
 function paint(now){drawAtlas(now);}
 async function api(path,options={}){
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),700);
  try{const response=await fetch(path,{...options,credentials:'same-origin',mode:'same-origin',cache:'no-store',redirect:'error',headers:{'X-Gamesense-View':'1',...(options.headers||{})},signal:controller.signal});if(!response.ok)throw new Error('unavailable');return await response.json();}finally{clearTimeout(timer);}
 }
 async function poll(){
  const mark=ticket,start=performance.now();
  try{if(!changing&&!document.hidden){const result=await api('/view');if(mark===ticket&&!changing&&!document.hidden){if(!keys(result,['state','view','valid_for_ms'])||result.state!=='active'||!Number.isInteger(result.valid_for_ms)||result.valid_for_ms<1||result.valid_for_ms>1000){clear();}else accept(result.view,start+result.valid_for_ms);}}}catch{if(mark===ticket)clear();}
  setTimeout(poll,50);
 }

 const A=window.GameAtlas,view=A.viewport(),follow=A.follow(),viewport=byID('viewport');
 let playerHits=[],playerOptionsKey='';
 const playerLabel=p=>(p.name||'未提供名字')+' · '+p.id.slice(0,4)+'…'+p.id.slice(-4);
 function renderPlayerControls(f){
  const players=f&&f.state==='ready'?f.players:[],sel=byID('playerTarget'),signature=JSON.stringify([f&&f.generation,f&&f.map_id,players.map(p=>[p.id,p.name,p.team])]);
  if(signature!==playerOptionsKey){const previous=sel.value;sel.replaceChildren();const empty=document.createElement('option');empty.value='';empty.textContent='选择人物';sel.append(empty);for(const p of players){const o=document.createElement('option');o.value=p.id;o.title=p.id;o.textContent=(p.team===2?'T':p.team===3?'CT':'人物')+' · '+playerLabel(p);sel.append(o);}sel.value=players.some(p=>p.id===previous)?previous:'';playerOptionsKey=signature;}
  byID('followSelected').disabled=!players.length;byID('nameStatus').textContent=f&&f.v===3?'显示已清理的游戏人物名称；同名人物用会话代号区分。':'当前后端未提供名字：显示临时会话代号，不伪造真实名字。';
 }
 function stopFollow(reason){follow.stop(reason);byID('followStatus').textContent=follow.reason;layoutAt=0;}
 function startFollow(){const id=byID('playerTarget').value,p=frame&&frame.players.find(p=>p.id===id);if(!p||frame.state!=='ready'||performance.now()>=deadline||currentMap()!==frame.map_id||!byID('showPlayers').checked){stopFollow('请先在当前实时地图选择有效人物');return;}follow.select(id,frame.generation,frame.map_id);view.z=Math.max(2,view.z);byID('followStatus').textContent='正在跟随 '+playerLabel(p);layoutAt=0;}

 let atlas=null,selected=null,editing=null,picking=false,busy=false,lastMap='',displayMap='',bg=null,bgKey='',bgTicket=0,bgRetryAt=0,hitPoints=[],layoutCache=[],layoutAt=0,drag=null;
 const types={smoke:'烟雾弹',flash:'闪光弹',fire:'燃烧弹',he:'手雷'},actions={left:'左键/左移',right:'右键/右移',both:'双键',jump:'跳投',nojump:'非跳投',fwd:'前进',back:'后退'};
 const clone=x=>JSON.parse(JSON.stringify(x));
 const status=s=>{byID('saveStatus').textContent=s;};
 const currentMap=()=>(frame&&frame.map_id)||lastMap;
 const rows=()=>atlas?A.filter(atlas.spots,currentMap(),byID('propSearch').value,byID('propType').value,byID('propSide').value):[];
 function tab(name){for(const e of document.querySelectorAll('[data-tab]'))e.classList.toggle('active',e.dataset.tab===name);for(const e of document.querySelectorAll('.tab-body'))e.hidden=e.id!=='tab-'+name;}
 function syncMap(force){
  const id=currentMap();if(!id)return;if(follow.id&&id!==follow.map)stopFollow('参考地图已改变，跟随停止');lastMap=(frame&&frame.map_id)||lastMap;
  const changed=id!==displayMap;if(changed||force){displayMap=id;view.mw=frame&&frame.map_id===id?frame.width:1024;view.mh=frame&&frame.map_id===id?frame.height:1024;view.reset();bg=null;bgKey='';bgTicket++;layoutAt=0;selected=null;byID('propDetail').hidden=true;renderList();}
  const meta=atlas&&atlas.maps.find(m=>m.id===id);byID('mapTitle').textContent=meta?meta.name:id;
  byID('referenceMode').textContent=frame&&id!==frame.map_id?'本地参考模式：实时人物和声音已隐藏，游戏地图识别不受影响。':'自动跟随游戏地图；底图、人物与声音保持同步。';
 }
 function renderList(){
  const list=byID('propList');list.replaceChildren();const found=rows();byID('propCount').textContent=found.length?`当前地图 ${found.length} 个匹配道具`:'这张地图没有匹配的自带点位；不自动补造。';
  if(!found.length){const e=document.createElement('p');e.className='empty';e.textContent='暂无点位。可清除筛选，或在本地编辑中新建。';list.append(e);}
  for(const {spot,prop} of found){const b=document.createElement('button');b.className='prop-item'+(selected&&selected.prop.id===prop.id?' selected':'');const title=document.createElement('strong');title.textContent=prop.name;const small=document.createElement('small');small.textContent=`${types[prop.type]} · ${prop.side==='both'?'T / CT 共用':prop.side} · ${(prop.keys.concat(prop.toss,prop.move).map(x=>actions[x]||x).join(' / '))||'见操作说明'}`;b.append(title,small);b.addEventListener('click',()=>selectProp(spot,prop,true));list.append(b);}
  byID('propTotal').textContent=atlas?String(atlas.spots.reduce((n,s)=>n+s.props.length,0)):'0';layoutAt=0;
 }
 function selectProp(spot,prop,focus){
  stopFollow('已查看道具，跟随暂停');
  selected={spot,prop};if(focus)view.focus(spot.x,spot.y);tab('props');byID('propDetail').hidden=false;byID('detailTitle').textContent=prop.name;
  byID('detailActions').textContent=`${types[prop.type]} / ${prop.side} · ${prop.keys.concat(prop.toss,prop.move).map(x=>actions[x]||x).join(' / ')}`;byID('detailNote').textContent=prop.note||'暂无额外说明';
  const box=byID('detailImages');box.replaceChildren();for(const file of prop.imgs){if(!Object.hasOwn(atlas.images,file))continue;const img=new Image();img.alt=prop.name+' 参考截图';img.loading='lazy';img.src='/atlas/image/'+file;img.addEventListener('error',()=>{img.alt='截图未通过校验或本地文件缺失';});box.append(img);}renderList();
 }
 async function loadAtlas(){
  const data=await api('/atlas/data');if(data.schema!==1||!Number.isSafeInteger(data.revision)||!Array.isArray(data.spots)||!Array.isArray(data.maps)||!data.labels||!data.images||data.spots.length>1000)throw new Error('invalid reference data');
  atlas=data;
  byID('alignmentNote').textContent=data.alignment_note;syncMap(false);renderList();status(`已加载本地点位 · 修订 ${atlas.revision} · 每次保存保留上一版备份`);
 }
 function resizeCanvas(){const r=viewport.getBoundingClientRect(),ratio=Math.min(2,window.devicePixelRatio||1);if(cv.width!==Math.round(r.width*ratio)||cv.height!==Math.round(r.height*ratio)){view.resize(r.width,r.height);cv.width=Math.round(r.width*ratio);cv.height=Math.round(r.height*ratio);layoutAt=0;}ctx.setTransform(ratio,0,0,ratio,0,0);return [r.width,r.height];}
 function drawAtlas(now){
  const [w,h]=resizeCanvas();ctx.clearRect(0,0,w,h);ctx.fillStyle='#100e12';ctx.fillRect(0,0,w,h);syncMap(false);const id=currentMap();
  let mapImage=frame&&id===frame.map_id?image:bg;
  if(id&&frame&&id!==frame.map_id&&bgKey!==id&&now>=bgRetryAt){bgKey=id;bgRetryAt=now+2000;const stamp=++bgTicket,candidate=new Image();candidate.onload=()=>{if(stamp===bgTicket&&currentMap()===id){bg=candidate;}};candidate.onerror=()=>{if(stamp===bgTicket){bgKey='';byID('notice').textContent='本地参考底图缺失；请保留完整 maps 目录。';}};candidate.src='/atlas/map/'+id;}
  const liveNow=frame&&frame.map_id===id&&now<deadline;if(follow.id){const points=liveNow&&byID('showPlayers').checked?Array.from(tracks,([id,t])=>{const p=position(t,now);return {id,x:p[0]/frame.width*100,y:p[1]/frame.height*100};}):[];const tracked=follow.update(points,frame&&frame.generation,id,view);if(!tracked)byID('followStatus').textContent=follow.reason;}
  const origin=view.toScreen(0,0),end=view.toScreen(100,100);if(mapImage)ctx.drawImage(mapImage,origin[0],origin[1],end[0]-origin[0],end[1]-origin[1]);
  if(!id){ctx.fillStyle='#81958a';ctx.font='16px Segoe UI';ctx.textAlign='center';ctx.fillText('gamesense · 等待有效远端视图',w/2,h/2);return;}
  const obstacles=[],text=[],live=liveNow;hitPoints=[];playerHits=[];ctx.globalAlpha=Number(byID('opacity').value)/100;
  if(live&&byID('showSounds').checked){ctx.strokeStyle='#9ca3a0';ctx.lineWidth=1.5;for(const p of frame.sounds){const q=view.toScreen(p.px/frame.width*100,p.py/frame.height*100);ctx.beginPath();ctx.arc(q[0],q[1],Number(byID('soundSize').value),0,Math.PI*2);ctx.stroke();}}
  if(live&&byID('showPlayers').checked){for(const [playerID,t] of tracks){ctx.fillStyle=byID('teamColors').checked&&t.team===2?byID('tColor').value:byID('teamColors').checked&&t.team===3?byID('ctColor').value:byID('playerColor').value;const p=position(t,now),q=view.toScreen(p[0]/frame.width*100,p[1]/frame.height*100),r=Number(byID('playerSize').value);ctx.beginPath();ctx.arc(q[0],q[1],r,0,Math.PI*2);ctx.fill();playerHits.push({id:playerID,x:q[0],y:q[1]});if(follow.id===playerID){ctx.strokeStyle='#fff';ctx.lineWidth=1.5;ctx.beginPath();ctx.arc(q[0],q[1],r+4,0,Math.PI*2);ctx.stroke();}if(byID('showPlayerNames').checked)text.push({text:t.name||('玩家 · '+playerID.slice(0,5)),x:q[0],y:q[1],color:ctx.fillStyle,priority:follow.id===playerID?0:1});obstacles.push({x:q[0]-r-2,y:q[1]-r-2,w:2*r+4,h:2*r+4});}}
  ctx.globalAlpha=1;
  if(atlas&&byID('showLabels').checked){for(const label of atlas.labels[id]||[]){const q=view.toScreen(label.x,label.y);text.push({text:label.text,x:q[0],y:q[1],color:'#c7d2cb',priority:3});}}
  if(atlas&&byID('showProps').checked){const seen=new Set();for(const row of rows()){const s=row.spot;if(seen.has(s.id))continue;seen.add(s.id);const q=view.toScreen(s.x,s.y);hitPoints.push({...row,x:q[0],y:q[1]});ctx.strokeStyle=selected&&selected.spot.id===s.id?'#e5f7d8':row.prop.side==='T'?'#e8ad51':row.prop.side==='CT'?'#65b6ef':'#9fe6b9';ctx.lineWidth=selected&&selected.spot.id===s.id?2.5:1.5;ctx.beginPath();ctx.moveTo(q[0],q[1]-6);ctx.lineTo(q[0]+6,q[1]);ctx.lineTo(q[0],q[1]+6);ctx.lineTo(q[0]-6,q[1]);ctx.closePath();ctx.stroke();obstacles.push({x:q[0]-8,y:q[1]-8,w:16,h:16});if(byID('showPropNames').checked)text.push({text:row.prop.name,x:q[0],y:q[1],color:ctx.strokeStyle,priority:2});}}
  if(picking&&editing){const q=view.toScreen(Number(byID('editX').value),Number(byID('editY').value));ctx.strokeStyle='#fff';ctx.strokeRect(q[0]-8,q[1]-8,16,16);}
  ctx.font='12px Segoe UI, Microsoft YaHei';ctx.textAlign='left';ctx.textBaseline='middle';
  if(now-layoutAt>100){layoutCache=A.labels(text.sort((a,b)=>(a.priority??3)-(b.priority??3)),t=>ctx.measureText(t).width,w,h,obstacles);layoutAt=now;}
  for(const t of layoutCache){const b=t.box;ctx.fillStyle='#0c151cdd';ctx.fillRect(b.x,b.y,b.w,b.h);ctx.strokeStyle='#314138';ctx.strokeRect(b.x,b.y,b.w,b.h);ctx.fillStyle=t.color;ctx.fillText(t.text,b.x+6,b.y+b.h/2,b.w-12);}
  byID('zoomRead').textContent=Math.round(view.z*100)+'%';
 }
 function beginEdit(s,p,isNew=false){stopFollow('正在编辑本地点位，跟随暂停');editing={spot:clone(s),prop:clone(p),isNew,revision:atlas.revision};picking=false;byID('spotForm').hidden=false;byID('editName').value=p.name;byID('editType').value=p.type;byID('editSide').value=p.side;byID('editX').value=s.x;byID('editY').value=s.y;byID('editKeys').value=p.keys[0]||'';byID('editToss').value=p.toss[0]||'';byID('editMove').value=p.move[0]||'';byID('editNote').value=p.note;byID('deleteSpot').hidden=isNew;tab('edit');}
 function cancelEdit(){editing=null;picking=false;byID('spotForm').hidden=true;byID('pickHint').hidden=true;viewport.classList.remove('picking');}
 async function persist(spots){if(busy||!atlas)return false;if(editing&&editing.revision!==atlas.revision){status('修订已变化，请重新打开该点位编辑，避免覆盖其他修改。');return false;}busy=true;byID('saveSpot').disabled=true;try{await api('/atlas/save',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:atlas.revision,spots})});await loadAtlas();cancelEdit();selected=null;byID('propDetail').hidden=true;status('已保存；上一版已备份。');return true;}catch{status('未保存：请检查授权或重新加载修订。原数据保留，编辑内容未清除。');return false;}finally{busy=false;byID('saveSpot').disabled=false;}}
 function initAtlas(){
  new ResizeObserver(()=>{layoutAt=0;}).observe(viewport);view.resize(viewport.clientWidth,viewport.clientHeight);view.reset();
  for(const b of document.querySelectorAll('[data-tab]'))b.addEventListener('click',()=>tab(b.dataset.tab));
  for(const id of ['propSearch','propType','propSide'])byID(id).addEventListener('input',renderList);
  for(const id of ['showLabels','showProps','showPropNames','showPlayerNames'])byID(id).addEventListener('change',()=>{layoutAt=0;});

  byID('zoomIn').addEventListener('click',()=>{view.zoom(1.25);layoutAt=0;});byID('zoomOut').addEventListener('click',()=>{view.zoom(.8);layoutAt=0;});byID('fitMap').addEventListener('click',()=>{stopFollow('已居中全图，跟随暂停');view.reset();layoutAt=0;});
  viewport.addEventListener('wheel',e=>{e.preventDefault();const r=viewport.getBoundingClientRect();view.zoom(Math.exp(-A.clamp(e.deltaY,-300,300)*.0015),e.clientX-r.left,e.clientY-r.top);layoutAt=0;},{passive:false});
  viewport.addEventListener('pointerdown',e=>{if(e.button!==0)return;drag={id:e.pointerId,x:e.clientX,y:e.clientY,sx:e.clientX,sy:e.clientY};viewport.setPointerCapture(e.pointerId);viewport.classList.add('dragging');});
  viewport.addEventListener('pointermove',e=>{if(!drag||drag.id!==e.pointerId)return;if(!picking){if(Math.hypot(e.clientX-drag.sx,e.clientY-drag.sy)>=5&&follow.id)stopFollow('已手动拖动，跟随暂停');view.pan(e.clientX-drag.x,e.clientY-drag.y);}drag.x=e.clientX;drag.y=e.clientY;layoutAt=0;});
  viewport.addEventListener('pointerup',e=>{if(!drag||drag.id!==e.pointerId)return;const click=Math.hypot(e.clientX-drag.sx,e.clientY-drag.sy)<5;drag=null;viewport.classList.remove('dragging');if(!click)return;const r=viewport.getBoundingClientRect(),x=e.clientX-r.left,y=e.clientY-r.top;if(picking&&editing){const p=view.toMap(x,y);if(p.some(v=>v<0||v>100)){status('请在地图范围内定位。');return;}byID('editX').value=p[0].toFixed(2);byID('editY').value=p[1].toFixed(2);picking=false;byID('pickHint').hidden=true;viewport.classList.remove('picking');return;}const person=playerHits.find(p=>Math.hypot(p.x-x,p.y-y)<14);if(person){stopFollow('已选择人物，等待锁定');byID('playerTarget').value=person.id;byID('followStatus').textContent='已选择人物，点击“跟随所选人物”锁定';return;}const hit=hitPoints.slice().reverse().find(p=>Math.hypot(p.x-x,p.y-y)<12);if(hit)selectProp(hit.spot,hit.prop,false);});
  viewport.addEventListener('pointercancel',()=>{drag=null;viewport.classList.remove('dragging');});
  viewport.addEventListener('keydown',e=>{if(e.key==='0'){stopFollow('已居中全图，跟随暂停');view.reset();e.preventDefault();}if(e.key==='+'||e.key==='=')view.zoom(1.25);if(e.key==='-')view.zoom(.8);if(e.key==='Escape'){stopFollow('已取消跟随');picking=false;byID('pickHint').hidden=true;viewport.classList.remove('picking');}layoutAt=0;});
  byID('closeDetail').addEventListener('click',()=>{byID('propDetail').hidden=true;});byID('editSelected').addEventListener('click',()=>{if(selected)beginEdit(selected.spot,selected.prop);});
  byID('newSpot').addEventListener('click',()=>{if(!atlas||!currentMap())return status('请等待自动识别地图并加载本地数据。');const id=()=>crypto.randomUUID().replaceAll('-',''),c=view.toMap(view.w/2,view.h/2);const s={id:'u_'+id(),map:currentMap(),x:A.clamp(c[0],0,100),y:A.clamp(c[1],0,100),props:[]};beginEdit(s,{id:'p_'+id(),name:'',type:'smoke',side:'T',keys:[],toss:[],move:[],note:'',imgs:[]},true);});
  byID('pickPosition').addEventListener('click',()=>{if(editing){picking=true;byID('pickHint').hidden=false;viewport.classList.add('picking');viewport.focus();}});byID('cancelEdit').addEventListener('click',cancelEdit);
  byID('spotForm').addEventListener('submit',async e=>{e.preventDefault();if(!editing||!atlas)return;const s=clone(editing.spot),p=clone(editing.prop);s.x=Number(byID('editX').value);s.y=Number(byID('editY').value);if(!Number.isFinite(s.x)||!Number.isFinite(s.y)||s.x<0||s.x>100||s.y<0||s.y>100)return status('坐标必须在0到100之间。');p.name=byID('editName').value.trim();if(!p.name)return status('请填写名称。');p.type=byID('editType').value;p.side=byID('editSide').value;p.note=byID('editNote').value;for(const [key,id] of [['keys','editKeys'],['toss','editToss'],['move','editMove']]){const value=byID(id).value;p[key]=value?[value]:[];}const i=s.props.findIndex(q=>q.id===p.id);if(i<0)s.props.push(p);else s.props[i]=p;const all=clone(atlas.spots),n=all.findIndex(q=>q.id===s.id);if(n<0)all.push(s);else all[n]=s;await persist(all);});
  byID('deleteSpot').addEventListener('click',()=>{if(editing&&!editing.isNew)byID('deleteDialog').showModal();});byID('cancelDelete').addEventListener('click',()=>byID('deleteDialog').close());byID('confirmDelete').addEventListener('click',async()=>{byID('deleteDialog').close();if(!editing)return;const all=clone(atlas.spots);const index=all.findIndex(s=>s.id===editing.spot.id);if(index<0)return;all[index].props=all[index].props.filter(p=>p.id!==editing.prop.id);if(!all[index].props.length)all.splice(index,1);await persist(all);});
  byID('reloadAtlas').addEventListener('click',()=>loadAtlas().catch(()=>status('加载失败；原数据未改。')));byID('restoreAtlas').addEventListener('click',()=>{if(atlas)byID('restoreDialog').showModal();});byID('cancelRestore').addEventListener('click',()=>byID('restoreDialog').close());
  byID('confirmRestore').addEventListener('click',async()=>{byID('restoreDialog').close();if(busy||!atlas)return;busy=true;try{await api('/atlas/restore',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({revision:atlas.revision})});await loadAtlas();cancelEdit();status('已恢复上一版；恢复前的数据也已备份。');}catch{status('恢复失败：可能没有备份或修订已变化。现有数据保留。');}finally{busy=false;}});
  byID('exportAtlas').addEventListener('click',()=>{if(!atlas)return;const url=URL.createObjectURL(new Blob([JSON.stringify({schema:1,revision:atlas.revision,spots:atlas.spots},null,2)],{type:'application/json'})),a=document.createElement('a');a.href=url;a.download='gamesense-atlas-'+new Date().toISOString().slice(0,10)+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
  byID('playerTarget').addEventListener('change',()=>stopFollow('已选择人物，点击跟随锁定'));byID('followSelected').addEventListener('click',startFollow);byID('stopFollow').addEventListener('click',()=>stopFollow('已手动停止跟随'));byID('showPlayers').addEventListener('change',()=>{if(!byID('showPlayers').checked)stopFollow('人物层已关闭，跟随停止');});
  loadAtlas().catch(()=>status('本地点位加载失败；请重新加载。不会改变实时绘图或覆盖已有文件。'));
 }

 function animate(now){if(frame&&now>=deadline)clear('视图已过期，画面已清空');paint(now);requestAnimationFrame(animate);}
 document.addEventListener('visibilitychange',()=>{if(document.hidden){ticket++;clear('页面已隐藏，旧画面已清空');}});
 window.addEventListener('pagehide',()=>{ticket++;clear();});
 initAtlas();clear('等待原生客户端的已授权远端视图');poll();requestAnimationFrame(animate);
 setTimeout(()=>{document.body.classList.add('loaded');byID('splash').classList.add('out');},matchMedia('(prefers-reduced-motion: reduce)').matches?0:800);
})();


(()=>{
 const canvas=document.createElement('canvas');canvas.className='particle-field';canvas.setAttribute('aria-hidden','true');document.body.prepend(canvas);const ctx=canvas.getContext('2d');if(!ctx)return;
 const reduced=matchMedia('(prefers-reduced-motion: reduce)').matches,colors=['#ed9ec8','#edb99a','#e7d48e','#a4d6b3','#c2a0ea'];let w=0,h=0,dots=[],raf=0,last=0;const mouse={x:0,y:0};
 function reset(){w=innerWidth;h=innerHeight;const ratio=Math.min(devicePixelRatio||1,1.5);canvas.width=Math.round(w*ratio);canvas.height=Math.round(h*ratio);ctx.setTransform(ratio,0,0,ratio,0,0);const n=Math.min(64,Math.max(22,Math.round(w*h/15000)));dots=Array.from({length:n},(_,i)=>({x:Math.random()*w,y:Math.random()*h,r:.7+Math.random()*1.4,vx:(Math.random()-.5)*8,vy:-3-Math.random()*7,c:colors[i%colors.length],phase:Math.random()*6.28}));if(reduced)paint(0);}
 function paint(t){const dt=last?Math.min(.04,(t-last)/1000):0;last=t;ctx.clearRect(0,0,w,h);const px=mouse.x*5,py=mouse.y*5;for(let i=0;i<dots.length;i++){const p=dots[i];if(!reduced){p.x+=p.vx*dt;p.y+=p.vy*dt;if(p.y< -10)p.y=h+10;if(p.x< -10)p.x=w+10;if(p.x>w+10)p.x=-10;}const x=p.x+px,y=p.y+py,a=.36+(Math.sin(t*.0006+p.phase)+1)*.15;ctx.globalAlpha=a;ctx.fillStyle=p.c;ctx.shadowColor=p.c;ctx.shadowBlur=p.r>1.6?9:0;ctx.beginPath();ctx.arc(x,y,p.r,0,Math.PI*2);ctx.fill();ctx.shadowBlur=0;if(i%5===0){ctx.globalAlpha=.09;ctx.strokeStyle=p.c;ctx.lineWidth=.7;ctx.beginPath();ctx.moveTo(x,y);ctx.lineTo(x-p.vx*.8,y+8);ctx.stroke();}if(i%3===0){const q=dots[(i+1)%dots.length],d=Math.hypot(p.x-q.x,p.y-q.y);if(d<105){ctx.globalAlpha=(1-d/105)*.09;ctx.strokeStyle=p.c;ctx.beginPath();ctx.moveTo(x,y);ctx.lineTo(q.x+px,q.y+py);ctx.stroke();}}}ctx.globalAlpha=1;if(!reduced&&!document.hidden)raf=requestAnimationFrame(paint);}
 addEventListener('resize',reset);addEventListener('pointermove',e=>{mouse.x=e.clientX/Math.max(w,1)-.5;mouse.y=e.clientY/Math.max(h,1)-.5;},{passive:true});document.addEventListener('visibilitychange',()=>{cancelAnimationFrame(raf);last=0;if(!document.hidden&&!reduced)raf=requestAnimationFrame(paint);});reset();if(!reduced)raf=requestAnimationFrame(paint);
})();


(()=>{
 const palette=['#eda5cf','#f2bf9d','#e7d88d','#acdcbc','#c6a4ef'];
 for(const logo of document.querySelectorAll('.product-brand,header>h1,.review-title')){
  logo.classList.add('brand-live');logo.setAttribute('aria-label','gamesense');logo.setAttribute('data-brand-motion','chroma');logo.textContent='';
  [...'gamesense'].forEach((char,i)=>{const part=document.createElement('span');part.className='brand-letter brand-letter-'+i;part.setAttribute('aria-hidden','true');part.textContent=char;logo.append(part);});
 }
})();
