'use strict';
// Screen-space interaction concepts reference: cs-prop-spots, MIT ©2026 nc3021.
((root)=>{
 const clamp=(x,a,b)=>Math.max(a,Math.min(b,x));
 function viewport(){
  const v={w:1,h:1,mw:1024,mh:1024,z:1,x:0,y:0};
  v.fit=()=>Math.min(v.w/v.mw,v.h/v.mh)*.96;v.scale=()=>v.fit()*v.z;
  v.toScreen=(x,y)=>[v.x+x/100*v.mw*v.scale(),v.y+y/100*v.mh*v.scale()];
  v.toMap=(x,y)=>[(x-v.x)/(v.mw*v.scale())*100,(y-v.y)/(v.mh*v.scale())*100];
  v.center=(x=50,y=50)=>{v.x=v.w/2-x/100*v.mw*v.scale();v.y=v.h/2-y/100*v.mh*v.scale();};
  v.resize=(w,h)=>{const c=v.toMap(v.w/2,v.h/2);v.w=Math.max(1,w);v.h=Math.max(1,h);v.center(...c);};
  v.reset=()=>{v.z=1;v.center();};
  v.zoom=(factor,x=v.w/2,y=v.h/2)=>{const p=v.toMap(x,y);v.z=clamp(v.z*factor,.7,8);v.x=x-p[0]/100*v.mw*v.scale();v.y=y-p[1]/100*v.mh*v.scale();};
  v.pan=(x,y)=>{v.x+=x;v.y+=y;};v.focus=(x,y)=>{v.z=Math.max(2,v.z);v.center(x,y);};return v;
 }
 function filter(spots,map,query='',type='all',side='all'){
  const q=query.trim().toLocaleLowerCase(),out=[];
  for(const s of spots){if(s.map!==map)continue;for(const p of s.props){if(type!=='all'&&p.type!==type)continue;if(side!=='all'&&p.side!==side&&p.side!=='both')continue;if(q&&!([p.name,p.note,...p.keys,...p.toss,...p.move].join(' ').toLocaleLowerCase().includes(q)))continue;out.push({spot:s,prop:p});}}return out;
 }
 const overlaps=(a,b)=>a.x<b.x+b.w&&a.x+a.w>b.x&&a.y<b.y+b.h&&a.y+a.h>b.y;
 function labels(items,measure,w,h,obstacles=[]){
  const taken=obstacles.slice(),out=[];
  for(const item of items){const width=Math.min(220,measure(item.text)+12),height=22,candidates=[[item.x+10,item.y-height/2],[item.x-width-10,item.y-height/2],[item.x-width/2,item.y-height-10],[item.x-width/2,item.y+10]];let chosen=null;
   for(const [x,y] of candidates){const b={x,y,w:width,h:height};if(x<3||y<3||x+width>w-3||y+height>h-3||taken.some(t=>overlaps(b,t)))continue;chosen=b;break;}
   if(chosen){taken.push(chosen);out.push({...item,box:chosen});}}return out;
 }
 function follow(){
  const f={id:'',generation:'',map:'',reason:'未选择跟随人物'};
  f.stop=(reason='已停止跟随')=>{f.id='';f.generation='';f.map='';f.reason=reason;};
  f.select=(id,generation,map)=>{f.id=id;f.generation=generation;f.map=map;f.reason='正在跟随';};
  f.update=(points,generation,map,v)=>{if(!f.id)return null;if(generation!==f.generation||map!==f.map){f.stop('地图或会话已变化，跟随已停止');return null;}const p=points.find(p=>p.id===f.id);if(!p||!Number.isFinite(p.x)||!Number.isFinite(p.y)){f.stop('目标已消失，跟随已停止');return null;}v.center(p.x,p.y);return p;};return f;
 }
 const api={viewport,filter,labels,overlaps,clamp,follow};root.GameAtlas=api;if(typeof module==='object'&&module.exports)module.exports=api;
})(typeof window==='object'?window:globalThis);
