'use strict';
((root)=>{
 const id=/^[A-Za-z0-9_-]{22}$/,map=/^[a-z0-9_]{1,64}$/;
 const keys=(o,k)=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===k.slice().sort().join(',');
 const name=s=>typeof s==='string'&&Array.from(s).length<=32&&!/[\p{Cc}\p{Cf}]/u.test(s)&&!Array.from(s).some(c=>c.codePointAt(0)>=0xD800&&c.codePointAt(0)<=0xDFFF)&&s.replace(/\s+/gu,' ').trim()===s;
 function valid(f){
  if(!keys(f,['v','generation','width','height','map_id','image','state','players','sounds'])||![1,2,3].includes(f.v)||!id.test(f.generation)||!Number.isInteger(f.width)||!Number.isInteger(f.height)||f.width<1||f.height<1||f.width>4096||f.height>4096||!['ready','sounds_only','waiting','map_required'].includes(f.state))return false;
  if(typeof f.map_id!=='string'||typeof f.image!=='string'||(f.map_id!==''&&!map.test(f.map_id))||(f.image!==''&&f.image!=='/mapimg/'+f.map_id+'/overview.png'&&f.image!=='/mapimg/'+f.map_id+'/density.png'))return false;
  const seen=new Set();for(const [group,max] of [['players',128],['sounds',512]]){
   if(!Array.isArray(f[group])||f[group].length>max)return false;
   for(const p of f[group]){const k=group==='players'&&f.v>=2?['id','px','py','team']:['id','px','py'];if(group==='players'&&f.v===3&&p&&Object.hasOwn(p,'name'))k.push('name');if(!keys(p,k)||(group==='players'&&f.v>=2&&p.team!==2&&p.team!==3)||(Object.hasOwn(p,'name')&&!name(p.name))||!id.test(p.id)||seen.has(p.id)||!Number.isInteger(p.px)||!Number.isInteger(p.py)||p.px<0||p.py<0||p.px>=f.width||p.py>=f.height)return false;seen.add(p.id);}
  }
  return !(f.state!=='ready'&&f.players.length)&&!(f.map_id===''&&(f.players.length||f.sounds.length||f.image!==''));
 }
 function lease(){return {frame:null,deadline:0,clear(){this.frame=null;this.deadline=0;},accept(r,start,now){this.clear();if(!keys(r,['state','view','valid_for_ms'])||r.state!=='active'||!Number.isInteger(r.valid_for_ms)||r.valid_for_ms<1||r.valid_for_ms>1000||!valid(r.view)||start+r.valid_for_ms<=now)return false;this.frame=r.view;this.deadline=start+r.valid_for_ms;return true;},current(now){if(now>=this.deadline)this.clear();return this.frame;}};}
 const api={valid,lease};root.GameViewerCore=api;if(typeof module==='object'&&module.exports)module.exports=api;
})(typeof window==='object'?window:globalThis);
