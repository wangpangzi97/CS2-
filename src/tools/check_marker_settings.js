const fs=require('fs'),vm=require('vm'),assert=require('assert');
const html=fs.readFileSync(process.argv[2],'utf8').split('const RadarPage = `')[1].split('`')[0];
if(!html.includes('id="playerOpacity"')||!html.includes('function normalizeMarkerStyle')){console.log('MARKER_SETTINGS_PRESENT=false');process.exit(1);}
const ids=new Set([...html.matchAll(/\bid="([^"]+)"/g)].map(x=>x[1]));
let code=html.split('<script>')[1].split('</script>')[0];
code=code.replace('initMarkerControls();\ninitMaps();\nstartRadar();','');
function fixture(storage=new Map(),throwStorage=false){
 const nodes={},ops=[],state={globalAlpha:1},stack=[];
 const ctx=new Proxy(state,{get(t,k){if(k in t)return t[k];return (...args)=>{if(k==='save'){stack.push({...t});return;}if(k==='restore'){Object.assign(t,stack.pop());return;}ops.push({op:k,args,alpha:t.globalAlpha,fill:t.fillStyle,stroke:t.strokeStyle});};},set(t,k,v){t[k]=v;return true;}});
 function node(id){return nodes[id]??=( {id,value:'',checked:true,style:{},children:[],events:{},textContent:'',innerHTML:'',width:760,height:760,
 getContext:()=>ctx,addEventListener(n,cb){this.events[n]=cb;},appendChild(c){this.children.push(c);},replaceChildren(){this.children=[];}});}
 const doc={getElementById:id=>ids.has(id)?node(id):null,createElement:tag=>({tag,style:{},textContent:'',value:''})};
 const c={document:doc,localStorage:{getItem:k=>{if(throwStorage)throw Error('disabled');return storage.get(k)||null;},setItem:(k,v)=>{if(throwStorage)throw Error('disabled');storage.set(k,v);},removeItem:k=>storage.delete(k)},location:{search:'?session=fixture'},URLSearchParams,Image:function(){},Date,console,encodeURIComponent,window:{addEventListener:()=>{}},performance:{now:()=>0},requestAnimationFrame:()=>1,cancelAnimationFrame:()=>{},setTimeout:()=>1,clearTimeout:()=>{},AbortController,setInterval:()=>{},fetch:async()=>({json:async()=>({})})};
 vm.createContext(c);vm.runInContext(code,c);vm.runInContext('initMarkerControls()',c);
 return {c,nodes,ops,storage,run:s=>vm.runInContext(s,c),change:(k,v)=>{const el=node(k);if(typeof v==='boolean')el.checked=v;else el.value=String(v);el.events.input();}};
}
const a=fixture();
assert.equal(a.run('markerStyle.playerOpacity'),100);assert.equal(a.run('markerStyle.playerSize'),8);
assert.equal(a.run('markerStyle.myteam'),0);assert.equal(a.run('teamLabel(2)'),'T');assert.equal(a.run('teamLabel(3)'),'CT');
assert.equal(a.run('teamLabel(0)'),'阵营未知');
a.run(`latestPlayers=[{id:1,team:2,pos:{x:0,y:0},alive:true,source:'packet_entities/test'},{id:2,team:3,pos:{x:5,y:5},stale:true,age_ms:1000,alive:true,source:'packet_entities/test'},{id:3,team:2,pos:{x:8,y:8},alive:false,source:'packet_entities/test'}];latestSounds=[{pos:{x:2,y:2},age_ms:0}];draw(latestPlayers,latestSounds)`);
assert(a.ops.some(o=>o.op==='fill'&&o.fill==='#ffb020'&&o.alpha===1));
assert(a.ops.some(o=>o.op==='fill'&&o.fill==='#4aa3ff'&&o.alpha===1)); // stale remains visible, tagged separately
assert(a.ops.some(o=>o.op==='setLineDash'&&JSON.stringify(o.args[0])==='[4,3]'));
assert(a.ops.some(o=>o.op==='fillText'&&String(o.args[0]).includes('旧')));
assert(a.ops.some(o=>o.op==='fillText'&&String(o.args[0]).includes('死亡')));
a.change('myteam',2);assert.equal(a.run('teamLabel(2)'),'友军 T');assert.equal(a.run('teamLabel(3)'),'敌军 CT');
a.change('playerSize',13);a.change('playerOpacity',85);a.change('enemyColor','#aa00ef');a.change('soundColor','#aabbcc');a.change('soundOpacity',75);
assert.equal(a.run('teamColor(3)'),'#aa00ef');assert.equal(a.run('markerStyle.playerSize'),13);
a.ops.length=0;a.run('draw(latestPlayers,latestSounds)');
assert(a.ops.some(o=>o.op==='arc'&&o.args[2]===13));
assert(a.ops.some(o=>o.op==='fill'&&o.alpha===0.85&&o.fill==='#aa00ef'));
assert(a.ops.some(o=>o.op==='stroke'&&o.alpha===0.75&&o.stroke==='#aabbcc'));
a.change('showPlayers',false);a.ops.length=0;a.run('draw(latestPlayers,latestSounds)');
assert(!a.ops.some(o=>o.op==='fill'&&(o.fill==='#aa00ef'||o.fill==='#34d399')));
const b=fixture(a.storage);assert.equal(b.run('markerStyle.playerSize'),13);assert.equal(b.run('markerStyle.showPlayers'),false);
b.change('myteam',3);assert.equal(b.run('teamLabel(2)'),'敌军 T');assert.equal(b.run('teamLabel(3)'),'友军 CT');
b.nodes.resetMarkers.events.click();assert.equal(b.run('markerStyle.playerSize'),8);assert.equal(b.run('markerStyle.playerOpacity'),100);assert.equal(b.run('markerStyle.myteam'),0);
const norm=JSON.parse(a.run(`JSON.stringify(normalizeMarkerStyle({playerSize:999,playerOpacity:0,myteam:999,tColor:'javascript:bad',enemyColor:'#11aa22',showPlayers:'false'}))`));
assert.equal(norm.playerSize,16);assert.equal(norm.playerOpacity,35);assert.equal(norm.myteam,0);assert.equal(norm.tColor,'#ffb020');assert.equal(norm.enemyColor,'#11aa22');assert.equal(norm.showPlayers,true);
const c=fixture(new Map(),true);assert.equal(c.run('markerStyle.playerSize'),8);
console.log('MARKER_SETTINGS_PRESENT=true DEFAULT_SOLID=true SIZE_COLOR_OPACITY=true EXPLICIT_ALLIANCE=true STALE_DEAD_DISTINCT=true PERSIST_RESET=true BOUNDED_SETTINGS=true');
