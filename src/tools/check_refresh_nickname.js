const fs=require('fs'),vm=require('vm'),assert=require('assert');
const bt=String.fromCharCode(96),source=fs.readFileSync(process.argv[2],'utf8');
const html=source.split('const RadarPage = '+bt)[1].split(bt)[0],code=html.split('<script>')[1].split('</script>')[0];
function harness(delay=20,opts={}){
 let now=0,nextID=0,seq=0,active=0,maxActive=0;const timers=new Map(),nodes={},ops=[],events={},requests=[],storage=new Map();
 const state={globalAlpha:1},stack=[];
 const ctx=new Proxy(state,{get(t,k){if(k in t)return t[k];return (...args)=>{if(k==='save'){stack.push({...t});return;}if(k==='restore'){Object.assign(t,stack.pop());return;}ops.push({op:k,args});};},set(t,k,v){t[k]=v;return true;}});
 function node(id){return nodes[id]||(nodes[id]={id,value:'',checked:true,style:{},children:[],events:{},textContent:'',innerHTML:'',width:760,height:760,getContext:()=>ctx,addEventListener(n,cb){this.events[n]=cb;},appendChild(c){this.children.push(c);},replaceChildren(){this.children=[];}});}
 const timeout=(cb,ms=0)=>{const id=++nextID;timers.set(id,{at:now+Math.max(0,ms),cb,interval:0});return id;};
 const clear=id=>timers.delete(id);
 function snapshot(){return {synced:true,scheme:'fixture',players:[{id:1,pawn_id:11,serial:1,steam_id:'fixture1',name:'同名',team:2,pos:{x:0,y:0,z:0},age_ms:0,alive:true,source:'packet_entities/test'},{id:2,pawn_id:12,serial:1,steam_id:'fixture2',name:'同名',team:3,pos:{x:10,y:20,z:0},age_ms:0,alive:true,source:'packet_entities/test'}],sounds:[]};}
 const fetch=async(url,settings={})=>{
  if(!url.includes('/api/v1/radar'))return {ok:true,status:200,json:async()=>({ids:[]})};
  const index=seq++;requests.push(now);active++;maxActive=Math.max(maxActive,active);
  return await new Promise((resolve,reject)=>{
   let done=false;const finish=(fail=false)=>{if(done)return;done=true;active--;if(fail)reject(Error('aborted'));else resolve({ok:!(opts.failFirst&&index===0),status:opts.failFirst&&index===0?503:200,json:async()=>snapshot()});};
   const latency=opts.timeoutFirst&&index===0?9000:delay;timeout(()=>finish(),latency);
   if(settings.signal)settings.signal.addEventListener('abort',()=>finish(true),{once:true});
  });
 };
 const c={document:{getElementById:node,createElement:tag=>node('created'+(++nextID))},window:{addEventListener:(n,cb)=>events[n]=cb},localStorage:{getItem:k=>storage.get(k)||null,setItem:(k,v)=>storage.set(k,v),removeItem:k=>storage.delete(k)},location:{search:'?session=fixture'},URLSearchParams,Image:function(){},performance:{now:()=>now},Date,Intl,console,encodeURIComponent,AbortController,fetch,
 setTimeout:timeout,clearTimeout:clear,setInterval:(cb,ms)=>{const id=timeout(cb,ms);timers.get(id).interval=ms;return id;},clearInterval:clear,requestAnimationFrame:cb=>timeout(()=>cb(now),16),cancelAnimationFrame:clear};
 vm.createContext(c);vm.runInContext(code,c);
 async function flush(){for(let i=0;i<16;i++)await Promise.resolve();}
 async function advance(ms){const end=now+ms;let steps=0;await flush();while(true){let id=null,item=null;for(const [i,t]of timers){if(t.at<=end&&(!item||t.at<item.at)){id=i;item=t;}}if(!item)break;if(++steps>10000)throw Error('timer runaway');now=item.at;if(item.interval)item.at+=item.interval;else timers.delete(id);item.cb();await flush();}now=end;await flush();}
 const run=s=>vm.runInContext(s,c);
 return {advance,run,nodes,ops,events,requests,storage,get maxActive(){return maxActive},get now(){return now}};
}
(async()=>{
 const normal=harness();await normal.advance(1250);
 const slow=harness(650);await slow.advance(2200);
 const gaps=normal.requests.slice(1).map((v,i)=>v-normal.requests[i]);
 const result={poll_ms:gaps.length?Math.min(...gaps):null,normal_requests:normal.requests.length,slow_max_concurrent:slow.maxActive,independent_raf:typeof normal.run('typeof renderFrame')==='string'&&normal.run('typeof renderFrame')==='function',names_toggle:html.includes('id="showNames"'),name_length:html.includes('id="nameLength"'),duplicate_disambiguation:false,unicode_safe:false,smoothing_bounded:false,stale_death_respawn_snap:false,lifecycle_stop:false,error_recovery:false,timeout_recovery:false};
 if(result.independent_raf){
  assert.equal(normal.run('pollInFlight'),false);
  normal.run('markerStyle.nameLength=4;latestPlayers=[{id:1,name:"同名",pawn_id:11,serial:1},{id:2,name:"同名",pawn_id:12,serial:1},{id:3,name:"长名称前缀甲",pawn_id:13,serial:1},{id:4,name:"长名称前缀乙",pawn_id:14,serial:1},{id:5,name:"",pawn_id:15,serial:1}];refreshPlayerLabels()');
  const labels=JSON.parse(normal.run('JSON.stringify(latestPlayers.map(displayName))'));
  assert.equal(new Set(labels).size,5);assert(labels[0].includes('#1'));assert(labels[1].includes('#2'));assert(labels[2].includes('#3'));assert.equal(labels[4],'#5');result.duplicate_disambiguation=true;
  normal.run('markerStyle.nameLength=4');
  const clipped=normal.run('clippedNickname("😀😀😀😀😀")');assert.equal(clipped,'😀😀😀😀…');
  assert.equal(normal.run('cleanNickname("\\u202e中\\n文\\u0000")'),'中 文');
  normal.run('markerStyle.showNames=false;refreshPlayerLabels()');assert.equal(normal.run('displayName(latestPlayers[0])'),'#1');result.unicode_safe=true;
  // Independent renderer does not start fetches. A midpoint is bounded between raw endpoints.
  const before=normal.requests.length;normal.run('renderFrame(performance.now())');assert.equal(normal.requests.length,before);
  normal.run('tracks.clear();markerStyle.smoothPlayers=true;latestSnapshot=null;acceptSnapshot({synced:true,players:[{id:7,pawn_id:17,serial:1,steam_id:"test7",team:2,alive:true,stale:false,age_ms:0,pos:{x:0,y:0,z:0}}],sounds:[]},0);acceptSnapshot({synced:true,players:[{id:7,pawn_id:17,serial:1,steam_id:"test7",team:2,alive:true,stale:false,age_ms:0,pos:{x:60,y:0,z:0}}],sounds:[]},100)');
  assert.equal(normal.run('renderPlayers(130)[0].pos.x'),30);assert.equal(normal.run('renderPlayers(160)[0].pos.x'),60);assert.equal(normal.run('latestPlayers[0].pos.x'),60);result.smoothing_bounded=true;
  for(const change of [{alive:false},{stale:true},{serial:2},{team:3},{pos:{x:1000,y:0,z:0}}]){
   normal.run('acceptSnapshot({synced:true,players:[{...latestPlayers[0],'+Object.entries(change).map(([k,v])=>JSON.stringify(k)+':'+JSON.stringify(v)).join(',')+',pos:'+JSON.stringify(change.pos||{x:120,y:0,z:0})+'}],sounds:[]},200)');
   assert.equal(normal.run('renderPlayers(200)[0].pos.x'),change.pos?1000:120);
  }
  assert.equal(normal.run('renderPlayers(11200).length'),0);result.stale_death_respawn_snap=true;
  normal.events.pagehide();const n=normal.requests.length;await normal.advance(600);assert.equal(normal.requests.length,n);result.lifecycle_stop=true;
  const error=harness(20,{failFirst:true});await error.advance(450);assert(error.requests.length>=4);assert.equal(error.run('uiPerf.errors'),1);result.error_recovery=true;error.events.pagehide();
  const hung=harness(20,{timeoutFirst:true});await hung.advance(5450);assert(hung.requests.length>=4);assert.equal(hung.maxActive,1);result.timeout_recovery=true;hung.events.pagehide();
  slow.events.pagehide();
 }
 console.log(JSON.stringify(result,null,2));
 const passed=result.poll_ms===100&&result.slow_max_concurrent===1&&Object.entries(result).filter(([k,v])=>typeof v==='boolean').every(([k,v])=>v);
 console.log('REFRESH_NICKNAME_ACCEPTED='+passed);
 if(process.argv[3])fs.writeFileSync(process.argv[3],JSON.stringify(result,null,2));
 if(!passed)process.exitCode=1;
})().catch(e=>{console.error(e.stack);process.exitCode=1;});

