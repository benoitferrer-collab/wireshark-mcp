const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),vm=require('node:vm');
function setup(fetch){
 const nodes=new Map();const node=id=>{if(!nodes.has(id))nodes.set(id,{style:{},textContent:'',disabled:false});return nodes.get(id)};
 const events=[],timers=new Map();let seq=0;
 const context={fetch,console:{error(){}},setInterval:fn=>{timers.set(++seq,fn);return seq},clearInterval:id=>timers.delete(id),setTimeout,clearTimeout,AbortSignal,CustomEvent:class{constructor(type,options){this.type=type;this.detail=options?.detail}},document:{getElementById:node,dispatchEvent:e=>events.push(e)},window:{PcapSupport:{setHistoryState:(...args)=>events.push(args)}}};
 vm.runInNewContext(fs.readFileSync('static/js/app.js','utf8').split('// Initialize')[0]+'\nglobalThis.Analyzer=PCAPAnalyzer;',context);
 const app=Object.create(context.Analyzer.prototype);app.currentTaskId='old';app.currentResults={filename:'old'};
 app.showToast=(...args)=>events.push(args);app.displayResults=r=>{app.currentResults=r};app.triggerTabDataLoad=()=>{};app.requestChartsResize=()=>{};app.resetUploadArea=()=>{};app.showError=()=>{};app.updateProgress=()=>{};app.displayHistory=x=>events.push(x);node('resultsSection').scrollIntoView=()=>{};
 return {app,nodes,events,timers,context};
}
const ok=data=>({ok:true,status:200,json:async()=>data});
test('late capture A cannot overwrite newer capture B',async()=>{
 let resolveA;const {app}=setup(url=>url.endsWith('/a')?new Promise(r=>resolveA=r):Promise.resolve(ok({filename:'B'})));
 const first=app.loadHistoryItem('a');await app.loadHistoryItem('b');resolveA(ok({filename:'A'}));await first;
 assert.equal(app.currentTaskId,'b');assert.equal(app.currentResults.filename,'B');
});
test('failed capture load retains current capture identity and results',async()=>{
 const {app}=setup(async()=>({ok:false,status:503}));
 assert.equal(await app.loadHistoryItem('missing'),false);assert.equal(app.currentTaskId,'old');assert.equal(app.currentResults.filename,'old');
});
test('failed history refresh does not replace library with empty data',async()=>{
 const {app,events}=setup(async()=>({ok:false,status:503,json:async()=>({detail:'failure'})}));
 await app.loadHistory();assert.ok(!events.some(x=>Array.isArray(x)&&x.length===0));assert.ok(events.some(x=>x[0]==='error'));
});
test('delete reports rejected HTTP and never announces success',async()=>{
 const {app,context,events}=setup(async()=>({ok:false,status:403}));context.confirm=()=>true;app.loadHistory=()=>events.push(['refresh']);
 await app.deleteHistoryItem('a');assert.ok(!events.some(x=>x[0]==='success'));assert.ok(!events.some(x=>x[0]==='refresh'));
});
test('polls do not overlap and old responses cannot complete a different capture',async()=>{
 let resolve,requests=0;const {app,timers}=setup(()=>{requests++;return new Promise(r=>resolve=r)});let loaded=0;app.loadResults=()=>loaded++;
 app.startStatusPolling();const tick=[...timers.values()][0];const first=tick();const second=tick();assert.equal(requests,1);await second;
 app.currentTaskId='new';resolve(ok({status:'completed'}));await first;assert.equal(loaded,0);
});
test('starting a new upload invalidates pending library navigation',async()=>{
 let resolveA;const {app,context}=setup(url=>url.endsWith('/a')?new Promise(r=>resolveA=r):Promise.resolve(ok({task_id:'upload-b'})));
 context.FormData=class{append(){}};app.startStatusPolling=()=>{};
 const pending=app.loadHistoryItem('a');await app.uploadFile({name:'new.pcap'});resolveA(ok({filename:'A'}));await pending;
 assert.equal(app.currentTaskId,'upload-b');
});
test('failed library navigation preserves polling for the retained processing capture',async()=>{
 const {app}=setup(async()=>({ok:false,status:503}));app.pollInterval=99;let restarted=0;app.startStatusPolling=()=>restarted++;
 await app.loadHistoryItem('a');assert.equal(restarted,0);assert.equal(app.pollInterval,99);assert.equal(app.currentTaskId,'old');
});
test('late packets cannot be cached under another capture',async()=>{
 let resolve;const {app}=setup(()=>new Promise(r=>resolve=r));app.virtualScroll={setData(){}};app.setMenuHealthStatus=()=>{};app.applyPacketFilters=()=>{};app.updateFilterStats=()=>{};app.setupResizableColumns=()=>{};
 const pending=app.loadPackets();app.currentTaskId='new';resolve(ok({packets:[{protocol:'TCP',src_ip:'198.51.100.1'}]}));await pending;
 assert.equal(app.packetsLoadedTaskId,undefined);assert.equal(app.allPackets,undefined);
});
test('successive failed navigations leave retained polling active',async()=>{
 const resolvers={};const {app,timers}=setup(url=>new Promise(r=>resolvers[url]=r));app.startStatusPolling();const pollId=app.pollInterval;
 const b=app.loadHistoryItem('b'),c=app.loadHistoryItem('c');resolvers['/api/analysis/c']({ok:false,status:503});await c;resolvers['/api/analysis/b'](ok({filename:'B'}));await b;
 assert.equal(app.currentTaskId,'old');assert.equal(app.pollInterval,pollId);assert.ok(timers.has(pollId));
});
test('failed navigation during upload does not discard successfully queued upload',async()=>{
 let resolveUpload;const {app,context}=setup(url=>url==='/api/upload'?new Promise(r=>resolveUpload=r):Promise.resolve({ok:false,status:503}));context.FormData=class{append(){}};app.startStatusPolling=()=>{};
 const upload=app.uploadFile({name:'new.pcap'});await app.loadHistoryItem('unavailable');resolveUpload(ok({task_id:'new-upload'}));await upload;
 assert.equal(app.currentTaskId,'new-upload');
});
