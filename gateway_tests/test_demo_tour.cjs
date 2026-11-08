const {test}=require('node:test');const assert=require('node:assert/strict');const fs=require('node:fs');const {steps,isDemoURL}=require('../static/js/demo-tour.js');
test('demo URI only starts explicitly and tour uses existing modules',()=>{
 assert.equal(isDemoURL('https://pcap.example/?demo=1'),true);assert.equal(isDemoURL('https://pcap.example/?task=abc'),false);assert.equal(isDemoURL('https://pcap.example/?demo=0'),false);
 const html=fs.readFileSync('templates/index.html','utf8');assert.equal(steps.length,15);
 for(const step of steps){if(step.tab)assert.ok(html.includes(`data-tab="${step.tab}"`));assert.ok(step.title&&step.text);}
 assert.ok(steps.some(s=>s.text.includes('Aucune session TLS')));assert.ok(steps.some(s=>s.text.includes('ne fabrique aucune activité')));
});
test('opening a real capture during demo preparation cancels pending demo navigation',async()=>{
 const vm=require('node:vm'),nodes=new Map(),events={};let resolve,loads=0;
 const node=id=>{if(!nodes.has(id))nodes.set(id,{hidden:false,style:{setProperty(){}},handlers:{},addEventListener(name,fn){this.handlers[name]=fn},setAttribute(){},focus(){}});return nodes.get(id)};
 const app={currentTaskId:'real-a',loadHistoryItem:async()=>{loads++;return true},loadHistory:async()=>{}};
 const ctx={document:{getElementById:node,body:{classList:{add(){},remove(){}}},addEventListener(name,fn){events[name]=fn},querySelector(){return null}},window:{addEventListener(){}},location:{href:'https://app.example/'},analyzer:app,fetch:()=>new Promise(r=>resolve=r),URL,AbortSignal,setInterval(){},clearInterval(){}};
 vm.runInNewContext(fs.readFileSync('static/js/demo-tour.js','utf8'),ctx);
 const pending=node('demoStart').handlers.click();app.currentTaskId='real-b';events['pcap:analysis-loaded']();resolve({ok:true,json:async()=>({task_id:'demo-new'})});await pending;
 assert.equal(loads,0);assert.equal(app.currentTaskId,'real-b');assert.equal(node('demoTour').hidden,true);
});
