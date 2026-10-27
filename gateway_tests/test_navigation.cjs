const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');
function setup(){
 const nodes=new Map();
 function node(id){if(!nodes.has(id))nodes.set(id,{dataset:{},hidden:false,style:{},classList:{toggle(){}},events:{},addEventListener(name,fn){(this.events[name]??=[]).push(fn);},scrollIntoView(){},querySelector(){return node('submit');},replaceChildren(){}});return nodes.get(id);}
 const captures=node('captures');captures.dataset.nomiosView='captures';
 const module=node('packets');module.dataset.tab='packets';
 const events={};
 const app={currentResults:null,showToast(){},openMultiPcapMode(){}};
 const context={console,URL,Date,analyzer:app,document:{hidden:false,getElementById:node,querySelector:node,querySelectorAll:s=>s==='.nomios-module-nav .tab'?[module]:s==='[data-nomios-view]'?[captures]:[],addEventListener(name,fn){(events[name]??=[]).push(fn);}},window:{PCAP_CONFIG:{webAuth:false}},setInterval(){}};
 vm.runInNewContext(fs.readFileSync('static/js/identity-ui.js','utf8'),context);
 return {nodes,captures,module,events};
}
test('navigation registers module handlers once, including repeated visits',()=>{
 const {captures,module,events}=setup();
 for(let i=0;i<5;i++)for(const handler of [...captures.events.click])handler();
 assert.equal(module.events.click.length,1);
 assert.equal(events['pcap:analysis-loaded'].length,1);
});
