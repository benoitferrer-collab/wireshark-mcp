const {test}=require('node:test'),assert=require('node:assert/strict');
const {httpView}=require('../static/js/tls-decryption.js');
test('decrypted HTTP charts use report totals while visible TLS rows remain paginated',()=>{
 const r={data:[{method:'GET'}],total:80,http_summary:{total_requests:40,total_responses:40,methods:{GET:40},status_codes:{200:39,503:1},hosts:[{name:'demo.example',count:40}],top_urls:[{name:'/health',count:40}],requests_sample:[{method:'GET',path:'/health'}],tls_versions:{'TLSv1.2':1}}};
 const v=httpView(r);
 assert.equal(v.summary.total_requests,40);assert.equal(v.methods.GET,40);assert.equal(v.status_codes['503'],1);
 assert.equal(v.tls.versions['TLSv1.2'],1);assert.equal(v.requests.length,1);
 assert.equal(v.source,'decrypted_tls');assert.equal(v.user_agents_available,false);
});
test('missing summary cannot fabricate a complete HTTP view from one page',()=>{
 assert.equal(httpView({data:[{method:'GET'}],total:80}),null);
});

test('existing HTTP renderer receives decrypted values and never mutates the initial analysis',()=>{
 const fs=require('node:fs'),vm=require('node:vm');
 const ctx={document:{getElementById:()=>null,querySelector:()=>null}};
 vm.runInNewContext(fs.readFileSync('static/js/app.js','utf8').split('// Initialize')[0]+'\nglobalThis.App=PCAPAnalyzer;',ctx);
 const controller=Object.create(ctx.App.prototype),seen={};
 controller.currentTaskId='capture';controller.renderSignatures={};
 controller.globalDrilldownFilter={query:'unrelated'};
 controller.getGlobalFilterSignature=()=>'';
 controller.setMenuHealthStatus=()=>{};
 for(const [method,key] of Object.entries({createHttpMethodsChart:'methods',createHttpStatusChart:'codes',createHttpHostsChart:'hosts',createTlsVersionsChart:'versions',populateUrlsTable:'urls'}))controller[method]=v=>seen[key]=v;
 for(const name of ['populateUserAgentsTable','populateSniHostsTable','populateHttpRequestsTable','populateHttpAnomaliesTable','renderHttpDataHint'])controller[name]=()=>{};
 const base={methods:{},requests:[],tls:{versions:{}}};
 controller.tlsHttpView={task:'capture',http:httpView({stream_count:1,http_summary:{total_requests:3,total_responses:3,methods:{GET:3},status_codes:{200:2,503:1},tls_versions:{'TLSv1.2':1}}})};
 controller.displayHttpResults(base);
 assert.equal(seen.methods.GET,3);assert.equal(seen.codes['503'],1);assert.equal(seen.versions['TLSv1.2'],1);
 assert.deepEqual(base,{methods:{},requests:[],tls:{versions:{}}});
 controller.currentTaskId='other';controller.globalDrilldownFilter={};controller.renderSignatures={};
 controller.displayHttpResults(base);assert.equal(Object.keys(seen.methods).length,0);
});

test('rejected replacement key clears old results and displays an error state',async()=>{
 const fs=require('node:fs'),vm=require('node:vm'),nodes=[],events={};
 class Element{
  constructor(tag){this.tag=tag;this.children=[];this.listeners={};this.dataset={};this.files=[];this.value='';nodes.push(this);}
  append(...items){this.children.push(...items);if(this.tag==='select'&&!this.value)this.value=items[0]?.value||'';}
  addEventListener(name,fn){this.listeners[name]=fn;}
  setAttribute(){} before(){} prepend(...items){this.children.unshift(...items);} replaceChildren(...items){this.children=items;}
 }
 const root=new Element('div'),upload=new Element('div');
 const controller={currentTaskId:'capture',currentResults:{http_analysis:{}},renderSignatures:{},displayHttpResults(){}};
 const report={state:'decoded',decrypted_packets:6,stream_count:1,total:0,data:[],http_summary:{total_requests:3,total_responses:3,methods:{GET:3},status_codes:{200:2,503:1}}};
 const ctx={window:{PCAP_CONFIG:{tlsDecryption:true}},document:{createElement:t=>new Element(t),getElementById:id=>id==='tab-http'?root:id==='uploadArea'?upload:null,addEventListener:(name,fn)=>events[name]=fn},analyzer:controller,
  Option:class extends Element{constructor(text,value){super('option');this.textContent=text;this.value=value;}},FormData:class{append(){}},AbortSignal,encodeURIComponent,setTimeout:()=>0,clearTimeout(){},
  fetch:async(url,options)=>options?.method==='POST'?{ok:false,json:async()=>({detail:'Clé PEM invalide ou mot de passe incorrect.'})}:{ok:true,json:async()=>url.includes('/preflight')?{message:'Compatible',sessions:[]}:({id:'old-job',status:'completed',report})}};
 vm.runInNewContext(fs.readFileSync('static/js/tls-decryption.js','utf8'),ctx);
 await events['pcap:analysis-loaded']();await new Promise(setImmediate);
 const live=nodes.find(n=>n.className==='tls-status');assert.equal(live.dataset.state,'completed');assert.ok(controller.tlsHttpView);
 const forms=nodes.filter(n=>n.tag==='form'),form=forms[1];
 const inputs=form.children.filter(n=>n.tag==='label').flatMap(n=>n.children);
 const file=inputs.find(n=>n.type==='file');file.files=[{size:10,name:'invalid.pem'}];
 await form.listeners.submit({preventDefault(){}});
 assert.equal(live.dataset.state,'failed');assert.match(live.textContent,/PEM invalide/);
 assert.equal(controller.tlsHttpView,null);
 const panel=root.children[0],output=panel.children.find(n=>n.tag==='div'&&!n.className);
 assert.deepEqual(output.children,[]);
 // A late preflight failure from the old capture must not clear a new result.
 let rejectPreflight;
 ctx.fetch=async(url)=>url.includes('/preflight')?await new Promise((_,reject)=>rejectPreflight=reject):({ok:true,json:async()=>({id:'new-job',status:'completed',report})});
 const check=nodes.find(n=>n.tag==='button'&&n.textContent==='Vérifier la compatibilité TLS');
 const pendingCheck=check.listeners.click();
 controller.currentTaskId='other';await events['pcap:analysis-loaded']();await new Promise(setImmediate);
 assert.equal(controller.tlsHttpView.task,'other');
 rejectPreflight(new Error('Old capture network error'));await pendingCheck;
 assert.equal(live.dataset.state,'completed');assert.equal(controller.tlsHttpView.task,'other');
});


test('switching HTTP source preserves observed SNI metadata from the capture',()=>{
 const base={tls:{sni_hosts:[{name:'support.nomios.example',count:1}]}};
 const view=httpView({http_summary:{total_requests:3}},base);
 assert.deepEqual(view.tls.sni_hosts,base.tls.sni_hosts);
});
