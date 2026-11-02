const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const vm=require('node:vm');

test('compact stream rows preserve endpoints, traffic, diagnostics and both actions',()=>{
 const tbody={innerHTML:''};
 const context={document:{querySelector:()=>tbody}};
 const source=fs.readFileSync('static/js/app.js','utf8').split('// Initialize')[0];
 vm.runInNewContext(source+'\nglobalThis.Analyzer=PCAPAnalyzer;',context);
 const analyzer=Object.create(context.Analyzer.prototype);
 analyzer.escapeHtml=value=>String(value).replaceAll('<','&lt;').replaceAll('>','&gt;').replaceAll('"','&quot;');
 const row={stream_id:7,src_endpoint:'10.1.2.3:48822',dst_endpoint:'10.2.3.4:12346',src_ip:'10.1.2.3',packet_count:25,total_bytes:10752,type:'TCP',state:'CLOSED',retransmissions:8,rst_count:3,risk_level:'HIGH',probable_cause_code:'reset-pair',probable_cause:'Reset pair (fermeture distante)',stream_identifier:'stream-7'};
 analyzer.renderStreamsTableRows([row]);
 assert.equal((tbody.innerHTML.match(/<td\b/g)||[]).length,9);
 for(const value of [row.src_endpoint,row.dst_endpoint,row.probable_cause,'CLOSED','TCP','HIGH','showStreamDetails','showIpSessionModal'])assert.ok(tbody.innerHTML.includes(value));
 analyzer.renderStreamsTableRows([]);
 assert.ok(tbody.innerHTML.includes('colspan="9"'));
});

test('opening a capture does not schedule unsolicited AI popups',()=>{
 let scheduled=0;
 const context={setTimeout:()=>{scheduled++;return 1;},clearTimeout(){}};
 const source=fs.readFileSync('static/js/app.js','utf8').split('// Initialize')[0];
 vm.runInNewContext(source+'\nglobalThis.Analyzer=PCAPAnalyzer;',context);
 context.Analyzer.prototype.init=function(){};
 const analyzer=new context.Analyzer();
 analyzer.currentTaskId='capture';
 analyzer.scheduleAutoQuestionnaire();
 assert.equal(scheduled,0);
});

test('virtual packet rows start below headers and align with resized columns',()=>{
 const rendered=[];
 const head={getBoundingClientRect:()=>({height:32})};
 const table={querySelector:()=>head,querySelectorAll:()=>[{getBoundingClientRect:()=>({width:60})},{getBoundingClientRect:()=>({width:130})}]};
 const tbody={closest:()=>table,replaceChildren:fragment=>rendered.push(...fragment.rows)};
 const spacer={style:{}};
 const container={offsetHeight:100,scrollTop:0,addEventListener(){}};
 const context={window:{addEventListener(){}},document:{createDocumentFragment:()=>({rows:[],appendChild(row){this.rows.push(row);}})}};
 const source=fs.readFileSync('static/js/app.js','utf8').split('// Initialize')[0];
 vm.runInNewContext(source+'\nglobalThis.Virtual=VirtualScroll;',context);
 const virtual=new context.Virtual(container,spacer,tbody,38);
 virtual.setData([1,2],()=>({style:{}}));
 assert.equal(rendered[0].style.top,'32px');
 assert.equal(spacer.style.height,'108px');
 assert.equal(rendered[0].style.gridTemplateColumns,'60px 130px');
});
