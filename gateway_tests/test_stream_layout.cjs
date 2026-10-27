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
