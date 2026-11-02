const {test}=require('node:test');
const assert=require('node:assert/strict');
const {parseEvidenceLocation,openEvidence}=require('../static/js/evidence-links.js');
const fs=require('node:fs');
const vm=require('node:vm');
test('MCP links preserve exact zero-based packet and capture identity',()=>{
 assert.deepEqual(parseEvidenceLocation('https://pcap.example/?task=abc-123#tab=packets&packet=0'),{taskId:'abc-123',tab:'packets',packetIndex:0});
 assert.equal(parseEvidenceLocation('https://pcap.example/?task=abc#tab=overview').packetIndex,null);
 for(const url of ['https://pcap.example/?task=../secret','https://pcap.example/?task=abc#packet=-1','https://pcap.example/?task=abc#packet=250000','https://pcap.example/?task=abc#tab=javascript:alert(1)']) assert.equal(parseEvidenceLocation(url),null);
});
test('startup preserves packet evidence before existing tabs rewrite the fragment',async()=>{
 const calls=[],listeners={};
 const window={location:{href:'https://pcap.example/?task=demo#tab=packets&packet=5001'},addEventListener:(name,fn)=>{listeners[name]=fn}};
 const analyzer={loadHistoryItem:async()=>true,switchTab:()=>{},showPacketDetails:idx=>calls.push(idx)};
 vm.runInNewContext(fs.readFileSync(require.resolve('../static/js/evidence-links.js'),'utf8'),{window,analyzer,URL,URLSearchParams});
 window.location.href='https://pcap.example/?task=demo#tab=packets';
 listeners.load();
 await new Promise(resolve=>setImmediate(resolve));
 assert.deepEqual(calls,[5001]);
 const html=fs.readFileSync(require.resolve('../templates/index.html'),'utf8');
 assert.ok(html.indexOf('/static/js/evidence-links.js')<html.indexOf('/static/js/app.js'));
});
test('navigation awaits successful analysis load before opening packet',async()=>{
 const calls=[];
 const controller={loadHistoryItem:async id=>{calls.push(['load',id]);return true},switchTab:tab=>calls.push(['tab',tab]),showPacketDetails:idx=>calls.push(['packet',idx])};
 assert.equal(await openEvidence(controller,'https://pcap.example/?task=abc#tab=packets&packet=5001'),true);
 assert.deepEqual(calls,[['load','abc'],['tab','packets'],['packet',5001]]);
 calls.length=0;controller.loadHistoryItem=async()=>false;
 assert.equal(await openEvidence(controller,'https://pcap.example/?task=abc#packet=0'),false);
 assert.equal(calls.length,0);
});
