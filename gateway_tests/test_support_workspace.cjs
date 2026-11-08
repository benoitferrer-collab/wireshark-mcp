const {test}=require('node:test');
const assert=require('node:assert/strict');
const {selectHistory,summarizeHistory,supportSignals,buildHandoff}=require('../static/js/support-workspace.js');
const history=[{task_id:'a',filename:'Agence Évreux.pcap',total_packets:200,risk_level:'LOW',timestamp:'2026-11-07T12:00:00Z'},{task_id:'b',filename:'VPN.pcap',total_packets:30,risk_level:'HIGH',timestamp:'2026-11-08T12:00:00Z'},{task_id:'c',filename:'Vide.pcap',total_packets:0}];
test('library searches accents, filters severity and sorts without modifying source',()=>{
 assert.equal(selectHistory(history,{query:'evreux'})[0].task_id,'a');
 assert.deepEqual(selectHistory(history,{risk:'HIGH'}).map(x=>x.task_id),['b']);
 assert.deepEqual(selectHistory(history,{sort:'packets'}).map(x=>x.task_id),['a','b','c']);
 assert.deepEqual(selectHistory(history,{sort:'risk'}).map(x=>x.task_id),['b','a','c']);
 assert.equal(history[0].task_id,'a');
});
test('library metrics distinguish unknown risk from low risk and sum metadata only',()=>{
 assert.deepEqual(summarizeHistory(history),{captures:3,packets:230,attention:1,unknownRisk:1});
 assert.equal(summarizeHistory([{total_packets:-2},{total_packets:'oops'}]).packets,0);
});
test('support signals keep missing measurements unknown and never diagnose cause',()=>{
 const empty=supportSignals({});
 assert.ok(empty.every(x=>x.value==='Non disponible'));
 const signals=supportSignals({tcp_analysis:{summary:{total_sessions:12}},dns_analysis:{summary:{total_queries:0}},http_analysis:{summary:{total_tls_sessions:3}},anomaly_detection:{summary:{total_anomalies:4}}});
 assert.deepEqual(signals.map(x=>x.value),['12','0','3','4']);
 assert.deepEqual(signals.map(x=>x.module),['tcp-health','dns','tls-audit','threat-intel']);
});
test('handoff is bounded, uses exact capture and typed context without raw packet data',()=>{
 const prompt=buildHandoff('abc-123',{issue:'performance',symptom:'Application lente',capture_point:'SPAN LAN'},{metadata:{filename:'test.pcap'},packets_index:[{password:'private-secret'}]});
 assert.ok(prompt.includes('abc-123'));assert.ok(prompt.includes('guide_investigation'));
 assert.ok(prompt.includes('Application lente'));assert.ok(prompt.includes('SPAN LAN'));
 assert.ok(!prompt.includes('private-secret'));assert.ok(prompt.includes('une question'));
 assert.throws(()=>buildHandoff('../bad',{},{}));
 assert.ok(buildHandoff('a',{symptom:'x'.repeat(10000)},{}).length<2500);
});
