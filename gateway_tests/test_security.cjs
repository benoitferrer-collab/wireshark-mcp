const {test}=require('node:test');
const assert=require('node:assert/strict');
const {simulate,filterTools}=require('../static/js/security.js');
const names=['search_packets','get_conversations'];
test('policy demonstration refuses invalid identity and tools outside PCAP catalogue',()=>{
 assert.equal(simulate('pcap',names).verdict,'allowed');
 for(const scenario of ['expired','tenant','scope','subject','unknown-tool'])assert.equal(simulate(scenario,names).verdict,'blocked');
 assert.equal(simulate('general-chat',names).verdict,'outside');
 assert.equal(simulate('injection',names).verdict,'conditional');
 assert.equal(simulate('direct',names).verdict,'conditional');
 assert.equal(simulate('unknown-scenario',[]).verdict,'conditional');
});
test('catalogue filter matches descriptions and names without changing tools',()=>{
 const tools=[{name:'search_packets',title:'Recherche PCAP',category:'Investigation',description:'Paquets et filtres Wireshark'},
 {name:'get_anomalies',title:'Anomalies',category:'Diagnostic',description:'Sévérité des détections'}];
 assert.equal(filterTools(tools,'severite','all')[0].name,'get_anomalies');
 assert.equal(filterTools(tools,'','Investigation').length,1);
 assert.equal(filterTools(tools,'inexistant','all').length,0);
 assert.equal(tools.length,2);
});
