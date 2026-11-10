const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),vm=require('node:vm');
function app(){const c={};vm.runInNewContext(fs.readFileSync('static/js/app.js','utf8').split('// Initialize')[0]+'\nglobalThis.App=PCAPAnalyzer;',c);return Object.create(c.App.prototype);}
test('multi-PCAP evidence shows unknown loss and explicit ambiguous or absent observations',()=>{
 const html=app().renderMultiSegmentEvidence({method_version:2,matched_packets:2,unmatched_packets:1,ambiguous_packets:2,confidence:'LOW',from_capture_index:0,to_capture_index:1,quality_warnings:['Capture partielle'],directions:[],evidence:[{session_id:'s',direction:'client_to_server',from_frame:4,to_frame:null,relative_delta_ms:null,state:'not_observed_at_other_point'}]},[{equipment_name:'LAN',packet_count:4,coverage:{packet_limit_reached:true}},{equipment_name:'WAN',packet_count:4,coverage:{}}]);
 assert.ok(html.includes('Non établies'));assert.ok(html.includes('Non retrouvé au point B'));assert.ok(html.includes('Couverture plafonnée'));assert.ok(!html.includes('0.000 ms'));
});
test('capture and session labels are escaped and legacy data requests reanalysis',()=>{
 const a=app();assert.ok(a.renderMultiSegmentEvidence({}).includes('Ancienne analyse'));
 const html=a.renderMultiSegmentEvidence({method_version:2,from_capture_index:0,to_capture_index:1,quality_warnings:['<script>'],directions:[],evidence:[]},[{equipment_name:'<img onerror=x>'},{}]);
 assert.ok(html.includes('&lt;img'));assert.ok(html.includes('&lt;script&gt;'));assert.ok(!html.includes('<script>'));
});
