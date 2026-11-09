const {test}=require('node:test'),assert=require('node:assert/strict');
const {delta,comparison,evidenceUrl}=require('../static/js/transactions.js');
test('timing differences keep zero and missing values distinct',()=>{
 assert.deepEqual(delta(200,50),{difference:-150,percent:-75});
 assert.deepEqual(delta(0,4),{difference:4,percent:null});
 for(const value of [null,undefined,NaN,-1,Infinity,'50'])assert.equal(delta(value,20),null);
});
test('comparison does not mix DNS-only exchanges with HTTP and never computes absent stages',()=>{
 const a={kind:'http',stages:{http:{duration_ms:200},tcp:{duration_ms:null}}};
 const b={kind:'http',stages:{http:{duration_ms:50}}};
 assert.equal(comparison(a,b).find(row=>row.key==='http').change.difference,-150);
 assert.equal(comparison(a,b).find(row=>row.key==='tcp').change,null);
 assert.ok(comparison(a,{...b,kind:'dns'}).every(row=>row.change===null));
});
test('transaction evidence uses exact original packet and rejects unsafe locations',()=>{
 assert.equal(evidenceUrl('capture-123',6),'/?task=capture-123#tab=packets&packet=5');
 assert.equal(evidenceUrl('../escape',6),null);assert.equal(evidenceUrl('good',0),null);assert.equal(evidenceUrl('good',250001),null);
});
