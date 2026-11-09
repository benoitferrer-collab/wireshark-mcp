const {test}=require('node:test'),assert=require('node:assert/strict');
const {metric,evidence,titles}=require('../static/js/support-protocols.js');
test('protocol measurements distinguish zero, missing and invalid values',()=>{
 assert.equal(metric(0,' ms'),'0 ms');
 for(const value of [null,undefined,NaN,Infinity,'3'])assert.equal(metric(value),'Non mesuré');
 assert.equal(Object.keys(titles).length,9);
});
test('support evidence returns original frame, never an arbitrary task URL',()=>{
 assert.equal(evidence('capture-1',1),'/?task=capture-1#tab=packets&packet=0');
 assert.equal(evidence('../private',1),null);
 assert.equal(evidence('good',0),null);
 assert.equal(evidence('good',250001),null);
});
