const {test}=require('node:test'),assert=require('node:assert/strict');
const {evidence,currentResult,causes}=require('../static/js/support-diagnosis.js');
test('old diagnosis response cannot populate another capture or newer request',()=>{
 assert.equal(currentResult({task:'a',generation:2},'a',2),true);
 assert.equal(currentResult({task:'b',generation:2},'a',2),false);
 assert.equal(currentResult({task:'a',generation:3},'a',2),false);
});
test('diagnosis evidence maps original frames safely',()=>{
 assert.equal(evidence('task-a',1),'/?task=task-a#tab=packets&packet=0');
 assert.equal(evidence('../escape',1),null);assert.equal(evidence('task',0),null);
 assert.equal(evidence('task',250001),null);assert.ok(causes.application);
});
