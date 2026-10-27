import { test } from 'node:test';
import assert from 'node:assert/strict';
import { finalizeJob } from './finalize.js';
test('a transient finalization failure retries the exact persisted job without upload', async () => {
 const bodies = [];
 let count = 0;
 const result = await finalizeJob({ task_id: 'existing-id', captures: [{ pathname: 'captures/existing-id/0.pcap' }] }, 'Bearer key', {
  fetcher: async (url, options) => { bodies.push(JSON.parse(options.body)); return { status: ++count === 1 ? 503 : 200, ok: count > 1 }; },
  sleep: async () => {},
 });
 assert.equal(result.status, 200);
 assert.equal(bodies.length, 2);
 assert.deepEqual(bodies[0], bodies[1]);
 assert.equal(bodies[1].task_id, 'existing-id');
});
