import { test } from 'node:test';
import assert from 'node:assert/strict';
import { uploadPolicy } from './policy.js';
const secret = 'x'.repeat(40);
test('upload token binds the capture pathname, denies overwrite and caps size', () => {
 const policy = uploadPolicy('captures/abc/source.pcap', 'Bearer ' + secret, secret);
 assert.equal(policy.maximumSizeInBytes, 104857600);
 assert.equal(policy.allowOverwrite, false);
});
test('unauthenticated or forged uploads are refused', () => {
 for(const path of ['captures/abc/../a.pcap', 'results/abc/results.json', 'captures/abc/a.exe']) {
  assert.throws(() => uploadPolicy(path, 'Bearer ' + secret, secret));
 }
 assert.throws(() => uploadPolicy('captures/abc/a.pcap', 'Bearer wrong', secret));
 assert.throws(() => uploadPolicy('captures/abc/a.pcap', '', ''));
});
