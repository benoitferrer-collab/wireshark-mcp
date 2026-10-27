import { timingSafeEqual } from 'node:crypto';
export function uploadPolicy(pathname, authorization, secret) {
 const expected = Buffer.from(`Bearer ${secret || ''}`);
 const actual = Buffer.from(authorization || '');
 if (!secret || secret.length < 32 || actual.length !== expected.length || !timingSafeEqual(actual, expected)) {
  throw new Error('Authentication required');
 }
 if (!/^captures\/[A-Za-z0-9][A-Za-z0-9_-]{0,63}\/[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.(pcap|pcapng|cap)$/i.test(pathname) || pathname.includes('..')) {
  throw new Error('Invalid capture pathname');
 }
 return { maximumSizeInBytes: 104857600, addRandomSuffix: false, allowOverwrite: false,
          validUntil: Date.now() + 10 * 60 * 1000,
          allowedContentTypes: ['application/octet-stream', 'application/vnd.tcpdump.pcap', 'application/x-pcapng', 'application/x-pcap'] };
}
