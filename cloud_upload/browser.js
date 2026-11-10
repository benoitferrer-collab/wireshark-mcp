import { upload } from '@vercel/blob/client';
import { finalizeJob } from './finalize.js';
const MAX_FILE = 104857600;
export async function uploadForm(form, apiPath, authorization) {
 const multi = apiPath === '/api/multi-pcap/analyze';
 const files = multi ? form.getAll('files') : [form.get('file')];
 if (!files.length || files.some(file => !(file instanceof File))) throw new Error('Capture manquante');
 if (files.some(file => file.size <= 0 || file.size > MAX_FILE)) throw new Error('Chaque capture doit être comprise entre 1 octet et 100 Mo.');
 if (files.length > 8 || files.reduce((sum, file) => sum + file.size, 0) > 209715200) throw new Error('Multi-PCAP : 8 captures et 200 Mo cumulés maximum.');
 const fingerprint = JSON.stringify({ multi, files: files.map(file => [file.name, file.size, file.lastModified]),
   metadata: form.get('metadata_json'), thresholds: form.get('thresholds_json'), tolerance: form.get('time_tolerance'), maxPackets: form.get('max_packets_per_capture') });
 const pendingKey = `pcap-pending:${fingerprint}`;
 let pending;
 try { pending = JSON.parse(sessionStorage.getItem(pendingKey) || 'null'); } catch (_) { pending = null; }
 const taskId = pending?.task_id || crypto.randomUUID();
 const metadata = multi ? JSON.parse(form.get('metadata_json') || '[]') : [];
 const captures = pending?.captures || [];
 for (const [index, file] of files.entries()) {
  if (captures[index]) continue;
  const extension = file.name.split('.').pop().toLowerCase();
  if (!['pcap', 'pcapng', 'cap'].includes(extension)) throw new Error('Format PCAP non pris en charge');
  const blob = await upload(`captures/${taskId}/capture-${index}.${extension}`, file, {
   access: 'private', handleUploadUrl: '/api/cloud/upload-token',
   headers: authorization ? { Authorization: authorization } : { 'X-CSRF-Token': window.PCAP_IDENTITY?.csrf || '' }, contentType: 'application/octet-stream',
   multipart: file.size > 5 * 1024 * 1024,
  });
  captures.push({ ...metadata[index], pathname: blob.pathname, filename: file.name });
  sessionStorage.setItem(pendingKey, JSON.stringify({ task_id: taskId, captures }));
 }
 const manifest = { task_id: taskId, kind: multi ? 'multi' : 'single', captures,
    options: multi ? { time_tolerance: Number(form.get('time_tolerance') || 5),
      max_packets_per_capture: Number(form.get('max_packets_per_capture') || 250000),
      root_cause_thresholds: JSON.parse(form.get('thresholds_json') || '{}') } : {} };
 const response = await finalizeJob(manifest, authorization);
 if (response.ok) sessionStorage.removeItem(pendingKey);
 return response;
}
