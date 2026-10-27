import express from 'express';
import { handleUpload } from '@vercel/blob/client';
import { uploadPolicy } from './policy.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const app = express();
app.use(express.json({ limit: '32kb' }));
app.get('/cloud-assets/upload.js', (req, res) => res.sendFile(path.join(path.dirname(fileURLToPath(import.meta.url)), 'public/upload.js')));
app.post('/api/cloud/upload-token', async (req, res) => {
 try {
  const result = await handleUpload({ body: req.body, request: req,
   onBeforeGenerateToken: async pathname => uploadPolicy(pathname, req.headers.authorization, process.env.API_ACCESS_TOKEN),
   onUploadCompleted: async () => { /* Finalization is explicit and authenticated; no duplicate queue callback. */ },
  });
  res.json(result);
 } catch (_) { res.status(400).json({ detail: 'Upload refusé : clé, chemin ou fichier invalide.' }); }
});
export default app;
app.listen(Number(process.env.PORT || 80), '0.0.0.0');
