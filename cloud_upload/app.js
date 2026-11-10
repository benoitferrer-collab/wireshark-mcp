import express from 'express';
import { handleUpload } from '@vercel/blob/client';
import { authorizeBrowserUpload } from './session.js';
import { uploadPolicy } from './policy.js';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const app = express();
app.use(express.json({ limit: '32kb' }));
app.get('/cloud-assets/upload.js', (req, res) => res.sendFile(path.join(path.dirname(fileURLToPath(import.meta.url)), 'public/upload.js')));
app.post('/api/cloud/upload-token', async (req, res) => {
 try {
  const result = await handleUpload({ body: req.body, request: req,
   onBeforeGenerateToken: async pathname => {
    let authorization = req.headers.authorization;
    if (process.env.WEB_AUTH_ENABLED === 'true') {
      if (!(await authorizeBrowserUpload(req))) throw new Error('Session required');
      authorization = `Bearer ${process.env.API_ACCESS_TOKEN}`;
    }
    return uploadPolicy(pathname, authorization, process.env.API_ACCESS_TOKEN);
   },
   onUploadCompleted: async () => { /* Finalization is explicit and authenticated; no duplicate queue callback. */ },
  });
  res.json(result);
 } catch (_) { res.status(400).json({ detail: 'Upload refusé : clé, chemin ou fichier invalide.' }); }
});
export default app;
app.listen(Number(process.env.PORT || 80), '0.0.0.0');
