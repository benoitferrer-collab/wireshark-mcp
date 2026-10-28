export async function authorizeBrowserUpload(req, env=process.env, fetcher=fetch) {
 if (env.WEB_AUTH_ENABLED !== 'true') return false;
 const session = (req.headers.cookie || '').split(';').map(x=>x.trim()).find(x=>x.startsWith('nomios_session='))?.slice('nomios_session='.length);
 if (!session || session.length>256 || !req.headers['x-csrf-token'] || !env.UPLOADS_BACKEND_URL) return false;
 try {
  const response=await fetcher(new URL('/api/identity/internal/authorize-upload',env.UPLOADS_BACKEND_URL).href,{
   method:'POST',redirect:'error',signal:AbortSignal.timeout(8000),
   headers:{Authorization:`Bearer ${env.API_ACCESS_TOKEN}`,'Content-Type':'application/json'},
   body:JSON.stringify({session_id:session,origin:req.headers.origin||'',csrf:req.headers['x-csrf-token']}),
  });
  return response.ok;
 } catch (_) { return false; }
}
