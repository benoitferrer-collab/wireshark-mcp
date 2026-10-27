import test from 'node:test';
import assert from 'node:assert/strict';
import { authorizeBrowserUpload } from './session.js';
test('forwards only session and CSRF to fixed backend, denies failed introspection',async()=>{
 let sent;
 const env={WEB_AUTH_ENABLED:'true',API_ACCESS_TOKEN:'x'.repeat(40),UPLOADS_BACKEND_URL:'https://internal.example'};
 const req={headers:{cookie:'other=x; nomios_session=opaque',origin:'https://app.example','x-csrf-token':'csrf'}};
 const fetcher=async(url,options)=>{sent={url,options};return {ok:true}};
 assert.equal(await authorizeBrowserUpload(req,env,fetcher),true);
 assert.equal(sent.url,'https://internal.example/api/identity/internal/authorize-upload');
 assert.deepEqual(JSON.parse(sent.options.body),{session_id:'opaque',origin:'https://app.example',csrf:'csrf'});
 assert.equal(await authorizeBrowserUpload(req,env,async()=>({ok:false})),false);
 assert.equal(await authorizeBrowserUpload({headers:{}},env,fetcher),false);
});
