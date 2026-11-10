/* Chart totals come from the full saved report, never from a paginated table. */
(function(root){
 'use strict';
 function httpView(report,base={}){
  const s=report?.http_summary;if(!s)return null;
  return {source:'decrypted_tls',summary:{total_requests:s.total_requests,total_responses:s.total_responses,total_tls_sessions:report.stream_count||0},
   methods:s.methods||{},status_codes:s.status_codes||{},hosts:s.hosts||[],top_urls:s.top_urls||[],user_agents:[],user_agents_available:false,
   requests:(s.requests_sample||[]).map(r=>({...r,src_ip:r.source,dst_ip:r.destination})),responses:[],
   tls:{versions:s.tls_versions||{},sni_hosts:base.tls?.sni_hosts||[]},anomalies:[],
   coverage_note:`HTTP déchiffré : ${s.total_requests||0} requêtes et ${s.total_responses||0} réponses sur le rapport disponible${s.truncated?' (limité à 10 000 lignes)':''}. Périmètre : rapport TLS complet, hors filtre global. Liste limitée à 25 requêtes. User-Agents non conservés. Versions TLS : négociations observées${s.tls_versions_sampled?' (échantillon)':''}.`};
 }
 if(typeof module!=='undefined'&&module.exports)module.exports={httpView};
 root.NomiosTlsHttp={httpView};
})(typeof window==='undefined'?globalThis:window);
/* TLS secrets stay in this tab until submitted; never browser storage or MCP arguments. */
(() => {
 'use strict';
 if(typeof window==='undefined'||!window.PCAP_CONFIG?.tlsDecryption)return;
 const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const app=()=>typeof analyzer==='undefined'?null:analyzer;
 let capture=null,timer=null,generation=0,pending=null,uploadDraft=null,offset=0,failures=0,readinessKey=null;
 const panel=node('section',undefined,'tls-panel');panel.id='tlsDecryptionPanel';
 panel.append(node('p','INVESTIGATION TLS','tls-eyebrow'),node('h3','Vos échanges, déchiffrés.'),node('p','Ajoutez les secrets correspondant à cette capture pour retrouver les échanges HTTP/HTTPS.','tls-muted'));
 const live=node('p','Aucun déchiffrement demandé.','tls-status');live.setAttribute('role','status');
 const readiness=node('div',undefined,'tls-readiness');readiness.hidden=true;
 const statusMeta=node('p','', 'tls-help');
 const refreshButton=node('button','Actualiser le suivi','btn btn-secondary');refreshButton.type='button';refreshButton.addEventListener('click',()=>refresh());
 const output=node('div');const pager=node('div',undefined,'tls-pager');
 const source=node('select');source.setAttribute('aria-label','Source des graphiques HTTP');source.append(new Option('HTTP déchiffré','decrypted'),new Option('Analyse initiale de la capture','original'));source.hidden=true;
 const sourceNote=node('p','Les graphiques et les listes ci-dessous suivent la source sélectionnée.','tls-help');sourceNote.hidden=true;
 let lastReport=null,reportKey=null;
 function updateCharts(){const a=app();if(!a)return;a.tlsHttpView=source.value==='decrypted'&&lastReport?{task:capture,http:window.NomiosTlsHttp.httpView(lastReport,a.currentResults?.http_analysis||{})}:null;if(a.renderSignatures)delete a.renderSignatures.http;a.displayHttpResults(a.currentResults?.http_analysis||{});}
 source.addEventListener('change',updateCharts);
 function showError(message){live.textContent=message;live.dataset.state='failed';statusMeta.textContent='Import non accepté. Le résultat précédent reste enregistré ; actualisez le suivi pour le consulter.';output.replaceChildren();pager.replaceChildren();lastReport=null;reportKey=null;source.hidden=true;sourceNote.hidden=true;updateCharts();}
 function form(forUpload){
  const details=node('details',undefined,'tls-options');details.append(node('summary',forUpload?'Déchiffrement TLS · facultatif':'Ajouter ou remplacer les secrets de cette capture'));
  const f=node('form',undefined,'tls-form');
  const select=node('select');select.name='kind';select.append(new Option('Secrets de session · SSLKEYLOGFILE','keylog'),new Option('Clé privée serveur · RSA PEM','rsa'));
  const file=node('input');file.type='file';file.accept='.pem,.key,.keys,.log,.txt';file.name='file';
  const password=node('input');password.type='password';password.name='password';password.autocomplete='off';password.placeholder='Mot de passe de la clé, si nécessaire';password.maxLength=512;password.hidden=true;
  select.addEventListener('change',()=>{password.hidden=select.value!=='rsa';password.value='';});
  for(const [label,input] of [['Type de secrets',select],['Fichier de secrets',file],['Mot de passe PEM',password]]){const l=node('label',label);l.append(input);if(input===password){l.className='tls-password';l.hidden=true;select.addEventListener('change',()=>l.hidden=select.value!=='rsa');}f.append(l);}
  f.append(node('p','RSA : TLS ≤ 1.2 avec échange RSA, sans ECDHE. Pour TLS 1.3, utilisez un keylog. RSA : 64 Kio · keylog : 2 Mio.','tls-help'));
  f.append(node('p','Secrets chiffrés pendant l’attente, supprimés après traitement. Corps, cookies et authentification exclus du rapport.','tls-help'));
  if(forUpload)f.append(node('p','Choisissez ces secrets avant d’importer le PCAP. Gardez cet onglet ouvert jusqu’à la fin de l’analyse.','tls-help'));
  else{const check=node('button','Vérifier la compatibilité TLS','btn btn-secondary');check.type='button';check.addEventListener('click',async()=>{check.disabled=true;try{await preflight(capture,select.value);}catch(e){showError(e.message);}finally{check.disabled=false;}});f.append(check);const b=node('button','Déchiffrer cette capture','btn btn-primary');b.type='submit';f.append(b);f.addEventListener('submit',async e=>{e.preventDefault();if(!capture)return;const target=capture;try{if(await submit(target,selection(),b))clear();}catch(error){if(capture===target)showError(error.message);}});}
  details.append(f);
  function selection(){const chosen=file.files[0];if(!chosen)return null;if(chosen.size>(select.value==='rsa'?65536:2097152))throw new Error('Fichier trop volumineux : RSA 64 Kio, keylog 2 Mio.');return {file:chosen,kind:select.value,password:password.value};}
  function clear(){file.value='';password.value='';}
  return {element:details,selection,clear};
 }
 const importForm=form(true),existingForm=form(false);
 document.getElementById('uploadArea')?.before(importForm.element);
 panel.append(existingForm.element,readiness,live,statusMeta,refreshButton,source,sourceNote,output,pager);document.getElementById('tab-http')?.prepend(panel);
 async function preflight(id,kind){
  if(!id)return;const version=generation;
  try{
  const response=await fetch(`/api/identity/tls/${encodeURIComponent(id)}/preflight?kind=${kind}`,{signal:AbortSignal.timeout(30000)});
  if(!response.ok)throw new Error('Contrôle TLS indisponible. Actualisez puis réessayez.');
  const r=await response.json();if(id!==capture||version!==generation)return;
  readiness.replaceChildren(node('strong','Compatibilité de la capture'),node('p',r.message));
  readiness.append(node('p',`${r.observed_sessions??0} négociations observées · ${r.rsa_candidates??0} candidates RSA · ${r.keylog_required??0} nécessitant un keylog · ${r.unknown??0} indéterminées`,'tls-help'));
  for(const row of r.sessions||[]){const b=node('button',`Trame #${row.frame_number} · ${row.version} · ${row.cipher_suite??'suite inconnue'}`,'tls-frame');b.type='button';b.addEventListener('click',()=>app()?.showPacketDetails(row.frame_number-1));readiness.append(b);}
  readiness.append(node('p',r.coverage?.scope||'Compatibilité partielle ; correspondance des secrets non vérifiée.','tls-help'));readiness.hidden=false;readinessKey=id+':'+kind;
  }catch(e){if(id===capture&&version===generation)throw e;}
 }
 async function submit(id,selected,button){
  if(!selected)throw new Error('Sélectionnez un fichier de secrets.');
  const data=new FormData();data.append('kind',selected.kind);data.append('file',selected.file);data.append('password',selected.password);
  if(button)button.disabled=true;let submitGeneration=generation;
  try{const version=generation;if(readinessKey!==id+':'+selected.kind){try{await preflight(id,selected.kind);}catch(e){showError(e.message);}}
   if(capture!==id||generation!==version)throw new Error('La capture affichée a changé. Relancez depuis la capture souhaitée.');
   generation++;submitGeneration=generation;clearTimeout(timer);
   const response=await fetch(`/api/identity/tls/${encodeURIComponent(id)}`,{method:'POST',body:data});const result=await response.json();if(!response.ok)throw new Error(typeof result.detail==='string'?result.detail:'Déchiffrement non démarré. Vérifiez le fichier.');
   if(capture===id){offset=0;await refresh();return true;}
   return false;
  }catch(e){if(id===capture&&submitGeneration===generation)throw e;return false;}finally{if(button)button.disabled=false;}
 }
 function render(data){
  output.replaceChildren();pager.replaceChildren();
  const labels={not_requested:'Aucun déchiffrement demandé.',queued:'Secrets reçus · en attente du worker.',processing:'Déchiffrement en cours…',failed:data.error||'Déchiffrement impossible.',completed:'Traitement terminé.'};
  live.textContent=data.notice||labels[data.status]||data.status;
  live.dataset.state=data.waiting_delayed?'delayed':data.status;
  const stage={preflight:'Vérification de la capture',decoding:'Décodage des échanges',queued:'Dans la file durable'};
  statusMeta.textContent=['queued','processing'].includes(data.status)?`${stage[data.stage]||'Traitement'} · ${data.elapsed_seconds??0} s depuis l’import${data.attempt?' · tentative '+data.attempt+'/3':''}`:'';
  const r=data.report;
  lastReport=r?.state==='decoded'?r:null;source.hidden=!lastReport;sourceNote.hidden=!lastReport;
  if(lastReport&&reportKey!==data.id)source.value='decrypted';reportKey=data.id;
  updateCharts();if(!r)return;
  live.textContent=r.message||live.textContent;
  const metrics=node('div',undefined,'tls-metrics');for(const [v,l] of [[r.decrypted_packets,'paquets décodés'],[r.stream_count,'flux TLS'],[r.total,'échanges HTTP']]){const m=node('div');m.append(node('strong',String(v??0)),node('span',l));metrics.append(m);}output.append(metrics);
  if(r.data?.length){const wrap=node('div',undefined,'tls-table-wrap'),table=node('table');const head=node('tr');for(const text of ['Trame / flux','Protocole','Méthode','Hôte / chemin','Statut','Source → destination'])head.append(node('th',text));const thead=node('thead');thead.append(head);table.append(thead);const tbody=node('tbody');
   for(const row of r.data){const tr=node('tr'),ref=node('td');const button=node('button',`#${row.frame_number}`,'tls-frame');button.type='button';button.addEventListener('click',()=>app()?.showPacketDetails(row.packet_index));ref.append(button,node('small',`TCP ${row.stream_id??'—'}${row.http2_stream_id!==null?' · H2 '+row.http2_stream_id:''}`));tr.append(ref,node('td',row.protocol),node('td',row.method||'Réponse'));const target=node('td');target.append(node('strong',row.host||'—'),node('small',row.path||'—'));tr.append(target,node('td',String(row.status??'—')),node('td',`${row.source} → ${row.destination}`));tbody.append(tr);}table.append(tbody);wrap.append(table);output.append(wrap);
  }
  for(const text of r.limitations||[])output.append(node('p',text,'tls-help'));
  if(r.offset>0){const b=node('button','← Précédent','btn btn-secondary');b.onclick=()=>{offset=Math.max(0,r.offset-25);refresh();};pager.append(b);}
  if(r.next_offset!==null&&r.next_offset!==undefined){const b=node('button','Suite →','btn btn-secondary');b.onclick=()=>{offset=r.next_offset;refresh();};pager.append(b);}
 }
 async function refresh(){
  clearTimeout(timer);const id=capture,version=generation;if(!id)return;
  try{const response=await fetch(`/api/identity/tls/${encodeURIComponent(id)}?offset=${offset}&limit=25`,{signal:AbortSignal.timeout(15000)});if([401,403].includes(response.status)){if(version===generation)live.textContent='Connexion Microsoft expirée ou accès refusé. Reconnectez-vous pour reprendre le suivi.';return;}if(!response.ok)throw new Error('Résultat TLS indisponible. Réessayez.');const data=await response.json();if(id!==capture||version!==generation)return;failures=0;render(data);if(['queued','processing'].includes(data.status))timer=setTimeout(refresh,4000);}
  catch(e){if(version===generation){live.textContent='Suivi momentanément indisponible ; nouvelle vérification automatique. Les secrets ne sont pas renvoyés.';failures++;timer=setTimeout(refresh,Math.min(30000,4000*failures));}}
 }
 document.addEventListener('pcap:upload-start',()=>{try{uploadDraft=importForm.selection();}catch(e){uploadDraft=null;app()?.showToast('error','Secrets TLS',e.message);}});
 document.addEventListener('pcap:upload-queued',e=>{pending=uploadDraft?{id:e.detail.taskId,value:uploadDraft}:null;uploadDraft=null;importForm.clear();});
 document.addEventListener('pcap:upload-failed',()=>{pending=null;uploadDraft=null;importForm.clear();});
 document.addEventListener('pcap:analysis-loaded',async()=>{
  capture=app()?.currentTaskId;lastReport=null;reportKey=null;source.hidden=true;sourceNote.hidden=true;if(app())app().tlsHttpView=null;generation++;offset=0;failures=0;readinessKey=null;readiness.hidden=true;statusMeta.textContent='';clearTimeout(timer);existingForm.clear();output.replaceChildren();pager.replaceChildren();
  if(pending&&pending.id===capture){const chosen=pending;pending=null;try{await submit(chosen.id,chosen.value);}catch(e){if(capture===chosen.id){showError(e.message);app()?.showToast('error','Déchiffrement TLS',e.message);}}return;}
  refresh();
 });
})();
