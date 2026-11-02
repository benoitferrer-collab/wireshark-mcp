/* TLS secrets stay in this tab until submitted; never browser storage or MCP arguments. */
(() => {
 'use strict';
 if(!window.PCAP_CONFIG?.tlsDecryption)return;
 const node=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const app=()=>typeof analyzer==='undefined'?null:analyzer;
 let capture=null,timer=null,generation=0,pending=null,uploadDraft=null,offset=0;
 const panel=node('section',undefined,'tls-panel');panel.id='tlsDecryptionPanel';
 panel.append(node('p','INVESTIGATION TLS','tls-eyebrow'),node('h3','Vos échanges, déchiffrés.'),node('p','Ajoutez les secrets correspondant à cette capture pour retrouver les échanges HTTP/HTTPS.','tls-muted'));
 const live=node('p','Aucun déchiffrement demandé.','tls-status');live.setAttribute('role','status');
 const output=node('div');const pager=node('div',undefined,'tls-pager');
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
  else{const b=node('button','Déchiffrer cette capture','btn btn-primary');b.type='submit';f.append(b);f.addEventListener('submit',async e=>{e.preventDefault();if(!capture)return;try{await submit(capture,selection(),b);clear();}catch(error){live.textContent=error.message;}});}
  details.append(f);
  function selection(){const chosen=file.files[0];if(!chosen)return null;if(chosen.size>(select.value==='rsa'?65536:2097152))throw new Error('Fichier trop volumineux : RSA 64 Kio, keylog 2 Mio.');return {file:chosen,kind:select.value,password:password.value};}
  function clear(){file.value='';password.value='';}
  return {element:details,selection,clear};
 }
 const importForm=form(true),existingForm=form(false);
 document.getElementById('uploadArea')?.before(importForm.element);
 panel.append(existingForm.element,live,output,pager);document.getElementById('tab-http')?.prepend(panel);
 async function submit(id,selected,button){
  if(!selected)throw new Error('Sélectionnez un fichier de secrets.');
  const data=new FormData();data.append('kind',selected.kind);data.append('file',selected.file);data.append('password',selected.password);
  if(button)button.disabled=true;
  try{const response=await fetch(`/api/identity/tls/${encodeURIComponent(id)}`,{method:'POST',body:data});const result=await response.json();if(!response.ok)throw new Error(typeof result.detail==='string'?result.detail:'Déchiffrement non démarré. Vérifiez le fichier.');
   if(capture===id){offset=0;await refresh();}
  }finally{if(button)button.disabled=false;}
 }
 function render(data){
  output.replaceChildren();pager.replaceChildren();
  const labels={not_requested:'Aucun déchiffrement demandé.',queued:'Secrets reçus · en attente du worker.',processing:'Déchiffrement en cours…',failed:data.error||'Déchiffrement impossible.',completed:'Traitement terminé.'};
  live.textContent=labels[data.status]||data.status;
  const r=data.report;if(!r)return;
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
  try{const response=await fetch(`/api/identity/tls/${encodeURIComponent(id)}?offset=${offset}&limit=25`);if(!response.ok)throw new Error('Résultat TLS indisponible. Réessayez.');const data=await response.json();if(id!==capture||version!==generation)return;render(data);if(['queued','processing'].includes(data.status))timer=setTimeout(refresh,4000);}
  catch(e){if(version===generation)live.textContent=e.message;}
 }
 document.addEventListener('pcap:upload-start',()=>{try{uploadDraft=importForm.selection();}catch(e){uploadDraft=null;app()?.showToast('error','Secrets TLS',e.message);}});
 document.addEventListener('pcap:upload-queued',e=>{pending=uploadDraft?{id:e.detail.taskId,value:uploadDraft}:null;uploadDraft=null;importForm.clear();});
 document.addEventListener('pcap:upload-failed',()=>{pending=null;uploadDraft=null;importForm.clear();});
 document.addEventListener('pcap:analysis-loaded',async()=>{
  capture=app()?.currentTaskId;generation++;offset=0;clearTimeout(timer);existingForm.clear();output.replaceChildren();pager.replaceChildren();
  if(pending&&pending.id===capture){const chosen=pending;pending=null;try{await submit(chosen.id,chosen.value);}catch(e){live.textContent=e.message;app()?.showToast('error','Déchiffrement TLS',e.message);}return;}
  refresh();
 });
})();
