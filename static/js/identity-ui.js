/* Live identity and MCP activity. No demo counters or captured evidence. */
(() => {
 'use strict';
 const $=id=>document.getElementById(id);
 let activeView='workspace', user=null, loading=false;
 const controller=()=>typeof analyzer==='undefined'?null:analyzer;
 const names={'34a342ef-6924-42f4-b3b5-c8e53da5bbd2':'Claude'};
 const date=value=>value?new Date(value*1000).toLocaleString('fr-FR',{timeZone:'UTC'})+' UTC':'Aucun appel enregistré';
 function element(tag,text,className){const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(className)node.className=className;return node;}
 async function json(path,options){const response=await fetch(path,options);if(!response.ok)throw new Error(response.status===403?'Accès refusé. Vérifiez votre groupe ou reconnectez-vous.':'Service indisponible. Réessayez.');return response.json();}
 function view(name){
  activeView=name;
  document.querySelector('.main-content').classList.toggle('nomios-secondary-view',['assistants','admin'].includes(name));
  $('nomiosAssistants').hidden=name!=='assistants';$('nomiosAdmin').hidden=name!=='admin';
 document.querySelectorAll('[data-nomios-view]').forEach(button=>button.classList.toggle('selected',button.dataset.nomiosView===name));
  document.querySelector('.nomios-sidebar').classList.toggle('is-library',name==='captures');
  if(name==='captures'){
   $('resultsSection').style.display='none';
   $('uploadSection').style.display='block';
   document.querySelector('.main-content').scrollIntoView({behavior:'smooth'});
  }
  if(name==='assistants')loadActivity();
  if(name==='admin')loadGroup();
 }
  document.addEventListener('pcap:analysis-loaded',()=>view('workspace'));
 document.querySelectorAll('.nomios-module-nav .tab').forEach(button=>button.addEventListener('click',event=>{
  const app=controller(), module=button.dataset.tab;
  view('workspace');
  if(module==='multi-pcap') {
   event.stopImmediatePropagation();
   app?.openMultiPcapMode();
   return;
  }
  if(!app?.currentResults) {
   event.stopImmediatePropagation();
   document.querySelector('.history-section')?.scrollIntoView({behavior:'smooth'});
   app?.showToast('info','Choisir une capture','Ouvrez ou importez un PCAP pour explorer ses résultats.');
   return;
  }
  $('resultsSection').style.display='block';
  $('uploadSection').style.display='none';
 },{capture:true}));
 document.querySelectorAll('[data-nomios-view]').forEach(button=>button.addEventListener('click',()=>view(button.dataset.nomiosView)));
 document.querySelectorAll('[data-nomios-module]').forEach(button=>button.addEventListener('click',()=>{
  view('workspace');
  const module=button.dataset.nomiosModule;
  const results=$('resultsSection');
  if(module==='multi-pcap'&&controller()){results.style.display='block';controller().switchTab(module);}
  else if(results.style.display!=='none'&&controller())controller().switchTab(module);
  else {$('uploadSection').scrollIntoView({behavior:'smooth'});controller()?.showToast?.('info','Ouvrir une analyse','Sélectionnez une capture dans l’historique pour explorer ce module.');}
 }));
 let registry={},seen=new Set(),initialized=false,paused=false;
 function logo(info){const box=element('span',undefined,'assistant-logo '+info.provider);if(info.logo){const img=element('img');img.src='/static/img/assistants/'+info.logo;img.alt=info.name;box.append(img);}else box.textContent='MCP';return box;}
 function addCard(id,stats){
  const info=window.PcapActivity.brand(id,registry),card=element('article',undefined,'card nomios-assistant-card');
  card.append(logo(info),element('div',info.vendor,'provider'),element('h3',info.name));
  const recent=stats&&Date.now()/1000-stats.last_call<900;
  card.append(element('span',recent?'Appel récent':stats?'Aucune activité récente':'Aucun appel enregistré','activity-state'+(recent?' recent':'')));
  const counts=element('div',undefined,'nomios-counts');for(const [value,label] of [[stats?.calls_today??'—','Appels aujourd’hui · UTC'],[stats?.errors_30d??'—','Erreurs · 30 jours']]){const block=element('div');block.append(element('strong',String(value)),element('small',label));counts.append(block);}card.append(counts,element('p','Dernier appel : '+date(stats?.last_call)),element('small','Client OAuth : '+id));
  if(info.provider==='litellm')card.append(element('p','Le modèle derrière la passerelle n’est pas identifié par ces événements.'));
  $('nomiosAssistantCards').append(card);
 }
 async function loadActivity(){
  if(loading)return;loading=true;$('nomiosMcpEndpoint').textContent=location.origin+'/mcp';
  try{
   if(!window.PCAP_CONFIG?.webAuth)throw new Error('Le suivi réel nécessite Microsoft Entra ID et le stockage partagé.');
   const response=await fetch('/api/identity/activity',{cache:'no-store',signal:AbortSignal.timeout(12000)});if(!response.ok)throw new Error('Actualisation indisponible. Les derniers événements restent affichés.');
   const data=await response.json();registry=data.client_registry||{};
   const newEvents=window.PcapActivity.freshEvents(data.recent,seen);const highlights=initialized?new Set(newEvents.map(e=>e.event_id)):new Set();
   seen=new Set(data.recent.map(e=>e.event_id));initialized=true;
   $('nomiosAssistantCards').replaceChildren();$('nomiosActivityRows').replaceChildren();
   const clients=new Map(data.clients.map(client=>[client.client_id,client]));for(const id of new Set([...Object.keys(registry),...clients.keys()]))addCard(id,clients.get(id));
   for(const event of data.recent){const info=window.PcapActivity.brand(event.client_id,registry),row=element('tr');if(highlights.has(event.event_id))row.className='activity-new';const who=element('td');who.append(logo(info),element('span',info.name));row.append(element('td',date(event.occurred)),who);for(const value of [event.tool,event.success?'Réussi':'Erreur',event.duration_ms+' ms'])row.append(element('td',value));$('nomiosActivityRows').append(row);}
   if(!data.recent.length){const row=element('tr'),cell=element('td','Aucun appel enregistré. Lancez une recherche depuis votre assistant connecté.');cell.colSpan=5;row.append(cell);$('nomiosActivityRows').append(row);}
   $('nomiosActivityMessage').textContent=data.collection_state==='available'?'Flux des appels terminés · actualisation toutes les 5 secondes.':data.collection_state==='disabled'?'Collecte désactivée : les derniers enregistrements ne prouvent pas une connexion actuelle.':'Collecte indisponible : les chiffres peuvent être incomplets.';
   $('activityLastRefresh').textContent='Dernière actualisation : '+new Date().toLocaleTimeString('fr-FR');
  }catch(error){$('nomiosActivityMessage').textContent=error.message;}
  finally{loading=false;}
 }
 $('activityPause')?.addEventListener('click',()=>{paused=!paused;$('activityPause').textContent=paused?'Reprendre le flux':'Mettre en pause';$('activityPause').setAttribute('aria-pressed',String(paused));if(!paused)loadActivity();});
 async function loadGroup(){
  if(!user?.is_admin){$('nomiosGroupMessage').textContent='Administration réservée au propriétaire.';return;}
  $('nomiosTenant').value=user.tenant_id;
  try{const policy=await json('/api/identity/group');$('nomiosGroupId').value=policy.group_id;$('nomiosGroupMessage').textContent=policy.group_id?'Groupe enregistré. L’appartenance est vérifiée à la connexion.':'Accès réservé à l’administrateur.';}
  catch(error){$('nomiosGroupMessage').textContent=error.message;}
 }
 $('nomiosGroupForm').addEventListener('submit',async event=>{
  event.preventDefault();const button=event.currentTarget.querySelector('button');button.disabled=true;
  try{await json('/api/identity/group',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_id:$('nomiosGroupId').value.trim()})});$('nomiosGroupMessage').textContent='Groupe enregistré. Les autorisations des sessions seront réévaluées dès leur prochaine requête.';}
  catch(error){$('nomiosGroupMessage').textContent=error.message;}finally{button.disabled=false;}
 });
 async function logout(){try{await json('/api/identity/logout',{method:'POST'});location.assign('/auth/login');}catch(error){window.alert(error.message);}}
 $('nomiosLogout').addEventListener('click',logout);
 $('nomiosRefreshActivity').addEventListener('click',loadActivity);
 setInterval(()=>{if(activeView==='assistants'&&!document.hidden&&!paused)loadActivity();},5000);
 document.addEventListener('visibilitychange',()=>{if(!document.hidden&&activeView==='assistants'&&!paused)loadActivity();});
 if(!controller()?.currentResults)view('captures');
 if(window.PCAP_IDENTITY_READY)window.PCAP_IDENTITY_READY.then(identity=>{
  user=identity;$('nomiosUserName').textContent=identity.name;$('nomiosUserStatus').textContent='Microsoft Entra ID';$('nomiosLogout').hidden=false;$('nomiosAdminNav').hidden=!identity.is_admin;
  const logoutButton=element('button','Se déconnecter','btn btn-secondary');logoutButton.type='button';logoutButton.addEventListener('click',logout);document.querySelector('.header-info').append(logoutButton);
 }).catch(()=>{$('nomiosUserStatus').textContent='Connexion requise';});
 else {$('nomiosUserStatus').textContent=(window.PCAP_CONFIG?.requiresAccessKey||window.PCAP_CONFIG?.apiBaseUrl)?'Accès par clé API':'Mode local · sans authentification';}
})();
