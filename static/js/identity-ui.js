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
  if(name==='captures')document.querySelector('.history-section').scrollIntoView({behavior:'smooth'});
  if(name==='assistants')loadActivity();
  if(name==='admin')loadGroup();
 }
 document.querySelectorAll('[data-nomios-view]').forEach(button=>button.addEventListener('click',()=>view(button.dataset.nomiosView)));
 document.querySelectorAll('[data-nomios-module]').forEach(button=>button.addEventListener('click',()=>{
  view('workspace');
  const module=button.dataset.nomiosModule;
  const results=$('resultsSection');
  if(module==='multi-pcap'&&controller()){results.style.display='block';controller().switchTab(module);}
  else if(results.style.display!=='none'&&controller())controller().switchTab(module);
  else {$('uploadSection').scrollIntoView({behavior:'smooth'});controller()?.showToast?.('info','Ouvrir une analyse','Sélectionnez une capture dans l’historique pour explorer ce module.');}
 }));
 function addCard(id, stats){
  const label=names[id]||'Client MCP';
  const card=element('article',undefined,'card nomios-assistant-card');
  card.append(element('div',label==='Claude'?'Anthropic':label==='ChatGPT'?'OpenAI':'Client autorisé','provider'),element('h3',label));
  const recent=stats&&Date.now()/1000-stats.last_call<900;
  card.append(element('span',recent?'Activité récente':stats?'Aucune activité récente':'Aucun appel enregistré','activity-state'+(recent?' recent':'')));
  const counts=element('div',undefined,'nomios-counts');
  for(const [count,caption] of [[stats?.calls_today??'—',"Appels aujourd’hui · UTC"],[stats?.calls_30d??'—','Appels sur 30 jours']]){const block=element('div');block.append(element('strong',String(count)),element('small',caption));counts.append(block);}
  card.append(counts,element('p','Dernier appel : '+date(stats?.last_call)),element('p','Dernière réussite : '+date(stats?.last_success)));
  card.append(element('p',stats?`${stats.calls_30d-stats.errors_30d} réussites · ${stats.errors_30d} erreurs sur 30 jours`:'Le compteur démarrera au premier appel enregistré.'));
  if(!names[id])card.append(element('p','Identifiant client : '+id));
  $('nomiosAssistantCards').append(card);
 }
 async function loadActivity(){
  if(loading)return;loading=true;
  $('nomiosMcpEndpoint').textContent=location.origin+'/mcp';
  try {
   if(!window.PCAP_CONFIG?.webAuth)throw new Error('Le suivi sera disponible après activation de la connexion Microsoft et du stockage partagé.');
   const data=await json('/api/identity/activity');
   $('nomiosAssistantCards').replaceChildren();$('nomiosActivityRows').replaceChildren();
   const clients=new Map(data.clients.map(client=>[client.client_id,client]));
   for(const id of new Set([...Object.keys(names),...clients.keys()]))addCard(id,clients.get(id));
   const chat=element('article',undefined,'card nomios-assistant-card');chat.append(element('div','OpenAI','provider'),element('h3','ChatGPT'),element('span','À configurer','activity-state'),element('p','Ajoutez un client OAuth dédié avant de connecter cet assistant.'));$('nomiosAssistantCards').append(chat);
   for(const event of data.recent){const row=element('tr');for(const value of [date(event.occurred),names[event.client_id]||event.client_id,event.tool,event.success?'Réussi':'Erreur',event.duration_ms+' ms'])row.append(element('td',value));$('nomiosActivityRows').append(row);}
   $('nomiosActivityMessage').textContent=data.collection_state!=='available' ? (data.collection_state==='disabled'?'La collecte MCP est désactivée. Les chiffres affichés sont les derniers enregistrements disponibles.':'Collecte MCP indisponible. Les derniers chiffres peuvent être incomplets ; aucune déconnexion ne peut être déduite.') : data.collection_started?'Historique disponible depuis le '+date(data.collection_started)+'. Actualisation toutes les 30 secondes.':'Aucun appel enregistré depuis l’activation du suivi. Les appels antérieurs ne sont pas reconstitués.';
  }catch(error){$('nomiosActivityMessage').textContent=error.message;$('nomiosAssistantCards').replaceChildren();$('nomiosActivityRows').replaceChildren();}
  finally{loading=false;}
 }
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
 setInterval(()=>{if(activeView==='assistants'&&!document.hidden)loadActivity();},30000);
 document.addEventListener('visibilitychange',()=>{if(!document.hidden&&activeView==='assistants')loadActivity();});
 if(window.PCAP_IDENTITY_READY)window.PCAP_IDENTITY_READY.then(identity=>{
  user=identity;$('nomiosUserName').textContent=identity.name;$('nomiosUserStatus').textContent='Microsoft Entra ID';$('nomiosLogout').hidden=false;$('nomiosAdminNav').hidden=!identity.is_admin;
  const logoutButton=element('button','Se déconnecter','btn btn-secondary');logoutButton.type='button';logoutButton.addEventListener('click',logout);document.querySelector('.header-info').append(logoutButton);
 }).catch(()=>{$('nomiosUserStatus').textContent='Connexion requise';});
 else {$('nomiosUserStatus').textContent='Accès par clé API';}
})();
