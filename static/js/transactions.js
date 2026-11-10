/* Measured exchanges only. Side B never changes the globally active capture. */
(function () {
 'use strict';
 const names={dns:'Résolution DNS',tcp:'Établissement TCP',tls:'Réponse ServerHello',http:'Réponse HTTP visible'};
 const safeId=id=>/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(String(id||''));
 function delta(a,b){if(!Number.isFinite(a)||!Number.isFinite(b)||a<0||b<0)return null;return {difference:b-a,percent:a===0?null:(b-a)/a*100};}
 function comparison(a,b){return Object.keys(names).map(key=>({key,name:names[key],before:a?.stages?.[key]?.duration_ms??null,after:b?.stages?.[key]?.duration_ms??null,change:a?.kind===b?.kind?delta(a?.stages?.[key]?.duration_ms,b?.stages?.[key]?.duration_ms):null}));}
 function evidenceUrl(task,frame){if(!safeId(task)||!Number.isSafeInteger(frame)||frame<1||frame>250000)return null;return '/?task='+encodeURIComponent(task)+'#tab=packets&packet='+(frame-1);}
 const exported={delta,comparison,evidenceUrl};
 if(typeof module!=='undefined'&&module.exports)module.exports=exported;
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id),el=(tag,text,cls)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;};
 const app=()=>typeof analyzer==='undefined'?null:analyzer;
 const sideState=()=>({task:'',data:[],selected:null,next:null,cursor:0,previous:[],request:0,loading:false});
 let sides={Left:sideState(),Right:sideState()},active='',epoch=0,historyEpoch=0;
 const format=value=>Number.isFinite(value)?value.toLocaleString('fr-FR',{maximumFractionDigits:3})+' ms':'Non mesurable';
 const address=endpoint=>endpoint?(endpoint.ip.includes(':')?'['+endpoint.ip+']':endpoint.ip)+':'+(endpoint.port??'—'):'—';
 const label=item=>'Paquet '+item.anchor_frame+' · '+(item.kind==='dns'?'DNS':item.http_method||'TCP')+' · '+(item.host||address(item.server));
 function selected(side){return side.data.find(item=>item.anchor_frame===side.selected)||null;}
 function drawComparison(){
  const a=selected(sides.Left),b=selected(sides.Right),host=$('txCompareTable');host.replaceChildren();
  if(!a||!b||sides.Left.loading||sides.Right.loading){$('txCompareMessage').textContent='Choisissez un échange de chaque côté ; les valeurs manquantes restent inconnues.';return;}
  const sameEndpoint=a.server.ip===b.server.ip&&a.server.port===b.server.port;
  const sameHost=a.host&&b.host&&a.host.toLowerCase()===b.host.toLowerCase();
  const different=a.kind!==b.kind||a.http_method!==b.http_method||(!sameEndpoint&&!sameHost);
  $('txCompareMessage').textContent=a.kind!==b.kind?'Échanges de natures différentes : aucun écart calculé.':different?'Les services ou méthodes diffèrent. Les écarts numériques ne prouvent pas l’effet d’une correction.':'Échanges candidats à une comparaison : confirmez la même opération et des conditions de capture comparables.';
  const table=el('table'),head=el('thead'),hr=el('tr');for(const text of ['Étape','A · Référence','B · Comparaison','Écart B − A'])hr.append(el('th',text));head.append(hr);table.append(head);const body=el('tbody');
  for(const row of comparison(a,b)){const tr=el('tr');const change=row.change;const text=change?(change.difference>0?'+':'')+format(change.difference)+(change.percent===null?'':' · '+(change.percent>0?'+':'')+change.percent.toFixed(1)+' %'):'Non comparable';tr.append(el('th',row.name),el('td',format(row.before)),el('td',format(row.after)),el('td',text));body.append(tr);}table.append(body);host.append(table);
  host.append(el('p','Compteurs de connexion (pas des taux de perte) · RST : '+a.resets+' → '+b.resets+' · retransmissions observées : '+a.retransmissions+' → '+b.retransmissions,'tx-scope'));
 }
 function drawStages(name){
  const side=sides[name],item=selected(side),host=$('tx'+name+'Stages');host.replaceChildren();if(!item){drawComparison();return;}
  host.append(el('p',address(item.client)+' → '+address(item.server),'tx-endpoints'));
  if(item.endpoint_basis==='first_observed_packet')host.append(el('p','Sens client/serveur indéterminé : adresses présentées selon le premier paquet observé.','tx-scope'));
  if(item.dns_rcode!==null&&item.dns_rcode!==undefined)host.append(el('p','Code DNS : '+({0:'NOERROR',2:'SERVFAIL',3:'NXDOMAIN',5:'REFUSED'}[item.dns_rcode]??item.dns_rcode),'tx-result'));
  if(item.http_status)host.append(el('p','Réponse HTTP : '+item.http_status,'tx-result'));
  if(item.resets)host.append(el('p',item.resets+' reset(s) observé(s) sur cette connexion.','tx-result'));
  const stages=el('div',undefined,'tx-stage-list');
  for(const [key,title] of Object.entries(names)){
   const stage=item.stages[key],card=el('article',undefined,'tx-stage '+(stage.state==='error'?'has-error':stage.duration_ms===null?'is-missing':'is-measured'));
   card.append(el('div',key.toUpperCase(),'tx-stage-kind'),el('h4',title),el('strong',format(stage.duration_ms)));
   if(stage.association==='candidate')card.append(el('span','Association candidate','tx-tag'));
   card.append(el('p',stage.note));const links=el('div',undefined,'tx-evidence');
   for(const frame of stage.evidence_frames||[]){const url=evidenceUrl(side.task,frame);if(url){const link=el('a','Paquet '+frame+' ↗');link.href=url;link.target='_blank';link.rel='noopener';links.append(link);}}card.append(links);stages.append(card);
  }host.append(stages);drawComparison();
 }
 function drawControls(name){
  const side=sides[name],host=$('tx'+name+'Controls');host.replaceChildren();
  const labelNode=el('label','Échange observé');labelNode.htmlFor='tx'+name+'Transaction';const select=el('select');select.id=labelNode.htmlFor;
  for(const item of side.data){const option=el('option',label(item));option.value=item.anchor_frame;option.selected=item.anchor_frame===side.selected;select.append(option);}select.disabled=!side.data.length||side.loading;
  select.addEventListener('change',()=>{side.selected=Number(select.value);drawStages(name);});host.append(labelNode,select);
  const actions=el('div',undefined,'tx-page-actions');const prev=el('button','← Précédents','btn btn-secondary'),next=el('button','Suivants →','btn btn-secondary'),retry=el('button','Actualiser','btn btn-secondary');
  for(const button of [prev,next,retry])button.type='button';prev.disabled=side.loading||!side.previous.length;next.disabled=side.loading||side.next===null;retry.disabled=side.loading||!side.task;
  prev.addEventListener('click',()=>read(name,side.task,side.previous.pop(),false));next.addEventListener('click',()=>{side.previous.push(side.cursor);read(name,side.task,side.next,false);});retry.addEventListener('click',()=>read(name,side.task,side.cursor,false));actions.append(prev,next,retry);host.append(actions);
 }
 async function read(name,task,cursor=0,reset=true){
  if(!safeId(task))return;
  const side=sides[name],request=++side.request,generation=epoch;side.task=task;side.loading=true;side.cursor=cursor;if(reset)side.previous=[];side.data=[];side.selected=null;side.next=null;drawControls(name);drawStages(name);$('tx'+name+'Status').textContent='Lecture bornée du PCAP original…';
  try{
   const response=await fetch('/api/analysis/'+encodeURIComponent(task)+'/transactions?after_frame='+cursor+'&limit=10',{cache:'no-store',signal:AbortSignal.timeout(25000)});
   if(!response.ok)throw Error(response.status===404?'PCAP original indisponible ou accès à cette capture impossible.':'Lecture indisponible ou moteur occupé. Réessayez avec Actualiser.');
   const report=await response.json();if(generation!==epoch||request!==side.request)return;
   side.data=report.data;side.next=report.next_after_frame;side.selected=side.data[0]?.anchor_frame??null;
   $('tx'+name+'Status').textContent=(report.coverage.complete?'Inspection complète dans les limites du moteur.':'Inspection partielle ('+String(report.coverage.reason||'limite atteinte')+').')+' '+side.data.length+' échanges sur cette page · '+report.observed_transactions+' observés dans le périmètre. Les étapes absentes ne prouvent pas une panne.';
  }catch(error){if(generation===epoch&&request===side.request)$('tx'+name+'Status').textContent=error.message;}
  finally{if(generation===epoch&&request===side.request){side.loading=false;drawControls(name);drawStages(name);}}
 }
 async function history(){
  const request=++historyEpoch,generation=epoch,select=$('txComparisonCapture');select.replaceChildren(el('option','Choisir une capture…'));select.firstChild.value='';
  try{const response=await fetch('/api/history?limit=500',{cache:'no-store',signal:AbortSignal.timeout(12000)});if(!response.ok)throw Error();const report=await response.json();if(request!==historyEpoch||generation!==epoch)return;
   const entries=report.history||report.analyses||report;for(const item of entries){const task=item.task_id;if(!safeId(task))continue;const option=el('option',(item.filename||task)+' · '+task);option.value=task;option.selected=task===sides.Right.task;select.append(option);}$('txHistoryStatus').textContent='La capture B est lue séparément ; elle ne remplace pas la capture active.';
  }catch(_){if(request===historyEpoch&&generation===epoch)$('txHistoryStatus').textContent='Bibliothèque indisponible. Revenez dans cette vue pour réessayer.';}
 }
 function load(task){if(!safeId(task))return;if(active===task){history();return;}epoch++;active=task;sides={Left:sideState(),Right:sideState()};$('txLeftCapture').textContent=(app()?.currentResults?.metadata?.filename||task)+' · '+task;$('txRightStatus').textContent='Choisissez une capture pour comparer deux échanges.';drawControls('Right');drawStages('Right');history();read('Left',task);}
 $('txComparisonCapture')?.addEventListener('change',event=>{const task=event.target.value;if(task)read('Right',task);else{++sides.Right.request;sides.Right=sideState();drawControls('Right');drawStages('Right');}});
 document.addEventListener('pcap:analysis-loaded',()=>{const task=app()?.currentTaskId;if(task!==active){epoch++;active='';for(const name of ['Left','Right']){$('tx'+name+'Stages')?.replaceChildren();$('tx'+name+'Controls')?.replaceChildren();}if(app()?.currentTabId==='transactions')load(task);}});
 window.PcapTransactions={...exported,load};
})();
