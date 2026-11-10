/* Real module navigation over an explicitly synthetic, stored capture. */
(function(){
 'use strict';
 const steps=[
  {tab:'overview',title:'Un incident, une vue d’ensemble',text:'Scénario : le portail support répond de façon intermittente. Les 192 paquets ont été générés hors ligne. Les graphiques et compteurs proviennent du moteur réel.'},
  {tab:'tcp-health',title:'Prioriser les vérifications réseau',text:'Comparez retransmissions, resets et RTT. Le scénario contient six connexions réinitialisées. Les scores sont des pistes heuristiques, pas une preuve de responsabilité.'},
  {tab:'streams',title:'Remonter à la conversation',text:'Retrouvez les échanges entre 192.0.2.10 et 198.51.100.20. Comparez les échanges avec une réponse HTTP et ceux qui présentent un reset ou une retransmission.'},
  {tab:'packets',title:'Revenir aux preuves',text:'Le paquet n°8 est un reset TCP dans la première conversation. Cliquez sur cette ligne pour inspecter les couches OSI. L’inspection s’appuie sur le PCAP original.'},
  {tab:'dns',title:'Vérifier la résolution de noms',text:'Le scénario alterne des réponses valides pour portail.support.example et des réponses NXDOMAIN pour introuvable.support.example. Corrélez noms, horodatages et symptômes.'},
  {tab:'http',title:'Comprendre les échanges applicatifs',text:'Les requêtes HTTP et leurs réponses sont visibles. Ce PCAP ne contient aucun secret ni trafic TLS : le formulaire de déchiffrement reste disponible pour vos captures compatibles.'},
  {tab:'timeline',title:'Replacer l’incident dans le temps',text:'Le trafic se déroule le 9 novembre 2026 à 13:00 UTC sur environ 48 secondes. Utilisez la chronologie pour rapprocher les échanges du moment du symptôme.'},
  {tab:'qos',title:'Explorer la qualité de service',text:'Consultez les indicateurs de débit, de rythme et de qualité issus de la capture. Ce scénario court ne constitue pas une mesure de capacité du réseau.'},
  {tab:'tls-audit',title:'Identifier les limites de la capture',text:'Aucune session TLS n’a été générée ici. Sur une capture adaptée, ce module permet l’examen des versions TLS et des certificats ; aucun déchiffrement fictif n’est simulé.'},
  {tab:'threat-intel',title:'Examiner les indicateurs de sécurité',text:'Ce jeu de données utilise uniquement des adresses réservées à la documentation. Les éventuels signaux restent des observations à vérifier ; aucune compromission réelle n’est simulée.'},
  {tab:'flow-behavior',title:'Explorer les comportements des flux',text:'Examinez les indicateurs C2/exfiltration disponibles. Une absence d’alerte dans cette courte capture synthétique ne prouve pas l’absence de menace dans un réseau réel.'},
  {tab:'lateral-movement',title:'Explorer les communications internes',text:'Ce module recherche des comportements de mouvement latéral. Le scénario support ne contient pas de déplacement latéral malveillant ; utilisez une capture adaptée pour cette investigation.'},
  {tab:'playbook',title:'Organiser la réponse à l’incident',text:'Consultez les pistes et le playbook disponibles, puis préparez les vérifications côté poste, pare-feu et serveur. Les exports restent accessibles dans la barre de rapports.'},
  {view:'assistants',title:'Observer l’activité réelle du MCP',text:'Cette page affiche les appels effectivement reçus. La démo ne fabrique aucune activité de Claude ou ChatGPT. Le serveur MCP peut rechercher dans ce PCAP synthétique avec son identifiant.'},
  {tab:'overview',title:'Poursuivre avec Claude et transmettre',text:'Cliquez sur « Préparer avec l’assistant », saisissez le symptôme puis copiez la consigne MCP dans Claude. Pour Multi-PCAP, importez deux captures de points différents. Le Centre de sécurité présente les contrôles Azure et MCP.'}
 ];
 function stageReadiness(loading,error){return loading?'loading':error?'error':'ready';}
 function isDemoURL(href){try{return new URL(href,'https://pcap.invalid').searchParams.get('demo')==='1';}catch(_){return false;}}
 if(typeof module!=='undefined'&&module.exports)module.exports={steps,isDemoURL,stageReadiness};
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id);
 let index=0,timer=null,running=false,busy=false,epoch=0,demoTaskId=null,auto=false,serial=0,evidence=null,target=null;
 const app=()=>typeof analyzer==='undefined'?null:analyzer;
 const targets=['.summary-cards','#tcpHealthDiagnosis','#streamConversation','#modalBody .osi-layer[data-layer="l4_transport"]','#dnsAnomaliesTable','#httpRequestsTable','#timelineVis','#tab-qos','#tab-tls-audit','#tab-threat-intel','#tab-flow-behavior','#tab-lateral-movement','#tab-playbook','#nomiosActivityMessage','#demoConclusion'];
 const delays=[14000,18000,18000,20000,18000,16000,14000,12000,10000,10000,10000,10000,12000,14000,25000];
 function pause(){auto=false;if(timer)clearTimeout(timer);timer=null;$('demoAuto').textContent='Reprendre';$('demoAuto').setAttribute('aria-pressed','false');}
 function clearSpot(){target?.classList.remove('demo-focus-target');target=null;$('demoSpotlight').hidden=true;document.body.classList.remove('demo-spotlight');}
 function stop(){epoch++;serial++;running=false;pause();clearSpot();$('demoTour').hidden=true;$('demoConclusion').hidden=true;document.body.classList.remove('demo-running');if($('detailModal')?.classList.contains('open'))app()?.closeModal();$('demoStart').focus();}
 function current(token){return running&&token===serial&&app()?.currentTaskId===demoTaskId;}
 function visible(node){return node&&node.getBoundingClientRect().width>0&&node.getBoundingClientRect().height>0;}
 async function ready(selector,token,predicate=()=>true){
  const began=Date.now();
  while(current(token)){
   const node=document.querySelector(selector);
   if(visible(node)&&predicate(node))return node;
   if(Date.now()-began>20000)throw new Error('Ce module ne répond pas encore. Réessayez cette étape ou passez à la suivante.');
   await new Promise(resolve=>setTimeout(resolve,120));
  }
  throw new Error('cancelled');
 }
 function position(){
  if(!visible(target)||$('demoTour').hidden)return;
  const r=target.getBoundingClientRect(),spot=$('demoSpotlight'),bubble=$('demoTour');
  const top=Math.max(76,r.top-6),left=Math.max(8,r.left-6),width=Math.min(innerWidth-left-8,r.width+12),height=Math.max(0,Math.min(innerHeight-12,r.bottom+6)-top);
  Object.assign(spot.style,{top:top+'px',left:left+'px',width:width+'px',height:height+'px'});
  const bw=bubble.offsetWidth,bh=bubble.offsetHeight;
  let x=r.right+18,y=Math.max(85,r.top);
  if(x+bw>innerWidth-12){x=Math.max(12,Math.min(r.left,innerWidth-bw-12));y=r.bottom+18;}
  if(y+bh>innerHeight-12)y=Math.max(85,innerHeight-bh-12);
  Object.assign(bubble.style,{left:x+'px',right:'auto',top:y+'px',bottom:'auto'});
 }
 function spotlight(node){target=node;node.classList.add('demo-focus-target');node.scrollIntoView({block:'start',behavior:'instant'});$('demoSpotlight').hidden=false;document.body.classList.add('demo-spotlight');position();}
 function nextTimer(){if(timer)clearTimeout(timer);timer=null;if(!auto||!running||index===steps.length-1)return;timer=setTimeout(()=>{if(document.hidden){nextTimer();return;}show(index+1);},delays[index]);}
 function autoplay(){if(!running)return;auto=true;$('demoAuto').textContent='Pause';$('demoAuto').setAttribute('aria-pressed','true');if(!$('demoNext').disabled)nextTimer();}
 function conclusion(){
  const host=$('demoConclusion');host.replaceChildren();host.hidden=false;
  const title=document.createElement('h3');title.textContent='Synthèse de l’incident · preuves du PCAP';host.append(title);
  for(const text of [`${evidence.resets.count} resets TCP observés — première preuve : paquet n°${evidence.resets.frames[0]}.`,`${evidence.dns_errors.count} réponses NXDOMAIN : vérifier le nom demandé et le résolveur.`,`${evidence.http_ok.count} réponses HTTP 200 : une partie des échanges applicatifs aboutit.`,`Cause racine non établie. Corréler les resets avec les journaux serveur/pare-feu et confirmer le point de capture.`,`Prochaine action : reproduire l’incident avec son heure précise ; comparer client et serveur. Ce scénario ne prouve aucune panne d’un équipement.`]){const p=document.createElement('p');p.textContent=text;host.append(p);}
  const button=document.createElement('button');button.type='button';button.className='support-primary';button.textContent='Préparer la suite avec Claude';button.addEventListener('click',()=>{pause();clearSpot();$('supportOpenBrief').click();});host.append(button);
 }
 async function show(next){
  if(!running)return;
  if(app()?.currentTaskId!==demoTaskId){stop();return;}
  if(timer)clearTimeout(timer);timer=null;const token=++serial;clearSpot();
  index=Math.max(0,Math.min(steps.length-1,next));const step=steps[index];
  $('demoNext').disabled=true;$('demoPrev').disabled=true;
  $('demoCounter').textContent=`${index+1} / ${steps.length}`;$('demoTitle').textContent=step.title;$('demoDescription').textContent=step.text;$('demoStatus').textContent='Ouverture et préparation de l’analyse…';
  $('demoProgress').style.setProperty('--demo-progress',`${(index+1)/steps.length*100}%`);
  $('demoConclusion').hidden=true;
  if($('detailModal')?.classList.contains('open'))app()?.closeModal();
  if(step.view)document.querySelector(`[data-nomios-view="${step.view}"]`)?.click();
  else document.querySelector(`.nomios-module-nav [data-tab="${step.tab}"]`)?.click();
  try{
   if(index===2){
    await ready('#streamsTable tbody tr',token,()=>Array.isArray(app().streamsData)&&app().streamsData.length>0);
    const stream=app().streamsData.find(x=>x.rst_count>0)||app().streamsData[0];
    const opened=await app().showStreamDetails(stream.stream_id,stream.stream_identifier||'',()=>current(token));
    if(current(token)&&!opened)throw new Error('La conversation ne peut pas être chargée. La présentation est en pause.');
    if(!current(token))return;
   }
   if(index===3){
    await ready('#packetTableBody tr',token);
    const opened=await app().showPacketDetails(evidence.resets.frames[0]-1,()=>current(token));
    if(current(token)&&!opened)throw new Error('L’inspection du paquet a échoué. La présentation est en pause.');
   }
   if(index===steps.length-1)conclusion();
   const node=await ready(targets[index],token,n=>{
    const loading=document.getElementById(step.tab+'-loading');
    const failure=document.querySelector('#tab-'+step.tab+' .adv-error');
    const state=stageReadiness(visible(loading),failure?.textContent);
    if(state==='error')throw new Error('Analyse indisponible : '+failure.textContent.trim().slice(0,180));
    return state==='ready'&&(index!==1||n.textContent.trim().length>40);
   });
   if(!current(token))return;
   if(index===1)$('demoDescription').textContent=`Lecture du PCAP original : ${evidence.resets.count} resets TCP. Le diagnostic propose des pistes ; il ne prouve pas la responsabilité du serveur ou du pare-feu.`;
   if(index===3)$('demoDescription').textContent=`Inspection ouverte automatiquement : paquet Wireshark n°${evidence.resets.frames[0]}, drapeau RST. Les adresses, ports et couches viennent du fichier original. Un reset ferme la connexion ; son origine doit être corrélée avec les journaux.`;
   if(index===4)$('demoDescription').textContent=`${evidence.dns_errors.count} réponses NXDOMAIN observées. Le nom introuvable.support.example ne se résout pas ; ce constat DNS est distinct des resets sur le portail.`;
   if(index===5)$('demoDescription').textContent=`${evidence.http_ok.count} réponses HTTP 200 dans la capture. Les échanges qui aboutissent permettent de comparer le cas nominal avec les connexions réinitialisées. Aucune session TLS dans ce scénario.`;
   $('demoStatus').textContent='Analyse affichée · données synthétiques, preuves réelles';spotlight(node);
   if(!auto)$('demoTitle').focus({preventScroll:true});
   if(index===steps.length-1)pause();else nextTimer();
  }catch(error){if(current(token)){pause();$('demoStatus').textContent=error.message;}}
  finally{if(current(token)){$('demoNext').disabled=false;$('demoPrev').disabled=index===0;$('demoNext').textContent=index===steps.length-1?'Terminer ✓':'Suivant →';}}
 }
 async function start(){
  if(busy)return;pause();running=false;demoTaskId=null;busy=true;const currentEpoch=++epoch;const button=$('demoStart');button.disabled=true;button.textContent='Préparation…';
  $('demoCounter').textContent='';$('demoNext').disabled=true;$('demoPrev').disabled=true;$('demoAuto').disabled=true;
  $('demoTour').hidden=false;document.body.classList.add('demo-running');$('demoTitle').textContent='Lecture des preuves du scénario';$('demoDescription').textContent='Le PCAP synthétique est chargé, puis Wireshark vérifie les resets TCP, les erreurs DNS et les réponses HTTP.';$('demoStatus').textContent='';
  try{
   const response=await fetch('/api/demo/start',{method:'POST',signal:AbortSignal.timeout(60000)});
   if(!response.ok)throw new Error('Préparation indisponible. Vérifiez votre connexion et réessayez.');
   const data=await response.json();if(currentEpoch!==epoch)return;demoTaskId=data.task_id;
   const proof=await fetch(`/api/demo/${demoTaskId}/evidence`,{signal:AbortSignal.timeout(30000)});
   if(!proof.ok)throw new Error('Le moteur ne peut pas vérifier les preuves du scénario. Réessayez.');
   evidence=await proof.json();if(currentEpoch!==epoch)return;
   if(!evidence.coverage?.complete||!evidence.resets?.frames?.length)throw new Error('Preuves incomplètes : la présentation automatique est suspendue.');
   const loaded=await app().loadHistoryItem(data.task_id,()=>currentEpoch===epoch);if(currentEpoch!==epoch)return;
   if(!loaded)throw new Error('La capture de démonstration n’a pas pu être ouverte.');
   await app().loadHistory();if(currentEpoch!==epoch)return;
   running=true;$('demoAuto').disabled=false;auto=true;$('demoAuto').textContent='Pause';$('demoAuto').setAttribute('aria-pressed','true');await show(0);
  }catch(error){if(currentEpoch===epoch){$('demoTitle').textContent='Démonstration indisponible';$('demoDescription').textContent=error.message;$('demoStatus').textContent='Fermez puis relancez la démo pour réessayer.';}}
  finally{busy=false;button.disabled=false;button.textContent='▶ Démo';}
 }
 $('demoStart')?.addEventListener('click',start);$('demoStop')?.addEventListener('click',stop);
 $('demoNext')?.addEventListener('click',()=>{pause();index===steps.length-1?stop():show(index+1);});
 $('demoPrev')?.addEventListener('click',()=>{pause();show(index-1);});
 $('demoAuto')?.addEventListener('click',()=>{if(auto)pause();else autoplay();});
 window.addEventListener('resize',position);document.addEventListener('scroll',position,{passive:true,capture:true});
 document.addEventListener('pcap:analysis-loaded',()=>{if((running||busy)&&app()?.currentTaskId!==demoTaskId)stop();});
 document.addEventListener('pcap:upload-start',()=>{if(running||busy)stop();});
 document.addEventListener('keydown',event=>{if(event.key==='Escape'&&(running||busy))stop();});
 if(isDemoURL(location.href))window.addEventListener('load',start,{once:true});
})();
