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
 function isDemoURL(href){try{return new URL(href,'https://pcap.invalid').searchParams.get('demo')==='1';}catch(_){return false;}}
 if(typeof module!=='undefined'&&module.exports)module.exports={steps,isDemoURL};
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id);
 let index=0,timer=null,running=false,busy=false,epoch=0,demoTaskId=null;
 const app=()=>typeof analyzer==='undefined'?null:analyzer;
 function pause(){if(timer)clearInterval(timer);timer=null;$('demoAuto').textContent='Lecture auto';$('demoAuto').setAttribute('aria-pressed','false');}
 function stop(){epoch++;running=false;pause();$('demoTour').hidden=true;document.body.classList.remove('demo-running');$('demoStart').focus();}
 function show(next){
  if(!running)return;
  if(app()?.currentTaskId!==demoTaskId){stop();return;}
  index=Math.max(0,Math.min(steps.length-1,next));const step=steps[index];
  if(document.getElementById('detailModal')?.classList.contains('open'))app()?.closeModal();
  if(step.view)document.querySelector(`[data-nomios-view="${step.view}"]`)?.click();
  else document.querySelector(`.nomios-module-nav [data-tab="${step.tab}"]`)?.click();
  $('demoNext').disabled=false;$('demoAuto').disabled=false;
  $('demoCounter').textContent=`${index+1} / ${steps.length}`;$('demoTitle').textContent=step.title;$('demoDescription').textContent=step.text;$('demoStatus').textContent='';
  $('demoProgress').style.setProperty('--demo-progress',`${(index+1)/steps.length*100}%`);
  $('demoPrev').disabled=index===0;$('demoNext').textContent=index===steps.length-1?'Terminer ✓':'Suivant →';
  if(!timer)$('demoTitle').focus({preventScroll:true});
  if(index===steps.length-1)pause();
 }
 async function start(){
  if(busy)return;pause();running=false;demoTaskId=null;busy=true;const current=++epoch;const button=$('demoStart');button.disabled=true;button.textContent='Préparation…';
  $('demoCounter').textContent='';$('demoProgress').style.setProperty('--demo-progress','0%');$('demoNext').disabled=true;$('demoPrev').disabled=true;$('demoAuto').disabled=true;
  $('demoTour').hidden=false;document.body.classList.add('demo-running');$('demoTitle').textContent='Préparation du scénario';$('demoDescription').textContent='Chargement d’un PCAP synthétique et de ses analyses réelles.';$('demoStatus').textContent='';
  try{
   const response=await fetch('/api/demo/start',{method:'POST',signal:AbortSignal.timeout(60000)});
   if(!response.ok)throw new Error('Préparation indisponible. Vérifiez votre connexion et réessayez.');
   const data=await response.json();if(current!==epoch)return;
   demoTaskId=data.task_id;
   const loaded=await app().loadHistoryItem(data.task_id,()=>current===epoch);if(current!==epoch)return;
   if(!loaded)throw new Error('La capture de démonstration n’a pas pu être ouverte. Réessayez.');
   await app().loadHistory();if(current!==epoch)return;
   demoTaskId=data.task_id;running=true;show(0);
  }catch(error){if(current===epoch){$('demoTitle').textContent='Démonstration indisponible';$('demoDescription').textContent=error.message;$('demoStatus').textContent='Fermez cette visite puis cliquez à nouveau sur Démo pour réessayer.';}}
  finally{busy=false;button.disabled=false;button.textContent='▶ Démo';}
 }
 $('demoStart')?.addEventListener('click',start);$('demoStop')?.addEventListener('click',stop);
 $('demoNext')?.addEventListener('click',()=>{pause();index===steps.length-1?stop():show(index+1);});
 $('demoPrev')?.addEventListener('click',()=>{pause();show(index-1);});
 $('demoAuto')?.addEventListener('click',()=>{if(!running)return;if(timer){pause();return;}$('demoAuto').textContent='Pause';$('demoAuto').setAttribute('aria-pressed','true');timer=setInterval(()=>{if(document.hidden)return;show(index+1);},12000);});
 document.addEventListener('pcap:analysis-loaded',()=>{if((running||busy)&&app()?.currentTaskId!==demoTaskId)stop();});
 document.addEventListener('pcap:upload-start',()=>{if(running||busy)stop();});
 document.addEventListener('keydown',event=>{if(event.key==='Escape'&&running)stop();});
 // No capture links or upload is overridden unless the user explicitly requested demo=1.
 if(isDemoURL(location.href))window.addEventListener('load',start,{once:true});
})();
