/* Explainable support findings. Captured strings and human ratings remain untrusted data. */
(function(){
 'use strict';
 const safeTask=task=>/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(String(task||''));
 function evidence(task,frame){return safeTask(task)&&Number.isSafeInteger(frame)&&frame>0&&frame<=250000?'/?task='+encodeURIComponent(task)+'#tab=packets&packet='+(frame-1):null;}
 function currentResult(state,task,generation){return state.task===task&&state.generation===generation;}
 const causes={unknown:'Choisir une cause confirmée…',dns:'Résolution DNS',tcp_connectivity:'Connectivité TCP',latency:'Latence',receiver_flow_control:'Contrôle de flux du récepteur',application:'Application / proxy',tls:'TLS',capture_artifact:'Artefact de capture',expected_behavior:'Comportement attendu',other:'Autre cause confirmée'};
 if(typeof module!=='undefined'&&module.exports)module.exports={evidence,currentResult,causes};
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id),el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const app=()=>typeof analyzer==='undefined'?null:analyzer;
 const button=(text,fn)=>{const n=el('button',text,'btn btn-secondary');n.type='button';n.addEventListener('click',fn);return n;};
 const state={task:'',generation:0,report:null,page:0,mine:{},controller:null};
 let historyGeneration=0;
 function reset(task){state.controller?.abort();state.generation++;state.task=task||'';state.report=null;state.mine={};state.page=0;$('supportDiagnosisResults')?.replaceChildren();$('supportDiagnosisStatus').textContent='Lecture à la demande du PCAP original · capture entière.';$('supportDiagnosisRun').disabled=false;$('supportDiagnosisReference').disabled=false;}
 async function history(){
  const request=++historyGeneration,select=$('supportDiagnosisReference');select.replaceChildren(el('option','Sans référence'));select.firstChild.value='';
  try{const response=await fetch('/api/history?limit=500',{cache:'no-store',signal:AbortSignal.timeout(12000)});if(!response.ok)return;const report=await response.json();if(request!==historyGeneration)return;for(const entry of report.history||report.analyses||report){if(!safeTask(entry.task_id)||entry.task_id===state.task)continue;const option=el('option',(entry.filename||entry.task_id)+' · '+entry.task_id);option.value=entry.task_id;select.append(option);}}
  catch(_){if(request===historyGeneration)$('supportDiagnosisStatus').textContent='Bibliothèque de références indisponible ; le diagnostic seul reste disponible.';}
 }
 async function run(){
  const task=app()?.currentTaskId;if(!safeTask(task))return;if(state.task!==task)reset(task);
  state.controller?.abort();const controller=new AbortController();state.controller=controller;const generation=++state.generation;
  state.report=null;state.mine={};state.page=0;$('supportDiagnosisResults').replaceChildren();$('supportDiagnosisRun').disabled=true;$('supportDiagnosisReference').disabled=true;
  $('supportDiagnosisStatus').textContent='Corrélation des métadonnées DNS, TCP, TLS et HTTP…';
  const reference=$('supportDiagnosisReference').value;const query=reference?'?reference_task_id='+encodeURIComponent(reference):'';
  const timeout=setTimeout(()=>controller.abort(),55000);
  try{const response=await fetch('/api/analysis/'+encodeURIComponent(task)+'/support-diagnosis'+query,{cache:'no-store',signal:controller.signal});if(!response.ok)throw Error(response.status===503?'Le moteur est occupé ou la capture est illisible ; réessayez.':response.status===404?'Le PCAP original est indisponible.':'Diagnostic indisponible ('+response.status+').');const report=await response.json();if(!currentResult(state,task,generation))return;state.report=report;
   if(report.feedback_available){try{const feedback=await fetch('/api/analysis/'+encodeURIComponent(task)+'/support-diagnosis/feedback?report_id='+report.report_id,{cache:'no-store',signal:controller.signal});if(feedback.ok){const value=await feedback.json();if(!currentResult(state,task,generation))return;state.mine=value.mine||{};}}catch(_){} }
   if(!currentResult(state,task,generation))return;draw();
  }catch(error){if(currentResult(state,task,generation))$('supportDiagnosisStatus').textContent=error.name==='AbortError'?'Lecture interrompue ou délai dépassé. Relancez le diagnostic.':error.message;}
  finally{clearTimeout(timeout);if(currentResult(state,task,generation)){$('supportDiagnosisRun').disabled=false;$('supportDiagnosisReference').disabled=false;}}
 }
 function list(title,items,host){if(!items?.length)return;host.append(el('h5',title));const ul=el('ul');for(const text of items)ul.append(el('li',text));host.append(ul);}
 async function rate(finding,rating,cause,status,controls){
  const task=state.task,report=state.report,generation=state.generation;if(!report)return;
  if(rating==='confirmed'&&cause==='unknown'){status.textContent='Sélectionnez la cause confirmée avant d’enregistrer.';return;}
  controls.forEach(c=>c.disabled=true);status.textContent='Enregistrement de votre avis…';
  try{const response=await fetch('/api/analysis/'+encodeURIComponent(task)+'/support-diagnosis/feedback',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({report_id:report.report_id,finding_id:finding.id,rating,cause}),signal:AbortSignal.timeout(15000)});if(!response.ok)throw Error(response.status===403?'Reconnectez-vous dans l’application pour enregistrer votre avis.':'Avis non enregistré. Réessayez.');const result=await response.json();if(!currentResult(state,task,generation)||state.report!==report)return;state.mine=result.mine||{};status.textContent='Votre avis est enregistré : '+({relevant:'pertinent',false_positive:'faux positif',confirmed:'cause confirmée'}[rating])+'.';}
  catch(error){if(currentResult(state,task,generation))status.textContent=error.message;}
  finally{if(currentResult(state,task,generation))controls.forEach(c=>c.disabled=false);}
 }
 function draw(){
  const report=state.report;if(!report)return;const host=$('supportDiagnosisResults');host.replaceChildren();
  $('supportDiagnosisStatus').textContent=(report.coverage.complete?'Inspection complète dans les limites du moteur.':'Inspection partielle · '+(report.coverage.reason||'limite atteinte')+'.')+' '+report.observed_findings+' constat(s) · '+report.summary.observed_sessions+' sessions TCP · version '+report.version+'.';
  host.append(el('p','Moteur de corrélation explicable : faits, hypothèses et preuves. Modèle appris : non activé ; vos avis préparent son évaluation.','sd-method'));
  if(report.synthetic_demo)host.append(el('p','Démo synthétique · les avis enregistrés ici sont exclus de l’export d’apprentissage.','sd-note'));
  if(!report.findings.length)host.append(el('p','Les observations disponibles ne permettent pas de proposer un diagnostic étayé. Confirmez le service, l’horaire et le point de capture.','sd-note'));
  if(report.findings_truncated)host.append(el('p','Les 20 premiers constats sont présentés ; utilisez les sessions et les paquets pour poursuivre.','sd-note'));
  const cards=el('div',undefined,'sd-findings');
  for(const finding of report.findings.slice(state.page*4,state.page*4+4)){
   const card=el('article',undefined,'sd-finding');const head=el('div',undefined,'sd-finding-head');head.append(el('span',finding.tcp_stream===null?'RÉSOLUTION DNS':'SESSION TCP #'+finding.tcp_stream,'support-eyebrow'),el('span','Cause à vérifier','sd-confidence'));card.append(head,el('h4',finding.title));list('Observations',finding.facts,card);
   const proofs=el('div',undefined,'sd-proofs');for(const frame of finding.evidence_frames){const href=evidence(state.task,frame);if(href){const link=el('a','Paquet #'+frame+' ↗');link.href=href;link.target='_blank';link.rel='noopener';proofs.append(link);}}card.append(proofs);list('Hypothèses',finding.hypotheses,card);list('Prochaines vérifications',finding.next_checks,card);
   const unknown=el('details');unknown.append(el('summary','Ce qui reste inconnu'));list('',finding.unknowns,unknown);card.append(unknown);
   if(report.feedback_available){const feedback=el('div',undefined,'sd-feedback'),status=el('p',undefined,'sd-feedback-status');status.setAttribute('role','status');const existing=state.mine[finding.id];status.textContent=existing?'Votre avis enregistré : '+({relevant:'pertinent',false_positive:'faux positif',confirmed:'cause confirmée'}[existing.rating])+'.':'Votre avis enrichit les futurs cas d’évaluation.';
    const select=el('select');select.setAttribute('aria-label','Cause confirmée pour '+finding.title);for(const [key,title] of Object.entries(causes)){const option=el('option',title);option.value=key;option.selected=key===(existing?.cause||'unknown');select.append(option);}const controls=[select];const actions=el('div',undefined,'sd-feedback-actions');for(const [value,title] of [['relevant','Pertinent'],['false_positive','Faux positif'],['confirmed','Confirmer la cause']]){const control=button(title,()=>rate(finding,value,select.value,status,controls));controls.push(control);actions.append(control);}feedback.append(select,actions,status);card.append(feedback);
   }else card.append(el('p','Enregistrement des avis indisponible pour cette lecture.','sd-note'));cards.append(card);
  }host.append(cards);
  const pages=el('div',undefined,'sd-page');if(state.page)pages.append(button('← Constats précédents',()=>{state.page--;draw();}));if((state.page+1)*4<report.findings.length)pages.append(button('Constats suivants →',()=>{state.page++;draw();}));host.append(pages);
  if(report.reference_comparison){const comparison=report.reference_comparison,section=el('section',undefined,'sd-reference');section.append(el('h4','Comparaison avec la référence sélectionnée'));
   for(const row of comparison.stages){section.append(el('p',row.service+' · '+row.stage.toUpperCase()+' : médiane '+row.current_median_ms+' ms / référence '+row.reference_median_ms+' ms · écart '+(row.difference_ms>=0?'+':'')+row.difference_ms+' ms · '+row.current_samples+' / '+row.reference_samples+' mesure(s).'));const links=el('div',undefined,'sd-proofs');for(const [task,frames,label] of [[state.task,row.current_evidence_frames,'Capture'],[report.reference_task_id,row.reference_evidence_frames,'Référence']]){for(const frame of frames||[]){const href=evidence(task,frame);if(href){const link=el('a',label+' #'+frame+' ↗');link.href=href;link.target='_blank';link.rel='noopener';links.append(link);}}}section.append(links);}
   if(comparison.stage_aggregation_truncated)section.append(el('p','Agrégation limitée aux 5 000 premiers paquets DNS/TCP décodés et aux 25 groupes d’étapes présentés. La comparaison est partielle.'));
   if(!comparison.stages.length)section.append(el('p','Aucune étape mesurée sur un même service candidat : comparaison non établie.'));list('Limites de comparaison',comparison.limitations,section);host.append(section);
  }
  const unknowns=el('details',undefined,'sd-unknowns');unknowns.append(el('summary','Contexte à confirmer et limites de capture'));list('',report.unknowns,unknowns);host.append(unknowns);
 }
 $('supportDiagnosisRun')?.addEventListener('click',run);
 $('supportDiagnosisPanel')?.addEventListener('toggle',()=>{if($('supportDiagnosisPanel').open){const task=app()?.currentTaskId;if(task!==state.task)reset(task);history();}});
 document.addEventListener('pcap:analysis-loaded',()=>{const task=app()?.currentTaskId;if(task!==state.task){reset(task);if($('supportDiagnosisPanel').open)history();}});
})();
