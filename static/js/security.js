/* Product security explainer. Simulations never call tools or change access policy. */
(function(){
 'use strict';
 const normalize=value=>String(value||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase();
 function filterTools(tools,query,category){
  const words=normalize(query).trim().split(/\s+/).filter(Boolean);
  return tools.filter(tool=>(category==='all'||tool.category===category)&&words.every(word=>normalize([tool.name,tool.title,tool.description].join(' ')).includes(word)));
 }
 function simulate(scenario,names){
  const steps=[['Identité Microsoft','passed'],['Autorisation & pcap:read','passed'],['Outil dans le catalogue PCAP','passed'],['Lecture de preuves bornée','passed']];
  const result={verdict:'allowed',title:'Une demande dans le bon périmètre.',description:'L’identité et la permission sont valides ; l’outil appartient au catalogue d’analyse.',request:'search_packets({ task_id: "capture-demo" })',steps,
   caveat:'Simulation uniquement. Un véritable appel vérifie aussi le fichier disponible, les paramètres et les limites du moteur.'};
  if(scenario==='pcap'&&!names.includes('search_packets'))return {...result,verdict:'conditional',title:'Catalogue non disponible.',description:'Impossible d’illustrer une autorisation sans le catalogue de cette version.',steps:[['Catalogue de la version','pending']]};
  const failures={
   expired:{index:0,title:'Le jeton a expiré.',description:'La vérification de la date d’expiration refuse le jeton avant l’exécution d’un outil.',request:'Authorization: Bearer [jeton expiré]'},
   tenant:{index:0,title:'L’identité vient d’un autre tenant.',description:'Le tenant et l’émetteur attendus ne correspondent pas ; le jeton est refusé.',request:'Authorization: Bearer [autre tenant]'},
   scope:{index:1,title:'La permission déléguée est absente.',description:'Un jeton Microsoft valide sans pcap:read ne permet pas l’exécution d’un outil MCP.',request:'Jeton valide · scp: [sans pcap:read]'},
   subject:{index:1,title:'L’utilisateur n’est pas autorisé sur le MCP.',description:'L’identité ne figure pas dans la liste MCP. L’appartenance au groupe Web ne remplace pas cette autorisation.',request:'Jeton valide · oid: [hors liste autorisée]'},
   'unknown-tool':{index:2,title:'Cet outil n’existe pas dans le périmètre.',description:'run_shell est absent du catalogue. Le serveur refuse l’appel ; aucune commande système n’est lancée.',request:'tools/call({ name: "run_shell" })'},
  };
  if(failures[scenario]){
   const f=failures[scenario];
   return {...result,verdict:'blocked',title:f.title,description:f.description,request:f.request,
    steps:steps.map((s,i)=>[s[0],i===f.index?'blocked':i>f.index?'pending':'passed']),
    caveat:'La démonstration modélise ce refus. Elle n’envoie aucun jeton et ne réalise aucun essai sur le serveur.'};
  }
  if(scenario==='general-chat')return {...result,verdict:'outside',title:'Cette conversation ne passe pas par le MCP.',
   description:'Le modèle peut répondre à une question générale sans appeler Nomios. Le catalogue d’outils n’est pas un filtre de toutes les conversations.',
   request:'Question générale → réponse du modèle, sans outil',steps:[['Aucun appel d’outil PCAP','pending'],['Conversation gérée par le client LLM','pending']],
   caveat:'Le MCP ne peut pas promettre de bloquer une conversation qu’il ne reçoit pas.'};
  if(scenario==='injection')return {...result,verdict:'conditional',title:'La décision dépend du garde-fou externe.',
   description:'Un contenu capturé peut contenir une instruction malveillante. post_mcp_call peut l’inspecter si un garde-fou compatible est activé dans LiteLLM.',
   request:'Preuve PCAP → [instruction non fiable] → post_mcp_call',
   steps:[['Identité et outil autorisés','passed'],['Résultat traité comme une donnée non fiable','passed'],['Garde-fou LiteLLM compatible et actif ?','pending']],
   caveat:'Le masquage ou le blocage dépend de la politique et de sa détection. Cette page ne vérifie pas LiteLLM et ne garantit pas la détection.'};
  if(scenario==='direct')return {...result,verdict:'conditional',title:'Azure AD reste actif. Le proxy est contourné.',
   description:'Un client qui possède un jeton utilisateur accepté peut appeler directement le MCP. Les garde-fous LiteLLM ne s’appliquent pas à ce trajet.',
   request:'Client → MCP Nomios, sans passerelle LiteLLM',steps:[['Contrôles OAuth du MCP','passed'],['Catalogue et paramètres serveur','passed'],['Garde-fous du proxy non traversés','pending']],
   caveat:'Rendre le proxy obligatoire exige un contrôle d’accès supplémentaire à l’amont. Cette page ne l’active pas.'};
  if(scenario!=='pcap')return {...result,verdict:'conditional',title:'Scénario non reconnu.',description:'Aucune autorisation ne peut être illustrée pour un scénario inconnu.',steps:[['Scénario non reconnu','pending']],caveat:'Choisissez un scénario disponible ; aucune requête réelle n’a été émise.'};
  return result;
 }
 if(typeof module!=='undefined'&&module.exports)module.exports={simulate,filterTools};
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id);
 let tools=[];
 const create=(tag,text,cls)=>{const node=document.createElement(tag);if(text!==undefined)node.textContent=text;if(cls)node.className=cls;return node;};
 const architecture={
  client:['CLIENT IA','Le modèle formule. Le moteur mesure.','Le client choisit les outils et interprète leurs résultats. Les volumes, horaires et références proviennent du moteur d’analyse. Le MCP ne maîtrise pas toute la conversation ni la réponse finale du modèle.','Frontière : les données capturées sont des preuves, jamais des instructions de confiance.'],
  gateway:['PASSERELLE EXTERNE','Des garde-fous sur le trajet du proxy.','LiteLLM peut vérifier les arguments et les résultats des outils. Ces contrôles doivent être activés dans une version et un fournisseur compatibles. Leur état n’est pas interrogé par cette page.','Limite : l’authentification au proxy ne prouve pas qu’un garde-fou a effectivement été exécuté.'],
  mcp:['IDENTITÉ + CATALOGUE','Une autorisation avant chaque outil.','Le MCP vérifie le jeton délégué, le tenant, l’identité autorisée et pcap:read. Seuls les noms d’outils enregistrés sont exécutables ; les paramètres sont validés avant d’atteindre les preuves.','Limite : la liste d’identités MCP et le groupe d’accès Web sont des règles distinctes.'],
  engine:['ANALYSE HORS LIGNE','Des observations, avec leur couverture.','Le moteur consulte les captures stockées et produit des métadonnées et des références. TShark s’exécute sans shell, avec une sélection fixe de champs et un budget de traitement. Les diagnostics restent des indices à interpréter.','Limite : une analyse partielle ou une capture incomplète ne permet pas de conclure à l’absence d’activité.'],
 };
 document.querySelectorAll('[data-node]').forEach(button=>button.addEventListener('click',()=>{
  const data=architecture[button.dataset.node];if(!data)return;
  document.querySelectorAll('[data-node]').forEach(peer=>peer.setAttribute('aria-pressed',String(peer===button)));
  ['nodeTag','nodeTitle','nodeDescription','nodeBoundary'].forEach((id,i)=>$(id).textContent=data[i]);
 }));
 function renderSimulation(){
  const result=simulate($('scenarioSelect').value,tools.map(t=>t.name));
  const labels={allowed:'AUTORISÉ DANS LE MODÈLE',blocked:'REFUSÉ DANS LE MODÈLE',outside:'HORS PÉRIMÈTRE MCP',conditional:'CONTRÔLE CONDITIONNEL'};
  $('verdictLabel').textContent=labels[result.verdict];$('verdictLabel').className='verdict '+result.verdict;
  $('verdictTitle').textContent=result.title;$('verdictDescription').textContent=result.description;
  $('simRequest').textContent=result.request;$('simCaveat').textContent=result.caveat;
  $('simSteps').replaceChildren(...result.steps.map(([label,state])=>{const li=create('li',undefined,state);li.append(create('span',state==='passed'?'✓':state==='blocked'?'×':'—'),create('span',label));return li;}));
 }
 function renderTools(){
  const selected=filterTools(tools,$('toolSearch').value,$('toolCategory').value);
  $('catalogueCount').textContent=selected.length+' / '+tools.length+' outils';
  const children=selected.map(tool=>{const article=create('article',undefined,'tool-entry');article.append(create('code',tool.name),create('span',tool.category,'tag'),create('h3',tool.title),create('p',tool.description));return article;});
  $('toolCatalogue').replaceChildren(...(children.length?children:[create('p',tools.length?'Aucun outil ne correspond à cette recherche.':'Catalogue indisponible. Connectez-vous et actualisez la page.','empty-catalogue')]));
 }
 async function loadOverview(){
  const button=$('refreshStatus');button.disabled=true;$('statusError').hidden=true;
  try{
   const response=await fetch('/api/security/overview',{credentials:'same-origin',cache:'no-store'});
   if(!response.ok)throw new Error(response.status===401||response.status===403?'Connexion requise : ouvrez l’application avec votre compte autorisé, puis actualisez cette page.':'La lecture de configuration est indisponible. Aucun état de protection ne peut être confirmé.');
   const state=await response.json();
   tools=state.tools;
   $('toolCount').textContent=tools.length;
   $('webState').textContent=state.web.state==='enabled'?'Entra Web configuré':'Mode local / Entra désactivé';
   $('webNote').textContent=state.web.state==='enabled'?'Propriétaire ou groupe configuré ; session serveur.':'Ce déploiement n’active pas la connexion Web Entra.';
   $('mcpState').textContent=state.mcp.state==='configuration_detected'?'Paramètres Entra détectés':'Configuration non détectée ici';
   $('mcpNote').textContent=state.mcp.state==='configuration_detected'?'Signal de configuration, pas un test OAuth réussi.':'Le service MCP est distinct ; vérifiez son déploiement.';
   $('limitPackets').textContent=new Intl.NumberFormat('fr-FR').format(state.limits.input_packets);
   $('limitTime').textContent=state.limits.scan_seconds+' s';
   $('observedAt').textContent='Lecture à '+new Date(state.generated_at).toLocaleTimeString('fr-FR',{hour:'2-digit',minute:'2-digit'})+' · sans audit';
   renderTools();renderSimulation();
  }catch(error){
   tools=[];$('toolCount').textContent='—';$('webState').textContent='État indisponible';$('mcpState').textContent='État indisponible';
   $('observedAt').textContent='Configuration non vérifiée';$('statusError').textContent=error.message;$('statusError').hidden=false;
   $('webNote').textContent='Une configuration non lue ne permet pas de confirmer la protection.';
   $('mcpNote').textContent='Aucun test OAuth n’a été réalisé.';renderTools();renderSimulation();
  }finally{button.disabled=false;}
 }
 $('scenarioSelect').addEventListener('change',renderSimulation);
 $('toolSearch').addEventListener('input',renderTools);$('toolCategory').addEventListener('change',renderTools);
 $('refreshStatus').addEventListener('click',loadOverview);$('printPage').addEventListener('click',()=>window.print());
 loadOverview();
})();
