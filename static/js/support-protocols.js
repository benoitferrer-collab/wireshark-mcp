/* Bounded protocol metadata, with independent TCP stream health. */
(function(){
 'use strict';
 const titles={icmp:'ICMP / ICMPv6',dhcp:'DHCP / DHCPv6',ssh:'SSH',smb:'SMB / SMB2',rdp:'RDP',ntp:'NTP',quic:'QUIC',tcp:'TCP',udp:'UDP'};
 const safeTask=task=>/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(String(task||''));
 const evidence=(task,frame)=>safeTask(task)&&Number.isSafeInteger(frame)&&frame>0&&frame<=250000?'/?task='+encodeURIComponent(task)+'#tab=packets&packet='+(frame-1):null;
 const metric=(value,unit='')=>Number.isFinite(value)?value.toLocaleString('fr-FR',{maximumFractionDigits:3})+unit:'Non mesuré';
 const exported={titles,evidence,metric};
 if(typeof module!=='undefined'&&module.exports)module.exports=exported;
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id),el=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const app=()=>typeof analyzer==='undefined'?null:analyzer;
 const button=(text,fn)=>{const n=el('button',text,'btn btn-secondary');n.type='button';n.addEventListener('click',fn);return n;};
 const address=(ip,port)=>String(ip||'—')+(port===null||port===undefined?'':':'+port);
 const flags=row=>[['tcp_syn','SYN'],['tcp_ack','ACK'],['tcp_fin','FIN'],['tcp_reset','RST'],['retransmission','Retransmission'],['zero_window','Zero Window'],['duplicate_ack','ACK dupliqué'],['out_of_order','Hors ordre'],['lost_segment','Segment précédent non observé']].filter(([key])=>row[key]).map(([,name])=>name).join(' · ');
 let state=null,healthMode=false;
 function invalidate(){if(state){state.controller?.abort();state.request++;}state=null;}
 function table(headers,rows){const wrap=el('div',undefined,'sp-table'),t=el('table'),head=el('thead'),tr=el('tr');headers.forEach(h=>tr.append(el('th',h)));head.append(tr);t.append(head);const body=el('tbody');for(const cells of rows){const row=el('tr');for(const value of cells){const td=el('td');td.append(value instanceof Node?value:document.createTextNode(String(value??'—')));row.append(td);}body.append(row);}t.append(body);wrap.append(t);return wrap;}
 function packetLink(task,frame){const url=evidence(task,frame);if(!url)return el('span','—');const a=el('a','#'+frame+' ↗');a.href=url;a.target='_blank';a.rel='noopener';a.setAttribute('aria-label','Ouvrir le paquet '+frame);return a;}
 function init(host,task,protocol,health){invalidate();state={host,task,protocol,health,stream:null,cursor:0,sessionOffset:0,request:0,controller:null};read();}
 async function read(){
  const s=state;if(!s)return;s.controller?.abort();s.controller=new AbortController();const request=++s.request;s.host.replaceChildren(el('p','Lecture du PCAP original par Wireshark…','sp-status'));s.host.setAttribute('aria-busy','true');
  const query=new URLSearchParams({after_frame:s.cursor,session_offset:s.sessionOffset,limit:25});if(s.stream!==null)query.set('stream',s.stream);
  const controller=s.controller;const timeout=setTimeout(()=>controller.abort(),26000);
  try{const response=await fetch('/api/analysis/'+encodeURIComponent(s.task)+'/protocols/'+s.protocol+'?'+query,{cache:'no-store',signal:s.controller.signal});if(!response.ok)throw Error(response.status===404?'Le PCAP original n’est plus disponible.':response.status===503?'Le moteur est occupé ou cette capture est illisible. Réessayez.':'Lecture indisponible ('+response.status+').');const data=await response.json();if(state!==s||request!==s.request)return;draw(s,data);}
  catch(error){if(state!==s||request!==s.request)return;s.host.replaceChildren(el('p',error.name==='AbortError'?'Lecture interrompue ou délai dépassé. Réessayez.':error.message,'sp-status'),button('Réessayer',read));}
  finally{clearTimeout(timeout);if(state===s&&request===s.request)s.host.setAttribute('aria-busy','false');}
 }
 function draw(s,data){
  const host=s.host;host.replaceChildren();const heading=el('div',undefined,'sp-heading'),copy=el('div');copy.append(el('p',s.health?'SANTÉ TCP · PAR SESSION':'EXPLORATION PROTOCOLAIRE','support-eyebrow'),el('h2',s.health?(s.stream===null?'Isoler la session qui ralentit.':'Session Wireshark #'+s.stream):titles[s.protocol]),el('p',s.health?'RTT, resets et signaux TCP, avec retour aux paquets.':'Métadonnées décodées par Wireshark · aucun contenu applicatif restitué.'));heading.append(copy,button('Actualiser',read));host.append(heading);
  const controls=el('div',undefined,'sp-controls');if(s.protocol==='tcp'){const label=el('label','Session Wireshark (tcp.stream)'),input=el('input');input.type='number';input.min='0';input.max='2147483647';input.step='1';input.placeholder='Toutes les sessions';input.id='spHealthStream';input.setAttribute('aria-label','Session Wireshark (tcp.stream)');input.value=s.stream??'';label.htmlFor=input.id;const apply=()=>{const value=input.value.trim(),number=Number(value);if(value!==''&&(!Number.isSafeInteger(number)||number<0||number>2147483647)){input.setCustomValidity('Entrez un identifiant de session entier positif ou zéro.');input.reportValidity();return;}input.setCustomValidity('');s.stream=value===''?null:number;s.cursor=0;s.sessionOffset=0;read();};controls.append(label,input,button('Examiner',apply),button('Toutes les sessions',()=>{s.stream=null;s.cursor=0;s.sessionOffset=0;read();}));input.addEventListener('keydown',e=>{if(e.key==='Enter')apply();});}
  controls.append(el('code',data.display_filter));host.append(controls);
  const coverage=el('p',(data.coverage.complete?'Inspection complète dans les limites du moteur.':'Inspection partielle · '+(data.coverage.reason||'limite atteinte')+'.')+' '+data.observed_packets+' paquets observés · '+data.observed_sessions+' session(s) TCP.','sp-status');coverage.setAttribute('role','status');host.append(coverage);
  const cards=el('div',undefined,'sp-metrics'),m=data.summary;const entries=[['Paquets observés',m.packets],['Volume observé',metric(m.bytes,' octets')]];
  if(s.protocol==='tcp'||s.health)entries.push(['RTT moyen ACK',metric(m.rtt_avg_ms,' ms')],['Échantillons RTT',m.rtt_samples],['Retransmissions',m.retransmissions],['Resets',m.resets],['Zero Window',m.zero_windows],['ACK dupliqués',m.duplicate_acks],['RTT ACK min.',metric(m.rtt_min_ms,' ms')],['RTT ACK max.',metric(m.rtt_max_ms,' ms')],['Fenêtre brute moy.',metric(m.window_raw_avg,' octets')],['Durée observée',metric(m.duration_seconds,' s')],['Hors ordre',m.out_of_order],['Segments précédents non observés',m.previous_segment_missing]);
  if(s.protocol==='tcp')host.append(el('p','RTT ACK : délai segment → acquittement corrélé par Wireshark, différent du RTT de handshake de la vue globale historique. Fenêtre brute annoncée, sans facteur d’échelle. Retransmission et segment non observé ne prouvent pas une perte réseau.','sp-status'));
  for(const [label,value] of entries){const card=el('article');card.append(el('span',label),el('strong',String(value)));cards.append(card);}host.append(cards);
  if(s.protocol==='tcp'||s.health){host.append(el('h3',s.stream===null?'Sessions TCP observées':'Métriques de cette session'));
   if(!data.sessions.length)host.append(el('p','Aucune session TCP observée dans le périmètre inspecté.'));
   else host.append(table(['Session','Extrémités A ↔ B','Paquets','RTT ACK moy.','Retrans.','RST','Zero Window','Preuve'],data.sessions.map(row=>{const choose=button('#'+row.stream_id,()=>{s.stream=row.stream_id;s.cursor=0;s.sessionOffset=0;read();});return [choose,address(row.endpoint_a.ip,row.endpoint_a.port)+' ↔ '+address(row.endpoint_b.ip,row.endpoint_b.port),row.packets,metric(row.rtt_avg_ms,' ms'),row.retransmissions,row.resets,row.zero_windows,packetLink(s.task,row.first_frame)];})));
   const pages=el('div',undefined,'sp-controls');if(s.sessionOffset)pages.append(button('← Sessions précédentes',()=>{s.sessionOffset=Math.max(0,s.sessionOffset-50);read();}));if(data.next_session_offset!==null)pages.append(button('Sessions suivantes →',()=>{s.sessionOffset=data.next_session_offset;read();}));host.append(pages);
  }
  host.append(el('h3','Paquets et preuves'));
  if(!data.data.length)host.append(el('p','Aucun paquet décodé pour cette sélection. Un protocole chiffré, un port inhabituel ou une capture partielle peut limiter sa visibilité.','sp-status'));
  else host.append(table(['Paquet','Source → Destination','Décodage','Détails observés'],data.data.map(row=>[packetLink(s.task,row.frame_number),address(row.src_ip,row.src_port)+' → '+address(row.dst_ip,row.dst_port),row.protocols,[flags(row),...Object.entries(row.protocol_details||{}).map(([key,value])=>key+' = '+value)].filter(Boolean).join(' · ')||'Métadonnées de transport uniquement'])));
  const pages=el('div',undefined,'sp-controls');if(s.cursor)pages.append(button('Revenir au début',()=>{s.cursor=0;read();}));if(data.next_after_frame!==null)pages.append(button('Paquets suivants →',()=>{s.cursor=data.next_after_frame;read();}));host.append(pages);
  const notes=el('details',undefined,'sp-notes');notes.append(el('summary','Périmètre et limites des mesures'));const ul=el('ul');for(const note of data.limitations)ul.append(el('li',note));notes.append(ul);host.append(notes);
 }
 function load(tab,task){const protocol=tab.replace('protocol-','');if(!titles[protocol]||!safeTask(task))return;if(state?.task===task&&state.protocol===protocol&&!state.health)return;const host=$('protocolExplorerHost');$('tab-'+tab)?.append(host);host.hidden=false;init(host,task,protocol,false);}
 function health(task){if(state?.task===task&&state.health)return;if(healthMode&&safeTask(task))init($('sessionHealthContent'),task,'tcp',true);}
 function setHealthMode(selected){healthMode=selected;$('tcp-health-content').hidden=selected;$('sessionHealthContent').hidden=!selected;document.querySelectorAll('[data-health-mode]').forEach(b=>b.setAttribute('aria-pressed',String((b.dataset.healthMode==='sessions')===selected)));if(selected)health(app()?.currentTaskId);else if(state?.health)invalidate();}
 document.querySelectorAll('[data-health-mode]').forEach(b=>b.addEventListener('click',()=>setHealthMode(b.dataset.healthMode==='sessions')));
 document.addEventListener('pcap:analysis-loaded',()=>{if(state?.task===app()?.currentTaskId)return;invalidate();$('protocolExplorerHost')?.replaceChildren();$('sessionHealthContent')?.replaceChildren();const current=app();if(current?.currentTabId?.startsWith('protocol-'))load(current.currentTabId,current.currentTaskId);else if(current?.currentTabId==='tcp-health')health(current.currentTaskId);});
 window.PcapSupportProtocols={load,health};
})();
