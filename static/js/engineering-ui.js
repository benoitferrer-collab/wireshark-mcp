/* Navigation presentation only; existing modules and their handlers own the data. */
(function(){
 'use strict';
 const normalize=s=>String(s||'').normalize('NFD').replace(/[\u0300-\u036f]/g,'').toLowerCase().trim();
 function filterCommands(commands,query){const words=normalize(query).split(/\s+/).filter(Boolean);return commands.filter(c=>words.every(w=>normalize(c.title+' '+c.detail).includes(w)));}
 if(typeof module!=='undefined'&&module.exports)module.exports={filterCommands};
 if(typeof document==='undefined')return;
 const $=id=>document.getElementById(id);
 const create=(tag,text,cls)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;if(cls)n.className=cls;return n;};
 const dialog=$('engineeringCommand'),input=$('engineeringCommandInput'),list=$('engineeringCommandList');
 if(!dialog||!input||!list)return;
 let options=[],selected=0,previousFocus=null;
 const labels={'overview':'Synthèse de la capture','packets':'Paquets et couches OSI','streams':'Sessions TCP et échanges','timeline':'Chronologie de la capture','dns':'Protocoles et résolution','http':'HTTP, HTTPS et déchiffrement TLS','tls-audit':'Versions TLS et certificats','tcp-health':'Retransmissions et qualité TCP','qos':'Qualité de service','threat-intel':'Indicateurs de menace','flow-behavior':'Comportement des flux','lateral-movement':'Mouvements latéraux','multi-pcap':'Corrélation entre captures','team-ia':'Analyses des assistants','playbook':'Aide à l’investigation'};
 function commands(){
  const items=[{title:'Importer une capture',detail:'Ajouter un PCAP ou PCAPNG',icon:'+',run:()=>document.querySelector('[data-nomios-view="captures"]')?.click()}];
  document.querySelectorAll('.nomios-module-nav .tab').forEach(button=>items.push({title:button.textContent.trim().replace(/\s+/g,' '),detail:labels[button.dataset.tab]||'Ouvrir ce module',icon:'↗',run:()=>{button.closest('details')?.setAttribute('open','');button.click();}}));
  for(const [id,title,detail] of [['assistants','Assistants IA','Activité des outils MCP'],['admin','Administration','Groupe Microsoft Entra ID']]){const button=document.querySelector(`[data-nomios-view="${id}"]`);if(button&&!button.hidden)items.push({title,detail,icon:'↗',run:()=>button.click()});}
  return items;
 }
 function highlight(){list.querySelectorAll('[role=option]').forEach((button,i)=>{button.setAttribute('aria-selected',String(i===selected));if(i===selected){input.setAttribute('aria-activedescendant',button.id);button.scrollIntoView({block:'nearest'});}});}
 function render(){options=filterCommands(commands(),input.value);selected=0;list.replaceChildren();input.removeAttribute('aria-activedescendant');if(!options.length){list.append(create('p','Aucune vue ne correspond à cette recherche.','engineering-command-empty'));return;}options.forEach((item,i)=>{const button=create('button',undefined,'engineering-command-option');button.type='button';button.id='engineering-option-'+i;button.setAttribute('role','option');button.setAttribute('aria-selected',String(i===0));const copy=create('div');copy.append(create('strong',item.title),create('small',item.detail));button.append(create('span',item.icon),copy,create('span','↵','command-enter'));button.addEventListener('click',()=>activate(i));list.append(button);});highlight();}
 function open(){previousFocus=document.activeElement;input.value='';render();if(!dialog.open)dialog.showModal();input.focus();}
 function close(){dialog.close();previousFocus?.focus?.();}
 function activate(index){const item=options[index];if(!item)return;close();item.run();closeNav();}
 $('engineeringCommandButton')?.addEventListener('click',open);
 input.addEventListener('input',render);
 input.addEventListener('keydown',e=>{if(e.key==='ArrowDown'||e.key==='ArrowUp'){e.preventDefault();if(!options.length)return;selected=(selected+(e.key==='ArrowDown'?1:-1)+options.length)%options.length;highlight();}if(e.key==='Enter'){e.preventDefault();activate(selected);}});
 dialog.addEventListener('click',e=>{if(e.target===dialog)close();});dialog.addEventListener('close',()=>previousFocus?.focus?.());
 document.addEventListener('keydown',e=>{if((e.metaKey||e.ctrlKey)&&e.key.toLowerCase()==='k'){e.preventDefault();dialog.open?close():open();}if(e.key==='Escape')closeNav();});
 $('engineeringImportButton')?.addEventListener('click',()=>{document.querySelector('[data-nomios-view="captures"]')?.click();closeNav();});
 const rail=document.querySelector('.nomios-sidebar'),menu=$('engineeringMenu'),backdrop=$('engineeringNavBackdrop');
 const mobile=window.matchMedia('(max-width:760px)');
 function syncRail(){if(rail)rail.inert=mobile.matches&&!rail.classList.contains('cockpit-nav-open');}
 mobile.addEventListener('change',()=>{closeNav();syncRail();});syncRail();
 function closeNav(){const restore=mobile.matches&&rail?.contains(document.activeElement);rail?.classList.remove('cockpit-nav-open');menu?.setAttribute('aria-expanded','false');menu?.setAttribute('aria-label','Ouvrir la navigation');if(backdrop)backdrop.hidden=true;syncRail();if(restore)menu?.focus();}
 menu?.addEventListener('click',()=>{const expanded=rail.classList.toggle('cockpit-nav-open');menu.setAttribute('aria-expanded',String(expanded));menu.setAttribute('aria-label',expanded?'Fermer la navigation':'Ouvrir la navigation');backdrop.hidden=!expanded;syncRail();if(expanded)rail.querySelector('button')?.focus();});backdrop?.addEventListener('click',closeNav);
 rail?.addEventListener('click',e=>{if(e.target.closest('button.tab,button[data-nomios-view]'))closeNav();});
 const theme=$('themeToggle');
 function themeLabel(){theme?.setAttribute('aria-label',document.documentElement.dataset.theme==='dark'?'Passer au thème clair':'Passer au thème sombre');}
 new MutationObserver(themeLabel).observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});themeLabel();
})();
