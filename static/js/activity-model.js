(function(){
 'use strict';
 const providers={claude:{name:'Claude',vendor:'Anthropic',logo:'claude.svg'},chatgpt:{name:'ChatGPT',vendor:'OpenAI',logo:'chatgpt.svg'},litellm:{name:'LiteLLM',vendor:'Passerelle MCP',logo:'litellm.svg'},generic:{name:'Client MCP',vendor:'Client autorisé',logo:null}};
 function brand(id,registry={}){const item=registry[String(id).toLowerCase()];const base=providers[item?.provider]||providers.generic;return {...base,name:item?.name||base.name,provider:providers[item?.provider]?item.provider:'generic'};}
 function freshEvents(recent,previous){return recent.filter(e=>e.event_id&&!previous.has(e.event_id));}
 function shareLink(origin,task,tab){if(!/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(task||''))throw new Error('Ouvrez une capture.');const tabs=new Set(['overview','streams','packets','dns','http','timeline','transactions','tcp-health','qos','tls-audit','threat-intel','flow-behavior','lateral-movement','playbook','team-ia']);const url=new URL('/',origin);url.searchParams.set('task',task);const view=tabs.has(tab)?tab:'overview';url.searchParams.set('view',view);url.hash='tab='+view;return url.href;}
 const exports={brand,freshEvents,shareLink};if(typeof module!=='undefined'&&module.exports)module.exports=exports;if(typeof window!=='undefined')window.PcapActivity=exports;
})();
