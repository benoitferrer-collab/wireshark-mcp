/* Open authenticated MCP evidence in the existing analysis/OSI interface. */
(function(root){
 'use strict';
 const tabs=new Set(['overview','dns','http','team-ai','team-ia','timeline','transactions','protocol-icmp','protocol-dhcp','protocol-ssh','protocol-smb','protocol-rdp','protocol-ntp','protocol-quic','protocol-tcp','protocol-udp','streams','multi','packets','tls-audit','threat-intel','flow-behavior','lateral-movement','qos','tcp-health','playbook']);
 function parseEvidenceLocation(href){
  try{
   const url=new URL(href,'https://pcap.invalid');
   const taskId=url.searchParams.get('task');
   if(!taskId || !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/.test(taskId)) return null;
   const fragment=new URLSearchParams(url.hash.slice(1));
   const raw=fragment.get('packet');
   const packetIndex=raw===null?null:Number(raw);
   if(raw!==null && (!/^\d+$/.test(raw)||!Number.isSafeInteger(packetIndex)||packetIndex>=250000))return null;
   const tab=fragment.get('tab')||(packetIndex===null?'overview':'packets');
   if(!tabs.has(tab))return null;
   return {taskId,tab,packetIndex};
  }catch(_){return null;}
 }
 async function openEvidence(controller,href){
  const target=parseEvidenceLocation(href);
  if(!target)return false;
  const loaded=await controller.loadHistoryItem(target.taskId);
  if(loaded===false)return false;
  controller.switchTab(target.tab);
  if(target.packetIndex!==null)controller.showPacketDetails(target.packetIndex);
  return true;
 }
 if(typeof module!=='undefined'&&module.exports)module.exports={parseEvidenceLocation,openEvidence};
 if(typeof window!=='undefined'){
  // Capture before app.js initializes tabs and normalizes the location fragment.
  const initialHref=window.location.href;
  const follow=(href)=>{
   if(typeof analyzer!=='undefined')openEvidence(analyzer,href).catch(()=>{
    analyzer.showToast('error','Preuve indisponible','Impossible de charger cette preuve ; vérifiez votre accès à la capture.');
   });
  };
  window.addEventListener('load',()=>follow(initialHref));
  window.addEventListener('popstate',()=>follow(window.location.href));
 }
})(typeof globalThis!=='undefined'?globalThis:this);
