"""
IR Playbook Generator — Feature 8
Génère des playbooks de réponse à incident personnalisés
basés sur les résultats d'analyse.
"""

from __future__ import annotations

from typing import Dict, Any, List
from datetime import datetime, timezone

try:
    from app.core.logging_config import get_logger
except ImportError:
    import logging
    def get_logger(name: str):  # type: ignore
        return logging.getLogger(name)

logger = get_logger(__name__)


# ─────────────────────────────────────────────────────────
# Playbook templates per incident type
# ─────────────────────────────────────────────────────────

PLAYBOOK_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "ransomware": {
        "name": "Playbook Ransomware",
        "icon": "🔒",
        "priority": "CRITIQUE",
        "description": "Réponse à une infection par ransomware détectée dans la capture réseau",
        "phases": [
            {
                "phase": "CONFINEMENT IMMÉDIAT",
                "icon": "🚨",
                "deadline_min": 15,
                "tasks": [
                    "Isoler immédiatement toutes les machines infectées du réseau (déconnecter les câbles Ethernet, désactiver le Wi-Fi)",
                    "Couper l'accès VPN et les tunnels réseau entrants/sortants",
                    "Identifier et isoler les partages réseau SMB/NFS accessibles depuis les machines infectées",
                    "Contacter le RSSI et l'équipe de direction — déclarer l'incident P1",
                    "NE PAS redémarrer les machines infectées (préserver les artefacts en mémoire)",
                    "Documenter l'heure exacte de détection et les machines concernées",
                ]
            },
            {
                "phase": "INVESTIGATION INITIALE",
                "icon": "🔍",
                "deadline_min": 60,
                "tasks": [
                    "Capturer la mémoire RAM des machines infectées (outils: WinPMEM, DumpIt, Volatility)",
                    "Identifier le variant ransomware (ID Ransomware, SHA256 du binaire)",
                    "Déterminer le Patient Zero — première machine infectée (logs d'accès, timeline des chiffrements)",
                    "Analyser les logs EventID 4624/4625 pour détecter des connexions RDP/SMB suspectes",
                    "Rechercher les IoCs réseau dans la capture PCAP (IPs C2, domaines de paiement Bitcoin)",
                    "Déterminer si des données ont été exfiltrées AVANT chiffrement (DLP, flux réseau sortants)",
                ]
            },
            {
                "phase": "ÉRADICATION",
                "icon": "🧹",
                "deadline_min": 240,
                "tasks": [
                    "Identifier tous les systèmes affectés (scan réseau, logs Active Directory)",
                    "Supprimer les mécanismes de persistance (clés Run, services, tâches planifiées)",
                    "Bloquer les IPs C2 et domaines identifiés sur tous les équipements périmètre",
                    "Analyser et nettoyer les partages réseau (détecter les fichiers chiffrés)",
                    "Réinitialiser tous les comptes compromis — Active Directory et locaux",
                    "Changer TOUS les mots de passe de service et mots de passe d'administration",
                ]
            },
            {
                "phase": "RÉCUPÉRATION",
                "icon": "♻️",
                "deadline_min": 480,
                "tasks": [
                    "Restaurer depuis les sauvegardes HORS-LIGNE validées (vérifier l'intégrité des backups d'abord)",
                    "Reconstruire les machines compromises depuis une image maîtresse connue bonne",
                    "Appliquer tous les patches de sécurité manquants AVANT reconnexion au réseau",
                    "Tester la restauration en environnement isolé avant reconnexion en production",
                    "Réintégrer progressivement les machines au réseau avec surveillance renforcée",
                ]
            },
            {
                "phase": "POST-INCIDENT & DURCISSEMENT",
                "icon": "🛡️",
                "deadline_min": None,
                "tasks": [
                    "Réaliser l'analyse post-mortem complète (how did they get in?)",
                    "Implémenter la segmentation réseau pour limiter la propagation SMB latérale",
                    "Déployer un EDR sur toutes les machines Windows",
                    "Activer et centraliser les journaux (SIEM): EventID 4624, 4625, 4688, 7045",
                    "Configurer des sauvegardes offline immuables avec test de restauration trimestriel",
                    "Former utilisateurs à la détection de phishing et maintenir la cyber-hygiène",
                    "Rédiger et soumettre le rapport d'incident réglementaire si applicable (RGPD: 72h)",
                ]
            }
        ],
        "mitre_techniques": [
            "T1566 - Phishing (Initial Access)",
            "T1486 - Data Encrypted for Impact",
            "T1490 - Inhibit System Recovery",
            "T1021.002 - SMB Lateral Movement",
            "T1078 - Valid Accounts",
        ]
    },

    "exfiltration": {
        "name": "Playbook Exfiltration de Données",
        "icon": "📤",
        "priority": "CRITIQUE",
        "description": "Réponse à une exfiltration de données détectée dans la capture réseau",
        "phases": [
            {
                "phase": "CONFINEMENT D'URGENCE",
                "icon": "🚨",
                "deadline_min": 30,
                "tasks": [
                    "Bloquer immédiatement les connexions sortantes vers les IPs suspects identifiés",
                    "Capturer un instantané du trafic réseau en temps réel (tcpdump si pas encore fait)",
                    "Identifier les sources de données exfiltrées (bases de données, partages fichiers, DLP)",
                    "Notifier le DPO si des données personnelles sont impliquées (pré-alerte RGPD)",
                    "Activer la journalisation détaillée sur tous les équipements clés",
                ]
            },
            {
                "phase": "QUANTIFICATION DE L'IMPACT",
                "icon": "📊",
                "deadline_min": 120,
                "tasks": [
                    "Calculer le volume exact exfiltré (octets, fichiers si DNS exfiltration ou HTTPS)",
                    "Identifier les données spécifiques volées: PII, secrets d'entreprise, credentials",
                    "Déterminer la durée de l'exfiltration (première/dernière timestamp suspects)",
                    "Analyser si l'exfiltration était compressée/chiffrée (HTTPS, DNS tunneling, ICMP)",
                    "Identifier l'infrastructure de réception (IP, hébergeur, pays destination)",
                ]
            },
            {
                "phase": "ÉRADICATION DE LA MENACE",
                "icon": "🧹",
                "deadline_min": 240,
                "tasks": [
                    "Identifier et supprimer le malware/backdoor utilisé pour l'exfiltration",
                    "Révoquer tous les tokens, clés API et credentials potentiellement compromis",
                    "Supprimer tous les accès non autorisés (comptes malveillants, SSH keys)",
                    "Analyser les logs d'accès DLP/DRM pour toute la période de compromission",
                    "Auditer les règles de firewall — identifier toute règle ajoutée malicieusement",
                ]
            },
            {
                "phase": "NOTIFICATION LÉGALE & RÉGLEMENTAIRE",
                "icon": "⚖️",
                "deadline_min": 4320,  # 72h
                "tasks": [
                    "Évaluer les obligations de notification (RGPD Article 33: 72h si données personnelles)",
                    "Notifier la CNIL si données personnelles >72h après découverte",
                    "Préparer la notification aux personnes affectées si risque élevé (RGPD Art. 34)",
                    "Déposer une plainte pénale si attaque externe (ANSSI, parquet cybercriminalité)",
                    "Prévenir les clients/partenaires si leurs données sont impliquées",
                    "Documenter toutes les actions pour la defense légale",
                ]
            }
        ],
        "mitre_techniques": [
            "T1048 - Exfiltration Over Alternative Protocol",
            "T1041 - Exfiltration Over C2 Channel",
            "T1071 - Application Layer Protocol",
            "T1567 - Exfiltration Over Web Service",
        ]
    },

    "lateral_movement": {
        "name": "Playbook Mouvement Latéral",
        "icon": "🔀",
        "priority": "HAUTE",
        "description": "Réponse à un mouvement latéral détecté dans le réseau interne",
        "phases": [
            {
                "phase": "CARTOGRAPHIE DE LA PROPAGATION",
                "icon": "🗺️",
                "deadline_min": 60,
                "tasks": [
                    "Identifier tous les systèmes atteints par l'attaquant (heat map des connexions)",
                    "Tracer le chemin exact de propagation (machine pivot → cibles)",
                    "Déterminer les techniques utilisées: PtH, PtT, RDP, SMB, WMI",
                    "Identifier les comptes AD utilisés pour le mouvement latéral",
                    "Chercher des backdoors installées sur chaque machine traversée",
                ]
            },
            {
                "phase": "CONFINEMENT CIBLÉ",
                "icon": "🚧",
                "deadline_min": 120,
                "tasks": [
                    "Isoler les machines compromises SANS perturber toute la production",
                    "Révoquer les Kerberos tickets des comptes compromis (klist purge, krbtgt reset si Golden Ticket)",
                    "Désactiver temporairement NTLM si Pass-the-Hash confirmé",
                    "Bloquer les connexions SMB entre machines non-nécessaires (micro-segmentation)",
                    "Changer les mots de passe KRBTGT si Kerberoasting/Golden Ticket suspecté (2 fois)",
                ]
            },
            {
                "phase": "REMÉDIATION ACTIVE DIRECTORY",
                "icon": "🗄️",
                "deadline_min": 240,
                "tasks": [
                    "Auditer tous les comptes DA (Domain Admin) — supprimer les comptes non autorisés",
                    "Activer Protected Users Security Group pour les comptes privilégiés",
                    "Implémenter LAPS (Local Administrator Password Solution)",
                    "Activer Credential Guard sur les serveurs critiques",
                    "Auditer les SPN enregistrés (Kerberoasting surface)",
                    "Vérifier les ACL des OUs sensibles (AdminSDHolder, GPO de sécurité)",
                    "Activer l'audit Kerberos dans les GPO (EventID 4768, 4769, 4771)",
                ]
            }
        ],
        "mitre_techniques": [
            "T1550.002 - Pass the Hash",
            "T1558.003 - Kerberoasting",
            "T1021.001 - Remote Desktop Protocol",
            "T1021.002 - SMB/Windows Admin Shares",
            "T1087.002 - Domain Account Discovery",
        ]
    },

    "c2_beaconing": {
        "name": "Playbook C2 Beaconing",
        "icon": "📡",
        "priority": "HAUTE",
        "description": "Réponse à une communication C2 détectée dans la capture réseau",
        "phases": [
            {
                "phase": "IDENTIFICATION DU C2",
                "icon": "🎯",
                "deadline_min": 30,
                "tasks": [
                    "Identifier la machine infectée (IP source du beaconing)",
                    "Documenter l'IP/domaine C2, le port, la fréquence et le protocole",
                    "Rechercher l'IP C2 sur Threat Intel (VirusTotal, AbuseIPDB, FeodoTracker)",
                    "Identifier le framework C2 probable: Cobalt Strike, Metasploit, Sliver (JA3 matching)",
                    "Déterminer depuis quand la backdoor est active (timestamp du premier beacon)",
                ]
            },
            {
                "phase": "INVESTIGATION FORENSIQUE",
                "icon": "🔬",
                "deadline_min": 120,
                "tasks": [
                    "Dumper la mémoire de la machine infectée AVANT isolation",
                    "Identifier le processus responsable du beaconing (netstat -anb, Process Monitor)",
                    "Analyser l'implant: hash, chemin, mécanisme de persistance (autorun, service, tâche planifiée)",
                    "Rechercher les fichiers déposés récemment (-30 jours) sur la machine",
                    "Analyser les PowerShell logs, WMI logs, Sysmon si disponible",
                ]
            },
            {
                "phase": "ÉRADICATION & DURCISSEMENT",
                "icon": "🛡️",
                "deadline_min": 180,
                "tasks": [
                    "Bloquer l'IP/domaine C2 au firewall périmètre et proxy",
                    "Supprimer l'implant et tous les mécanismes de persistance",
                    "Restaurer la machine depuis image propre",
                    "Configurer le proxy web avec whitelist d'URLs autorisées",
                    "Implémenter le filtrage DNS avec blocage des DGA et nouveaux domaines",
                    "Déployer des règles YARA/Sigma pour détecter les patterns C2 similaires",
                ]
            }
        ],
        "mitre_techniques": [
            "T1071 - Application Layer Protocol",
            "T1095 - Non-Application Layer Protocol",
            "T1132 - Data Encoding",
            "T1571 - Non-Standard Port",
        ]
    },

    "brute_force": {
        "name": "Playbook Brute Force / Password Spray",
        "icon": "🔨",
        "priority": "MOYENNE",
        "description": "Réponse à une attaque par force brute ou password spray détectée",
        "phases": [
            {
                "phase": "BLOCAGE D'URGENCE",
                "icon": "🚫",
                "deadline_min": 15,
                "tasks": [
                    "Bloquer l'IP attaquante au firewall (si externe)",
                    "Activer le rate limiting sur les services attaqués (SSH, RDP, LDAP, Exchange OWA)",
                    "Vérifier si un compte a été compromis (connexion réussie après les échecs)",
                    "Désactiver temporairement les comptes ciblés si compromise confirmée",
                ]
            },
            {
                "phase": "INVESTIGATION",
                "icon": "🔍",
                "deadline_min": 60,
                "tasks": [
                    "Identifier tous les comptes ciblés (EventID 4625 grouped by TargetUserName)",
                    "Vérifier si c'est un password spray (même password, plusieurs comptes) ou force brute (un compte, plusieurs passwords)",
                    "Analyser les User-Agents et fingerprints TLS pour identifier l'outil utilisé",
                    "Vérifier les IPs de source pour identifier proxy/Tor/bulletproof hosting",
                    "Déterminer si une authentification a réussi (EventID 4624 après 4625s)",
                ]
            },
            {
                "phase": "HARDENING",
                "icon": "🛡️",
                "deadline_min": 240,
                "tasks": [
                    "Activer l'authentification multi-facteurs (MFA) sur tous les accès externes",
                    "Implémenter le verrouillage de compte (5 tentatives → 30min lockout)",
                    "Activer Azure AD Smart Lockout / AD Fine-Grained Password Policy",
                    "Mettre en place fail2ban ou équivalent sur les services exposés",
                    "Restreindre l'accès RDP/SSH aux IPs autorisées uniquement (whitelist + VPN)",
                    "Réinitialiser les mots de passe des comptes ciblés avec politique forte (16+ chars)",
                ]
            }
        ],
        "mitre_techniques": [
            "T1110.001 - Brute Force: Password Guessing",
            "T1110.003 - Brute Force: Password Spraying",
            "T1078 - Valid Accounts",
        ]
    }
}


class IRPlaybookGenerator:
    """
    Génère des playbooks IR interactifs adaptés au type d'incident détecté.
    """

    def generate(
        self,
        analysis_results: Dict[str, Any],
        incident_types: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Génère un ou plusieurs playbooks basés sur les résultats d'analyse.

        Args:
            analysis_results: Résultats complets d'analyse PCAP
            incident_types: Forcer un ou plusieurs types. Si None, auto-détecte.
        """
        detected_types = incident_types or self._auto_detect_incident_type(analysis_results)

        playbooks = []
        for incident_type in detected_types:
            if incident_type in PLAYBOOK_TEMPLATES:
                playbook = self._generate_playbook(incident_type, analysis_results)
                playbooks.append(playbook)

        if not playbooks:
            # Playbook générique si aucun type détecté
            playbooks.append(self._generate_generic_playbook(analysis_results))

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "incident_types_detected": detected_types,
            "total_playbooks": len(playbooks),
            "playbooks": playbooks,
        }

    def _auto_detect_incident_type(self, results: Dict[str, Any]) -> List[str]:
        """Détecte automatiquement le type d'incident à partir des résultats"""
        detected = []

        # Beaconing C2
        flow_behavior = results.get("flow_behavior", {})
        if flow_behavior.get("summary", {}).get("beaconing_alerts", 0) > 0:
            detected.append("c2_beaconing")

        # Exfiltration
        if flow_behavior.get("summary", {}).get("exfiltration_alerts", 0) > 0:
            detected.append("exfiltration")

        # Lateral movement
        lateral = results.get("lateral_movement", {})
        if lateral.get("summary", {}).get("total_indicators", 0) > 0:
            detected.append("lateral_movement")

        # Brute force (from anomaly detection)
        anomalies = results.get("anomalies", [])
        for a in anomalies:
            if "brute" in str(a.get("type", "")).lower() or "force" in str(a.get("description", "")).lower():
                detected.append("brute_force")
                break

        # Ransomware indicators (SMB + large file writes over network)
        smb = results.get("smb_analysis", {})
        if smb.get("file_operations"):
            write_ops = [op for op in smb["file_operations"] if op.get("type") == "WRITE"]
            if len(write_ops) > 100:  # Massif de writes = chiffrement possible
                detected.append("ransomware")

        return list(set(detected)) or ["c2_beaconing"]  # Default fallback

    def _generate_playbook(self, incident_type: str, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un playbook personnalisé pour un type d'incident"""
        template = PLAYBOOK_TEMPLATES[incident_type]

        # Personnaliser avec les indicateurs réels
        context_iocs: List[str] = []

        if incident_type == "c2_beaconing":
            beacons = results.get("flow_behavior", {}).get("beaconing_alerts", [])
            for b in beacons[:5]:
                context_iocs.append(f"C2 probable: {b.get('dst_ip')}:{b.get('dst_port')} (score beacon: {b.get('beacon_score')})")

        elif incident_type == "exfiltration":
            exfils = results.get("flow_behavior", {}).get("exfiltration_alerts", [])
            for e in exfils[:5]:
                mb = e.get("estimated_exfil_mb", 0)
                context_iocs.append(f"Exfiltration: {e.get('src_ip')} → {e.get('dst_ip')} (~{mb}MB)")

        elif incident_type == "lateral_movement":
            pivots = results.get("lateral_movement", {}).get("pivot_hosts", [])
            for p in pivots[:5]:
                context_iocs.append(f"Pivot: {p.get('src_ip')} → {len(p.get('targets', []))} machines via {p.get('protocol')}")

        # Calcul du score de priorité
        playbook = dict(template)
        playbook["context_iocs"] = context_iocs
        playbook["total_tasks"] = sum(
            len(phase["tasks"]) for phase in template["phases"]
        )
        playbook["completed_tasks"] = 0  # Sera géré côté frontend via localStorage
        playbook["incident_type"] = incident_type
        playbook["playbook_id"] = f"{incident_type}_{int(__import__('time').time())}"

        return playbook

    def _generate_generic_playbook(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Playbook IR générique si aucun type spécifique détecté"""
        return {
            "name": "Playbook IR Générique",
            "icon": "🔒",
            "priority": "STANDARD",
            "incident_type": "generic",
            "description": "Procédure de réponse à incident standard",
            "total_tasks": 10,
            "completed_tasks": 0,
            "context_iocs": [],
            "phases": [
                {
                    "phase": "DÉTECTION & ANALYSE",
                    "icon": "🔍",
                    "deadline_min": 60,
                    "tasks": [
                        "Confirmer l'incident — distinguer vrai positif d'un faux positif",
                        "Identifier le périmètre affecté (machines, services, données)",
                        "Collecter les preuves initiales (logs, captures réseau, screenshots)",
                        "Notifier l'équipe de réponse à incident et le management",
                    ]
                },
                {
                    "phase": "CONFINEMENT",
                    "icon": "🚨",
                    "deadline_min": 120,
                    "tasks": [
                        "Contenir l'incident pour éviter la propagation",
                        "Préserver les preuves forensiques (dump mémoire, snapshot disque)",
                        "Mettre en place un monitoring renforcé",
                    ]
                },
                {
                    "phase": "ÉRADICATION & RÉCUPÉRATION",
                    "icon": "♻️",
                    "deadline_min": 480,
                    "tasks": [
                        "Supprimer la cause racine de l'incident",
                        "Restaurer les systèmes depuis des sauvegardes validées",
                        "Valider la remédiation avec l'équipe sécurité",
                        "Rédiger le rapport post-incident",
                    ]
                }
            ],
            "mitre_techniques": [],
            "playbook_id": f"generic_{int(__import__('time').time())}",
        }
