"""
Service d'analyse IA avec Ollama
Analyse intelligente des captures PCAP
"""

import requests
import json
import re
from typing import Dict, List, Any, Optional
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


class OllamaAnalysisService:
    """Service d'analyse IA utilisant Ollama en local"""
    
    def __init__(self):
        self.config_file = Path(
            os.getenv("OLLAMA_RUNTIME_CONFIG_PATH", "/tmp/pcap_analyzer_ollama_runtime.json")
        )
        self.base_url = self._normalize_base_url(
            os.getenv("OLLAMA_BASE_URL", "http://host.docker.internal:11434")
        )
        self.model = os.getenv("OLLAMA_MODEL", "llama3.1:8b")
        timeout_raw = os.getenv("OLLAMA_TIMEOUT", "300")
        try:
            self.timeout = int(timeout_raw)
        except (TypeError, ValueError):
            logger.warning(f"OLLAMA_TIMEOUT invalide ('{timeout_raw}'), fallback à 300s")
            self.timeout = 300
        self.timeout = max(60, self.timeout)
        self.available = False
        self.available_models: List[str] = []
        self.last_error: str = ""
        self._config_mtime: float = 0.0
        
        logger.info(f"🔧 Configuration Ollama: URL={self.base_url}, Model={self.model}, Timeout={self.timeout}s")
        self._sync_from_persisted_config(force=True)
        self.refresh_connection()

    def _normalize_base_url(self, value: str) -> str:
        raw = str(value or "").strip()
        if not raw:
            return "http://host.docker.internal:11434"
        if not raw.startswith("http://") and not raw.startswith("https://"):
            raw = f"http://{raw}"
        return raw.rstrip("/")

    def _fetch_models(self, base_url: Optional[str] = None, timeout: int = 5) -> Dict[str, Any]:
        endpoint = self._normalize_base_url(base_url or self.base_url)
        try:
            response = requests.get(f"{endpoint}/api/tags", timeout=(3, timeout))
            if response.status_code != 200:
                return {
                    "available": False,
                    "models": [],
                    "error": f"HTTP {response.status_code}",
                    "endpoint": endpoint
                }

            payload = response.json() if response.content else {}
            models_raw = payload.get("models", [])
            model_names = []
            for item in models_raw:
                if isinstance(item, dict):
                    name = item.get("name")
                    if name:
                        model_names.append(str(name))
                elif isinstance(item, str):
                    model_names.append(item)

            return {
                "available": True,
                "models": model_names,
                "error": "",
                "endpoint": endpoint
            }
        except requests.exceptions.Timeout:
            return {"available": False, "models": [], "error": "timeout", "endpoint": endpoint}
        except requests.exceptions.RequestException as e:
            return {"available": False, "models": [], "error": str(e), "endpoint": endpoint}
        except Exception as e:
            return {"available": False, "models": [], "error": str(e), "endpoint": endpoint}

    def _persist_runtime_config(self):
        """Persist configuration for cross-worker consistency."""
        try:
            payload = {
                "endpoint": self.base_url,
                "model": self.model,
                "timeout": self.timeout,
            }
            self.config_file.parent.mkdir(parents=True, exist_ok=True)
            tmp_file = self.config_file.with_suffix(".tmp")
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            tmp_file.replace(self.config_file)
            self._config_mtime = self.config_file.stat().st_mtime
        except Exception as e:
            logger.warning(f"Impossible de persister la config Ollama: {e}")

    def _sync_from_persisted_config(self, force: bool = False):
        """Reload runtime config when another worker updated it."""
        try:
            if not self.config_file.exists():
                return
            mtime = self.config_file.stat().st_mtime
            if not force and mtime <= self._config_mtime:
                return

            with open(self.config_file, "r", encoding="utf-8") as f:
                payload = json.load(f)

            endpoint = str(payload.get("endpoint", "")).strip()
            model = str(payload.get("model", "")).strip()
            timeout = payload.get("timeout")

            if endpoint:
                self.base_url = self._normalize_base_url(endpoint)
            if model:
                self.model = model
            if timeout is not None:
                try:
                    self.timeout = max(60, int(timeout))
                except (TypeError, ValueError):
                    pass

            self._config_mtime = mtime
            logger.info(
                f"🔄 Config Ollama rechargée depuis disque: endpoint={self.base_url}, model={self.model}, timeout={self.timeout}s"
            )
        except Exception as e:
            logger.warning(f"Impossible de recharger la config Ollama persistée: {e}")

    def refresh_connection(self) -> Dict[str, Any]:
        """Rafraîchit la disponibilité Ollama et la liste des modèles."""
        self._sync_from_persisted_config()
        result = self._fetch_models(self.base_url, timeout=5)
        self.available = bool(result.get("available"))
        self.available_models = result.get("models", []) if isinstance(result.get("models"), list) else []
        self.last_error = str(result.get("error") or "")

        if self.available:
            logger.info(f"✅ Ollama disponible - Modèles détectés: {self.available_models}")
            if self.available_models and self.model not in self.available_models:
                logger.warning(f"⚠️ Modèle {self.model} non trouvé. Bascule sur {self.available_models[0]}")
                self.model = self.available_models[0]
            logger.info(f"🤖 Modèle configuré: {self.model}")
        else:
            logger.warning(f"⚠️ Ollama non disponible sur {self.base_url}: {self.last_error}")

        self._persist_runtime_config()
        return self.get_status()

    def get_status(self) -> Dict[str, Any]:
        self._sync_from_persisted_config()
        return {
            "available": self.available,
            "model": self.model,
            "endpoint": self.base_url,
            "timeout": self.timeout,
            "models": self.available_models,
            "error": self.last_error if not self.available else ""
        }

    def list_models(self, endpoint: Optional[str] = None) -> Dict[str, Any]:
        """Retourne les modèles disponibles pour un endpoint Ollama donné."""
        self._sync_from_persisted_config()
        return self._fetch_models(endpoint or self.base_url, timeout=8)

    def update_runtime_config(
        self,
        endpoint: Optional[str] = None,
        model: Optional[str] = None,
        timeout: Optional[int] = None
    ) -> Dict[str, Any]:
        """Met à jour la configuration Ollama à chaud."""
        self._sync_from_persisted_config()
        warnings: List[str] = []

        if endpoint is not None and str(endpoint).strip():
            self.base_url = self._normalize_base_url(str(endpoint))

        if timeout is not None:
            try:
                self.timeout = max(60, int(timeout))
            except (TypeError, ValueError):
                warnings.append(f"Timeout invalide '{timeout}', valeur conservée: {self.timeout}s")

        refresh = self._fetch_models(self.base_url, timeout=8)
        self.available = bool(refresh.get("available"))
        self.available_models = refresh.get("models", []) if isinstance(refresh.get("models"), list) else []
        self.last_error = str(refresh.get("error") or "")

        requested_model = str(model or "").strip()
        if requested_model:
            if self.available and self.available_models and requested_model not in self.available_models:
                warnings.append(f"Modèle '{requested_model}' non trouvé sur {self.base_url}, modèle inchangé.")
            else:
                self.model = requested_model
        elif self.available and self.available_models and self.model not in self.available_models:
            self.model = self.available_models[0]
            warnings.append(f"Modèle précédent indisponible, bascule vers '{self.model}'.")

        status = self.get_status()
        status["warnings"] = warnings
        self._persist_runtime_config()
        return status
    
    def is_available(self) -> bool:
        """Vérifie si le service Ollama est disponible"""
        return self.available

    def extract_structured_response(self, response_text: str) -> Dict[str, Any]:
        """
        Construit une structure JSON exploitable par l'UI pour toutes les réponses IA.
        Format cible:
        {
          "summary": "...",
          "culprits": [{"culprit": "...", "evidence": "...", "confidence": 0-100}],
          "signals": ["..."],
          "recommendations": ["..."],
          "confidence_note": "..."
        }
        """
        raw = str(response_text or "").strip()
        if not raw:
            return {
                "summary": "",
                "culprits": [],
                "signals": [],
                "recommendations": [],
                "confidence_note": ""
            }

        extracted = self._extract_json_from_text(raw)
        normalized = self._normalize_structured_payload(extracted)
        if normalized.get("culprits"):
            return normalized

        return self._fallback_structured_from_text(raw)

    def _extract_json_from_text(self, text: str) -> Any:
        stripped = str(text or "").strip()
        if not stripped:
            return None

        # 1) Réponse pure JSON
        if stripped.startswith("{") or stripped.startswith("["):
            try:
                return json.loads(stripped)
            except Exception:
                pass

        # 2) Bloc fenced ```json ... ```
        fenced = re.search(r"```(?:json)?\s*([\s\S]*?)```", stripped, re.IGNORECASE)
        if fenced:
            candidate = fenced.group(1).strip()
            if candidate:
                try:
                    return json.loads(candidate)
                except Exception:
                    pass

        # 3) Première sous-chaîne JSON décodable
        decoder = json.JSONDecoder()
        for idx, ch in enumerate(stripped):
            if ch not in "{[":
                continue
            try:
                obj, _ = decoder.raw_decode(stripped[idx:])
                return obj
            except Exception:
                continue

        return None

    def _coerce_confidence(self, value: Any) -> Optional[float]:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            v = float(value)
            return max(0.0, min(100.0, v))

        raw = str(value).strip().lower()
        if not raw:
            return None

        pct = re.search(r"(\d{1,3}(?:[.,]\d+)?)\s*%?", raw)
        if pct:
            try:
                v = float(pct.group(1).replace(",", "."))
                return max(0.0, min(100.0, v))
            except Exception:
                pass

        map_words = {
            "high": 80.0,
            "élevé": 80.0,
            "eleve": 80.0,
            "medium": 55.0,
            "modéré": 55.0,
            "modere": 55.0,
            "low": 30.0,
            "faible": 30.0,
        }
        for key, score in map_words.items():
            if key in raw:
                return score
        return None

    def _normalize_culprit_item(self, item: Any) -> Optional[Dict[str, Any]]:
        if item is None:
            return None

        if isinstance(item, str):
            name = item.strip()
            if not name:
                return None
            return {"culprit": name, "evidence": "", "confidence": None}

        if not isinstance(item, dict):
            return {"culprit": str(item), "evidence": "", "confidence": None}

        culprit = (
            item.get("culprit")
            or item.get("coupable")
            or item.get("responsable")
            or item.get("entity")
            or item.get("equipment")
            or item.get("equipement")
            or item.get("name")
            or item.get("target")
            or item.get("ip")
            or item.get("mac")
            or item.get("host")
            or item.get("segment")
            or "Inconnu"
        )

        evidence = (
            item.get("evidence")
            or item.get("preuve")
            or item.get("reason")
            or item.get("raison")
            or item.get("why")
            or item.get("justification")
            or item.get("details")
            or item.get("description")
            or ""
        )

        confidence = self._coerce_confidence(
            item.get("confidence")
            or item.get("confiance")
            or item.get("score")
            or item.get("probability")
            or item.get("probabilite")
        )

        return {
            "culprit": str(culprit).strip() or "Inconnu",
            "evidence": str(evidence).strip(),
            "confidence": confidence
        }

    def _normalize_structured_payload(self, payload: Any) -> Dict[str, Any]:
        base = {
            "summary": "",
            "culprits": [],
            "signals": [],
            "recommendations": [],
            "confidence_note": ""
        }

        if payload is None:
            return base

        if isinstance(payload, list):
            culprits = [self._normalize_culprit_item(item) for item in payload]
            base["culprits"] = [c for c in culprits if c]
            return base

        if not isinstance(payload, dict):
            return base

        base["summary"] = str(
            payload.get("summary")
            or payload.get("synthese")
            or payload.get("executive_summary")
            or payload.get("verdict")
            or ""
        ).strip()
        base["confidence_note"] = str(
            payload.get("confidence_note")
            or payload.get("confidence_explanation")
            or payload.get("note_confiance")
            or ""
        ).strip()

        culprits_raw = (
            payload.get("culprits")
            or payload.get("coupables")
            or payload.get("suspects")
            or payload.get("responsables")
        )
        if culprits_raw is None and (
            payload.get("culprit")
            or payload.get("coupable_probable")
            or payload.get("preuve")
            or payload.get("confiance")
        ):
            culprits_raw = [payload]

        if isinstance(culprits_raw, dict):
            culprits_raw = [culprits_raw]
        if isinstance(culprits_raw, list):
            normalized = [self._normalize_culprit_item(item) for item in culprits_raw]
            base["culprits"] = [c for c in normalized if c]

        signals = payload.get("signals") or payload.get("signaux") or payload.get("findings")
        if isinstance(signals, list):
            base["signals"] = [str(s).strip() for s in signals if str(s).strip()]
        elif isinstance(signals, str) and signals.strip():
            base["signals"] = [signals.strip()]

        recommendations = (
            payload.get("recommendations")
            or payload.get("actions")
            or payload.get("next_steps")
            or payload.get("remediation")
            or payload.get("remédiation")
        )
        if isinstance(recommendations, list):
            base["recommendations"] = [str(r).strip() for r in recommendations if str(r).strip()]
        elif isinstance(recommendations, str) and recommendations.strip():
            base["recommendations"] = [recommendations.strip()]

        return base

    def _fallback_structured_from_text(self, text: str) -> Dict[str, Any]:
        lines = [ln.strip(" \t-•") for ln in str(text or "").splitlines() if ln and ln.strip()]

        summary = lines[0] if lines else ""
        culprits: List[Dict[str, Any]] = []
        recommendations: List[str] = []
        signals: List[str] = []

        culprit_pattern = re.compile(
            r"(?i)\b(coupable|responsable|suspect|équipement|equipement|ip|mac|segment)\b[:\-]\s*(.+)"
        )
        evidence_pattern = re.compile(r"(?i)\b(preuve|evidence|indice|justification|raison)\b[:\-]\s*(.+)")
        action_pattern = re.compile(r"(?i)\b(action|recommandation|correctif|remédiation|remediation)\b[:\-]\s*(.+)")
        confidence_pattern = re.compile(r"(?i)\b(confiance|confidence|probabilité|probabilite|score)\b[:\-]?\s*([^\n]+)")

        last_culprit: Optional[Dict[str, Any]] = None
        for line in lines:
            m_culprit = culprit_pattern.search(line)
            if m_culprit:
                item = {"culprit": m_culprit.group(2).strip(), "evidence": "", "confidence": None}
                culprits.append(item)
                last_culprit = item
                continue

            m_evidence = evidence_pattern.search(line)
            if m_evidence:
                evidence = m_evidence.group(2).strip()
                if last_culprit:
                    last_culprit["evidence"] = evidence
                elif evidence:
                    signals.append(evidence)
                continue

            m_conf = confidence_pattern.search(line)
            if m_conf and last_culprit:
                last_culprit["confidence"] = self._coerce_confidence(m_conf.group(2))
                continue

            m_action = action_pattern.search(line)
            if m_action:
                recommendations.append(m_action.group(2).strip())
                continue

            if any(token in line.lower() for token in ["retrans", "latence", "rtt", "window", "rst", "perte", "congestion"]):
                signals.append(line)

        return {
            "summary": summary,
            "culprits": culprits[:8],
            "signals": signals[:10],
            "recommendations": recommendations[:10],
            "confidence_note": ""
        }

    def analyze_pcap_summary(self, analysis_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse globale du PCAP avec IA
        """
        try:
            # Préparer le contexte pour l'IA
            context = self._prepare_context(analysis_results)
            
            prompt = f"""Tu es un expert senior en ingénierie réseau, TCP/IP et cybersécurité (niveau Wireshark / RFC / troubleshooting production).

Tu analyses une capture PCAP à partir de métriques extraites (pas le PCAP brut).

OBJECTIFS PRIORITAIRES :
- Identifier précisément les causes de ralentissement réseau
- Détecter les anomalies TCP avancées (fenêtres, scaling, congestion)
- Différencier problème réseau, serveur ou applicatif
- Identifier toute activité de sécurité suspecte

=== DONNÉES PCAP ===
{json.dumps(context, indent=2, ensure_ascii=False)}

ANALYSE OBLIGATOIRE (ne saute aucune section) :

1. SYNTHÈSE EXÉCUTIVE
- Conclusion claire en 3 phrases maximum
- Problème dominant identifié (performance / sécurité / mixte)

2. ANALYSE PERFORMANCE TCP AVANCÉE
Analyse en priorité :
- RTT estimé et variabilité (latence stable ou instable)
- Retransmissions TCP (cause probable : perte, congestion, buffer)
- DUP ACK et Fast Retransmit
- RST TCP (origine client vs serveur)
- Connexions lentes ou incomplètes

3. FENÊTRES TCP & WINDOW SCALING
- Analyse du Window Size
- Présence ou absence du TCP Window Scaling
- Fenêtre trop petite côté client ou serveur
- Indices de saturation (Window Full / Zero Window)
- Impact sur le débit et la latence

4. CONGESTION & CAPACITÉ RÉSEAU
- Indices de congestion réseau
- Comportement de contrôle de flux
- Goulot d'étranglement probable (LAN / WAN / serveur)
- Hypothèse bande passante insuffisante ou buffer limité

5. ANALYSE SÉCURITÉ
- Activités anormales ou malveillantes potentielles
- Flood, scan, comportements automatisés
- Séparer clairement anomalie technique vs attaque

6. INDICATEURS TECHNIQUES CLÉS
Présente une liste claire :
- IPs impactées
- Ports concernés
- Symptômes observés
- Gravité (FAIBLE / MOYEN / ÉLEVÉ / CRITIQUE)

7. RECOMMANDATIONS TECHNIQUES ACTIONNABLES
- Actions immédiates
- Points de contrôle Wireshark (filtres display)
- Vérifications côté firewall / serveur / OS

RÈGLES :
- Sois factuel, précis, orienté ingénierie
- Pas de généralités
- Pas de conseils vagues
- Si une donnée manque, indique-le explicitement

IMPORTANT :
- Si tu ne peux pas conclure, dis-le clairement
- Ne sur-interprète pas les données
- Ne fais pas de suppositions non observables dans les métriques
"""

            # Appeler Ollama
            response = self._call_ollama(prompt)
            structured = self.extract_structured_response(response)
            
            return {
                "success": True,
                "analysis": response,
                "structured": structured,
                "model": self.model,
                "context_size": len(json.dumps(context))
            }
            
        except Exception as e:
            logger.error(f"Erreur analyse IA: {e}")
            return {
                "success": False,
                "error": str(e),
                "analysis": f"Erreur lors de l'analyse: {str(e)}",
                "structured": self.extract_structured_response(str(e))
            }
    
    def detect_attack_patterns(self, anomalies: List[Dict], 
                              protocol_analysis: Dict) -> Dict[str, Any]:
        """
        Détecte des patterns d'attaque avec l'IA
        """
        try:
            if not anomalies:
                return {
                    "success": True,
                    "patterns": [],
                    "raw_analysis": "Aucune anomalie détectée"
                }
            
            prompt = f"""Tu es un expert en détection d'intrusion et analyse de menaces.

ANOMALIES DÉTECTÉES:
{json.dumps(anomalies[:10], indent=2, ensure_ascii=False)}

ANALYSE ET IDENTIFIE:
1. **Patterns d'attaque reconnus** (DDoS, Scan, Brute Force, etc.)
2. **Niveau de confiance** pour chaque détection
3. **Actions recommandées** immédiates

Réponds en français, format structuré."""

            response = self._call_ollama(prompt)
            structured = self.extract_structured_response(response)
            
            # Parser la réponse
            attack_patterns = self._parse_attack_patterns(response)
            
            return {
                "success": True,
                "patterns": attack_patterns,
                "structured": structured,
                "raw_analysis": response
            }
            
        except Exception as e:
            logger.error(f"Erreur détection patterns: {e}")
            return {
                "success": False, 
                "error": str(e),
                "patterns": [],
                "structured": self.extract_structured_response(str(e)),
                "raw_analysis": f"Erreur: {str(e)}"
            }
    
    def analyze_dns_suspicious(self, dns_data: Dict) -> Dict[str, Any]:
        """
        Analyse les requêtes DNS suspectes
        """
        try:
            top_domains = dns_data.get('top_domains', [])[:20]
            
            if not top_domains:
                return {
                    "success": True,
                    "dns_analysis": "Pas de domaines DNS à analyser"
                }
            
            prompt = f"""Tu es un expert senior en cybersécurité spécialisé en analyse DNS et threat hunting (SOC / CERT).

Tu analyses des domaines DNS observés dans une capture réseau (PCAP).
Tu ne fais aucune supposition non observable : base-toi uniquement sur les caractéristiques des domaines fournis.

=== DOMAINES DNS OBSERVÉS ===
{json.dumps(top_domains, indent=2, ensure_ascii=False)}

ANALYSE OBLIGATOIRE POUR CHAQUE DOMAINE :

1. ANALYSE STRUCTURELLE
- Longueur totale du domaine
- Nombre de labels (sous-domaines)
- Caractères atypiques (chiffres, encodage, base32/base64)
- Entropie apparente (faible / moyenne / élevée)
- Ressemblance avec des domaines légitimes (typosquatting)

2. INDICES DE MALVEILLANCE
- DGA probable ou non (et pourquoi)
- Indices de Command & Control (C2)
- DNS tunneling ou exfiltration possible
- Utilisation abusive de sous-domaines dynamiques

3. CONTEXTE DE RISQUE
- Domaine probablement légitime / douteux / suspect / malveillant
- Raisons techniques précises (pas de généralités)

4. SCORE DE RISQUE
- Score de 0 à 100
- Justification courte et factuelle

5. ACTIONS RECOMMANDÉES
- À surveiller
- À bloquer
- À enrichir (Threat Intel, logs complémentaires)

FORMAT DE SORTIE ATTENDU (obligatoire) :

- Domaine :
- Analyse :
- Indices détectés :
- Score de risque :
- Verdict :
- Action recommandée :

RÈGLES STRICTES :
- Ne marque PAS un domaine comme malveillant sans indicateurs clairs
- Si l'analyse est incertaine, indique-le explicitement
- Évite les conclusions génériques
- Réponds en français, ton clair et professionnel
"""

            response = self._call_ollama(prompt)
            structured = self.extract_structured_response(response)
            
            return {
                "success": True,
                "dns_analysis": response,
                "structured": structured
            }
            
        except Exception as e:
            logger.error(f"Erreur analyse DNS: {e}")
            return {
                "success": False, 
                "error": str(e),
                "dns_analysis": f"Erreur: {str(e)}",
                "structured": self.extract_structured_response(str(e))
            }
    
    def analyze_http_traffic(self, http_data: Dict) -> Dict[str, Any]:
        """
        Analyse le trafic HTTP/HTTPS
        """
        try:
            hosts = http_data.get('top_hosts', [])[:15]
            user_agents = http_data.get('user_agents', [])[:10]
            
            if not hosts and not user_agents:
                return {
                    "success": True,
                    "http_analysis": "Pas de trafic HTTP à analyser"
                }
            
            prompt = f"""Tu es un expert senior en cybersécurité spécialisé en analyse HTTP/HTTPS et détection de menaces (SOC / WAF / Proxy).

Tu analyses du trafic HTTP observé dans une capture réseau (PCAP).
Tu te bases uniquement sur les informations fournies (hosts et user-agents), sans supposition externe.

=== HOSTS OBSERVÉS ===
{json.dumps(hosts, indent=2, ensure_ascii=False)}

=== USER-AGENTS OBSERVÉS ===
{json.dumps(user_agents, indent=2, ensure_ascii=False)}

ANALYSE OBLIGATOIRE :

1. ANALYSE DES USER-AGENTS
- User-agents standards (navigateurs, OS connus)
- User-agents automatisés (scripts, crawlers, scanners)
- User-agents suspects ou malveillants
- User-agents absents, vides ou anormalement génériques
- Incohérences UA (ex: navigateur vs comportement attendu)

2. ANALYSE DES HOSTS
- Hosts légitimes vs douteux
- Hosts à usage dynamique ou non conventionnel
- Indices de phishing, C2 HTTP ou hébergement suspect
- Usage anormal de sous-domaines

3. CORRÉLATION HOST ↔ USER-AGENT
- Combinaisons anormales (UA suspect sur host critique)
- Automatisation ciblée
- Indices de beaconing HTTP

4. NIVEAU DE RISQUE
Classe chaque élément comme :
- Légitime
- Douteux
- Suspect
- Malveillant
Avec justification technique concise.

5. RECOMMANDATIONS DE SÉCURITÉ
- Règles WAF / reverse proxy
- Filtrage User-Agent
- Surveillance renforcée
- Blocage si pertinent (justifié)

FORMAT DE SORTIE ATTENDU (obligatoire) :

- Élément analysé :
- Type (Host / User-Agent / Corrélation) :
- Analyse :
- Indices détectés :
- Niveau de risque :
- Action recommandée :

RÈGLES STRICTES :
- Ne marque PAS un élément comme malveillant sans indicateurs clairs
- Si l'analyse est incertaine, indique-le explicitement
- Pas de généralités
- Réponds en français, ton clair et professionnel
"""

            response = self._call_ollama(prompt)
            structured = self.extract_structured_response(response)
            
            return {
                "success": True,
                "http_analysis": response,
                "structured": structured
            }
            
        except Exception as e:
            logger.error(f"Erreur analyse HTTP: {e}")
            return {
                "success": False, 
                "error": str(e),
                "http_analysis": f"Erreur: {str(e)}",
                "structured": self.extract_structured_response(str(e))
            }
    
    def suggest_troubleshooting(self, analysis_results: Dict) -> Dict[str, Any]:
        """
        Suggère des solutions de dépannage
        """
        try:
            anomaly_block = analysis_results.get('anomaly_detection') or analysis_results.get('anomaly_analysis', {})
            anomalies = anomaly_block.get('anomalies', [])
            tcp_summary = analysis_results.get('tcp_analysis', {}).get('summary', {})
            tcp_issues = tcp_summary.get('total_retransmissions', 0)
            
            prompt = f"""Tu es un ingénieur réseau senior spécialisé en troubleshooting avancé TCP/IP (production, WAN, datacenter, cloud).

Tu analyses des anomalies issues d'une capture PCAP (métriques extraites, pas le PCAP brut).

=== INDICATEURS OBSERVÉS ===
- Nombre total d'anomalies : {len(anomalies)}
- Retransmissions TCP : {tcp_issues}

OBJECTIF :
Identifier la cause racine des problèmes de performance ou de stabilité réseau
et fournir un plan de remédiation clair et priorisé.

ANALYSE OBLIGATOIRE :

1. DIAGNOSTIC DIFFÉRENTIEL
Détermine la cause la plus probable parmi :
- Problème de latence réseau (RTT élevé, jitter)
- Congestion réseau ou saturation de lien
- Fenêtre TCP sous-dimensionnée (Window / Window Scaling)
- Pertes de paquets (physique, buffer, QoS)
- Problème serveur (CPU, socket, backlog)
- Problème applicatif

Justifie chaque hypothèse par des indicateurs observables.

2. IMPACT OPÉRATIONNEL
- Effet sur le débit
- Effet sur la latence perçue
- Risque de coupure ou d'instabilité
- Gravité : FAIBLE / MOYENNE / ÉLEVÉE / CRITIQUE

3. PLAN DE REMÉDIATION (ORDRE STRICT)
Fournis des actions concrètes et ordonnées :
- Vérifications immédiates
- Correctifs réseau (MTU, QoS, congestion)
- Tuning TCP/OS (window, buffers)
- Actions côté serveur
- Tests de validation post-correction

4. INDICES À SURVEILLER
- Métriques à monitorer
- Seuils d'alerte recommandés

5. OUTILS & FILTRES UTILES
- Filtres Wireshark pertinents
- Commandes système (ex : sysctl, netstat, ss)

RÈGLES :
- Ne donne pas de solutions génériques
- Si les données sont insuffisantes, indique précisément ce qu'il manque
- Raisonne comme en incident de production réel
- Réponds en français, ton professionnel, orienté action
"""

            response = self._call_ollama(prompt)
            structured = self.extract_structured_response(response)
            
            return {
                "success": True,
                "troubleshooting": response,
                "structured": structured
            }
            
        except Exception as e:
            logger.error(f"Erreur troubleshooting: {e}")
            return {
                "success": False, 
                "error": str(e),
                "troubleshooting": f"Erreur: {str(e)}",
                "structured": self.extract_structured_response(str(e))
            }
    
    def _call_ollama(self, prompt: str, stream: bool = False) -> str:
        """
        Appelle l'API Ollama avec gestion robuste des erreurs
        """
        try:
            # Ensure we use the latest model/endpoint selected via another worker.
            self._sync_from_persisted_config()
            logger.info(f"📡 Appel Ollama - Prompt: {len(prompt)} caractères")
            
            payload = {
                "model": self.model,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.7,
                    "top_p": 0.9,
                    "num_predict": 800
                }
            }
            
            response = requests.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=(10, self.timeout)
            )
            
            if response.status_code == 200:
                result = response.json()
                answer = result.get('response', '').strip()
                self.available = True
                self.last_error = ""
                logger.info(f"✅ Réponse Ollama: {len(answer)} caractères")
                return answer
            else:
                error_msg = f"Erreur Ollama HTTP {response.status_code}: {response.text}"
                self.available = False
                self.last_error = error_msg
                logger.error(error_msg)
                return error_msg
                
        except requests.exceptions.Timeout:
            error_msg = f"⏱️ Timeout Ollama ({self.timeout}s dépassé)"
            self.available = False
            self.last_error = error_msg
            logger.error(error_msg)
            return error_msg
        except requests.exceptions.ConnectionError:
            error_msg = "🔌 Erreur connexion Ollama - Vérifiez qu'Ollama est démarré"
            self.available = False
            self.last_error = error_msg
            logger.error(error_msg)
            return error_msg
        except Exception as e:
            error_msg = f"❌ Erreur Ollama: {str(e)}"
            self.available = False
            self.last_error = error_msg
            logger.error(error_msg)
            return error_msg
    
    def _prepare_context(self, results: Dict) -> Dict:
        """
        Prépare un contexte résumé pour l'IA
        """
        protocol = results.get('protocol_analysis', {})
        tcp = results.get('tcp_analysis', {})
        anomaly = results.get('anomaly_detection') or results.get('anomaly_analysis', {})
        dns = results.get('dns_analysis', {})
        http = results.get('http_analysis', {})
        
        protocol_summary = protocol.get('summary', {})
        tcp_summary = tcp.get('summary', {})
        anomaly_summary = anomaly.get('summary', {})
        dns_summary = dns.get('summary', {})
        http_summary = http.get('summary', {})
        
        return {
            "statistiques_globales": {
                "total_paquets": protocol_summary.get('total_packets', 0),
                "total_bytes": protocol_summary.get('total_bytes', 0),
                "durée_capture": protocol_summary.get('duration', 0),
                "protocoles_détectés": len(protocol.get('protocols', {}))
            },
            "tcp": {
                "sessions": tcp_summary.get('total_sessions', 0),
                "retransmissions": tcp_summary.get('total_retransmissions', 0),
                "connexions_échouées": tcp_summary.get('failed_connections', 0)
            },
            "anomalies": {
                "total": anomaly_summary.get('total_anomalies', 0),
                "niveau_risque": anomaly_summary.get('risk_level', 'NONE'),
                "critiques": len([a for a in anomaly.get('anomalies', []) 
                                 if a.get('severity') == 'CRITICAL']),
                "top_anomalies": anomaly.get('anomalies', [])[:5]
            },
            "dns": {
                "requêtes": dns_summary.get('total_queries', 0),
                "domaines_uniques": dns_summary.get('unique_domains', 0)
            },
            "http": {
                "requêtes": http_summary.get('total_requests', 0),
                "hosts_uniques": len(http.get('hosts', []))
            }
        }
    
    def _parse_attack_patterns(self, response: str) -> List[Dict]:
        """
        Parse la réponse de l'IA pour extraire les patterns
        """
        try:
            # Chercher un bloc JSON dans la réponse
            json_match = re.search(r'\{.*\}|\[.*\]', response, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            # Sinon, retourner la réponse brute structurée
            return [{
                "type": "Analyse textuelle",
                "description": response[:500],
                "confidence": "medium"
            }]
            
        except Exception as e:
            logger.error(f"Erreur parsing patterns: {e}")
            return [{
                "type": "Erreur parsing",
                "description": response[:200],
                "error": str(e)
            }]


# Instance singleton - IMPORTANT !
ai_service = OllamaAnalysisService()
