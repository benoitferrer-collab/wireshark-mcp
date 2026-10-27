"""
Enrichment Service
Provides GeoIP, ASN, WHOIS, and SSL certificate analysis
Uses free APIs with caching and rate limiting
"""

import json
import time
import hashlib
import ssl
import socket
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from pathlib import Path
from collections import defaultdict
import threading
import re

import requests
from app.core.logging_config import get_logger
from app.core.config import get_settings

logger = get_logger(__name__)
settings = get_settings()


class RateLimiter:
    """Simple rate limiter for API calls"""
    
    def __init__(self, calls_per_minute: int = 45):
        self.calls_per_minute = calls_per_minute
        self.calls = []
        self.lock = threading.Lock()
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded"""
        with self.lock:
            now = time.time()
            # Remove calls older than 1 minute
            self.calls = [t for t in self.calls if now - t < 60]
            
            if len(self.calls) >= self.calls_per_minute:
                # Wait until oldest call expires
                sleep_time = 60 - (now - self.calls[0]) + 0.1
                if sleep_time > 0:
                    time.sleep(sleep_time)
                self.calls = self.calls[1:]
            
            self.calls.append(time.time())


class EnrichmentCache:
    """Cache for enrichment data with TTL"""
    
    def __init__(self, cache_dir: Path = None, ttl_hours: int = 24):
        self.cache_dir = cache_dir or (settings.results_dir / "enrichment_cache")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.ttl = timedelta(hours=ttl_hours)
        self.memory_cache: Dict[str, Dict] = {}
        self.lock = threading.Lock()
    
    def _get_cache_key(self, prefix: str, value: str) -> str:
        """Generate cache key"""
        return hashlib.md5(f"{prefix}:{value}".encode()).hexdigest()
    
    def get(self, prefix: str, value: str) -> Optional[Dict]:
        """Get cached value"""
        cache_key = self._get_cache_key(prefix, value)
        
        # Check memory cache first
        with self.lock:
            if cache_key in self.memory_cache:
                entry = self.memory_cache[cache_key]
                if datetime.fromisoformat(entry["expires"]) > datetime.now():
                    return entry["data"]
        
        # Check file cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        if cache_file.exists():
            try:
                with open(cache_file, 'r') as f:
                    entry = json.load(f)
                if datetime.fromisoformat(entry["expires"]) > datetime.now():
                    # Populate memory cache
                    with self.lock:
                        self.memory_cache[cache_key] = entry
                    return entry["data"]
            except Exception:
                pass
        
        return None
    
    def set(self, prefix: str, value: str, data: Dict) -> None:
        """Set cached value"""
        cache_key = self._get_cache_key(prefix, value)
        entry = {
            "data": data,
            "expires": (datetime.now() + self.ttl).isoformat(),
        }
        
        # Update memory cache
        with self.lock:
            self.memory_cache[cache_key] = entry
        
        # Write to file cache
        cache_file = self.cache_dir / f"{cache_key}.json"
        try:
            with open(cache_file, 'w') as f:
                json.dump(entry, f)
        except Exception as e:
            logger.debug(f"Failed to write cache: {e}")


class EnrichmentService:
    """Service for enriching IPs, domains, and certificates"""
    
    def __init__(self):
        self.cache = EnrichmentCache()
        self.rate_limiter = RateLimiter(calls_per_minute=45)  # ip-api.com limit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PCAP-Analyzer/2.0'
        })
    
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP address with GeoIP and ASN data"""
        # Check cache
        cached = self.cache.get("ip", ip)
        if cached:
            return cached
        
        result = {
            "ip": ip,
            "is_private": self._is_private_ip(ip),
            "geoip": None,
            "asn": None,
            "enriched_at": datetime.now().isoformat(),
        }
        
        # Skip private IPs
        if result["is_private"]:
            return result
        
        # Use ip-api.com (free, no API key needed)
        try:
            self.rate_limiter.wait_if_needed()
            response = self.session.get(
                f"http://ip-api.com/json/{ip}",
                params={
                    "fields": "status,message,country,countryCode,region,regionName,"
                             "city,zip,lat,lon,timezone,isp,org,as,asname,query"
                },
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    result["geoip"] = {
                        "country": data.get("country"),
                        "country_code": data.get("countryCode"),
                        "region": data.get("regionName"),
                        "city": data.get("city"),
                        "postal": data.get("zip"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone"),
                    }
                    result["asn"] = {
                        "number": data.get("as", "").split()[0] if data.get("as") else None,
                        "name": data.get("asname"),
                        "organization": data.get("org"),
                        "isp": data.get("isp"),
                    }
        except Exception as e:
            logger.debug(f"GeoIP lookup failed for {ip}: {e}")
        
        # Cache result
        self.cache.set("ip", ip, result)
        return result
    
    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with WHOIS data"""
        # Check cache
        cached = self.cache.get("domain", domain)
        if cached:
            return cached
        
        result = {
            "domain": domain,
            "whois": None,
            "dns": None,
            "enriched_at": datetime.now().isoformat(),
        }
        
        # Try to get WHOIS data
        try:
            import whois
            w = whois.whois(domain)
            if w:
                result["whois"] = {
                    "registrar": w.registrar if hasattr(w, 'registrar') else None,
                    "creation_date": self._format_date(w.creation_date) if hasattr(w, 'creation_date') else None,
                    "expiration_date": self._format_date(w.expiration_date) if hasattr(w, 'expiration_date') else None,
                    "updated_date": self._format_date(w.updated_date) if hasattr(w, 'updated_date') else None,
                    "name_servers": list(w.name_servers) if hasattr(w, 'name_servers') and w.name_servers else None,
                    "status": list(w.status) if hasattr(w, 'status') and w.status else None,
                    "organization": w.org if hasattr(w, 'org') else None,
                    "country": w.country if hasattr(w, 'country') else None,
                }
        except ImportError:
            logger.debug("python-whois not available")
        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
        
        # Cache result
        self.cache.set("domain", domain, result)
        return result
    
    def analyze_certificate(self, cert_data: Dict) -> Dict[str, Any]:
        """Analyze SSL/TLS certificate"""
        result = {
            "subject": cert_data.get("subject"),
            "issuer": cert_data.get("issuer"),
            "serial": cert_data.get("serial"),
            "not_before": cert_data.get("not_before"),
            "not_after": cert_data.get("not_after"),
            "version": cert_data.get("version"),
            "signature_algorithm": cert_data.get("signature_algorithm"),
            "san": cert_data.get("san", []),
            "analysis": {
                "is_valid": False,
                "is_expired": False,
                "is_self_signed": False,
                "days_until_expiry": None,
                "issues": [],
            }
        }
        
        try:
            # Check expiration
            if result["not_after"]:
                expiry = datetime.fromisoformat(result["not_after"].replace('Z', '+00:00'))
                now = datetime.now(expiry.tzinfo) if expiry.tzinfo else datetime.now()
                
                result["analysis"]["days_until_expiry"] = (expiry - now).days
                result["analysis"]["is_expired"] = expiry < now
                
                if result["analysis"]["is_expired"]:
                    result["analysis"]["issues"].append("Certificate has expired")
                elif result["analysis"]["days_until_expiry"] < 30:
                    result["analysis"]["issues"].append(
                        f"Certificate expires in {result['analysis']['days_until_expiry']} days"
                    )
            
            # Check self-signed
            subject = result.get("subject", {})
            issuer = result.get("issuer", {})
            if subject and issuer:
                if subject == issuer or \
                   subject.get("CN") == issuer.get("CN") and subject.get("O") == issuer.get("O"):
                    result["analysis"]["is_self_signed"] = True
                    result["analysis"]["issues"].append("Self-signed certificate")
            
            # Check weak signature
            sig_algo = result.get("signature_algorithm", "").lower()
            if sig_algo:
                if "md5" in sig_algo:
                    result["analysis"]["issues"].append("Weak signature algorithm (MD5)")
                elif "sha1" in sig_algo:
                    result["analysis"]["issues"].append("Deprecated signature algorithm (SHA-1)")
            
            # Set validity
            result["analysis"]["is_valid"] = len(result["analysis"]["issues"]) == 0 and \
                                             not result["analysis"]["is_expired"]
            
        except Exception as e:
            logger.debug(f"Certificate analysis failed: {e}")
        
        return result
    
    def get_certificate_from_host(self, host: str, port: int = 443) -> Optional[Dict]:
        """Retrieve and parse SSL certificate from host"""
        cache_key = f"{host}:{port}"
        cached = self.cache.get("cert", cache_key)
        if cached:
            return cached
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cert_binary = ssock.getpeercert(binary_form=True)
                    
                    if cert:
                        result = self._parse_certificate(cert)
                        result["host"] = host
                        result["port"] = port
                        
                        # Analyze
                        analysis = self.analyze_certificate(result)
                        result["analysis"] = analysis["analysis"]
                        
                        self.cache.set("cert", cache_key, result)
                        return result
                        
        except Exception as e:
            logger.debug(f"Certificate retrieval failed for {host}:{port}: {e}")
        
        return None
    
    def enrich_batch(self, ips: List[str], domains: List[str] = None) -> Dict[str, Any]:
        """Batch enrichment of IPs and domains"""
        result = {
            "ips": {},
            "domains": {},
            "summary": {
                "total_ips": len(ips),
                "total_domains": len(domains) if domains else 0,
                "countries": defaultdict(int),
                "asns": defaultdict(int),
                "private_ips": 0,
            }
        }
        
        # Deduplicate
        unique_ips = list(set(ips))
        unique_domains = list(set(domains)) if domains else []
        
        # Enrich IPs (with rate limiting)
        for ip in unique_ips[:100]:  # Limit to first 100
            try:
                enriched = self.enrich_ip(ip)
                if not enriched:
                    enriched = {"ip": ip, "is_private": self._is_private_ip(ip)}
                result["ips"][ip] = enriched
                
                if enriched.get("is_private"):
                    result["summary"]["private_ips"] += 1
                else:
                    geoip = enriched.get("geoip") or {}
                    if geoip.get("country_code"):
                        result["summary"]["countries"][geoip["country_code"]] += 1
                
                asn = enriched.get("asn") or {}
                if asn.get("name"):
                    result["summary"]["asns"][asn["name"]] += 1
                    
            except Exception as e:
                logger.debug(f"Failed to enrich IP {ip}: {e}")
                # Store minimal info even on error
                result["ips"][ip] = {"ip": ip, "is_private": self._is_private_ip(ip), "error": str(e)}
        
        # Enrich domains
        for domain in unique_domains[:50]:  # Limit to first 50
            try:
                enriched = self.enrich_domain(domain)
                result["domains"][domain] = enriched
            except Exception as e:
                logger.debug(f"Failed to enrich domain {domain}: {e}")
        
        # Convert defaultdicts
        result["summary"]["countries"] = dict(
            sorted(result["summary"]["countries"].items(), key=lambda x: x[1], reverse=True)
        )
        result["summary"]["asns"] = dict(
            sorted(result["summary"]["asns"].items(), key=lambda x: x[1], reverse=True)[:20]
        )
        
        return result
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/reserved"""
        try:
            import ipaddress
            addr = ipaddress.ip_address(ip)
            return addr.is_private or addr.is_loopback or addr.is_reserved or \
                   addr.is_multicast or addr.is_link_local
        except:
            return False
    
    def _format_date(self, date_val) -> Optional[str]:
        """Format date value to ISO string"""
        if date_val is None:
            return None
        if isinstance(date_val, list):
            date_val = date_val[0] if date_val else None
        if isinstance(date_val, datetime):
            return date_val.isoformat()
        return str(date_val) if date_val else None
    
    def _parse_certificate(self, cert: Dict) -> Dict:
        """Parse certificate dict to standard format"""
        result = {
            "subject": {},
            "issuer": {},
            "serial": cert.get("serialNumber"),
            "version": cert.get("version"),
            "not_before": None,
            "not_after": None,
            "san": [],
        }
        
        # Parse subject
        if cert.get("subject"):
            for rdn in cert["subject"]:
                for attr_type, attr_value in rdn:
                    result["subject"][attr_type] = attr_value
        
        # Parse issuer
        if cert.get("issuer"):
            for rdn in cert["issuer"]:
                for attr_type, attr_value in rdn:
                    result["issuer"][attr_type] = attr_value
        
        # Parse dates
        if cert.get("notBefore"):
            try:
                result["not_before"] = datetime.strptime(
                    cert["notBefore"], "%b %d %H:%M:%S %Y %Z"
                ).isoformat()
            except:
                result["not_before"] = cert["notBefore"]
        
        if cert.get("notAfter"):
            try:
                result["not_after"] = datetime.strptime(
                    cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                ).isoformat()
            except:
                result["not_after"] = cert["notAfter"]
        
        # Parse SAN
        if cert.get("subjectAltName"):
            for san_type, san_value in cert["subjectAltName"]:
                result["san"].append({"type": san_type, "value": san_value})
        
        return result


# Singleton instance
_enrichment_service = None

def get_enrichment_service() -> EnrichmentService:
    """Get singleton enrichment service instance"""
    global _enrichment_service
    if _enrichment_service is None:
        _enrichment_service = EnrichmentService()
    return _enrichment_service


# ============================================================
# THREAT INTELLIGENCE SERVICE — Feature 9
# ============================================================

import os
import csv
import io

class ThreatIntelService:
    """
    Service d'enrichissement Threat Intelligence multi-sources:
    - AbuseIPDB (signalement IPs malveillantes)
    - FeodoTracker (boutnets & C2 IPs)
    - URLhaus (domaines malveillants)
    """

    FEODOTRACKER_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
    URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"
    ABUSEIPDB_API = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self):
        self.cache = EnrichmentCache(ttl_hours=6)
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'PCAP-Analyzer/2.0'})
        self.abuseipdb_key: str = os.getenv("ABUSEIPDB_API_KEY", "")
        self.crowdsec_key: str = os.getenv("CROWDSEC_API_KEY", "")
        self._feodo_cache: Optional[set] = None
        self._feodo_loaded_at: float = 0.0
        # Verrou: les lookups parallèles ne doivent télécharger la liste qu'une fois
        self._feodo_lock = threading.Lock()

    # ─────────────────────────────────────────────────────────
    # AbuseIPDB
    # ─────────────────────────────────────────────────────────
    def check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Interroge AbuseIPDB pour une IP (nécessite ABUSEIPDB_API_KEY dans .env)"""
        cached = self.cache.get("abuseipdb", ip)
        if cached:
            return cached

        if not self.abuseipdb_key:
            result: Dict[str, Any] = {"ip": ip, "source": "AbuseIPDB", "error": "No API key — set ABUSEIPDB_API_KEY in .env"}
            return result

        try:
            resp = self.session.get(
                self.ABUSEIPDB_API,
                headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                timeout=8
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                result = {
                    "ip": ip,
                    "source": "AbuseIPDB",
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country_code": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "domain": data.get("domain"),
                    "is_tor": data.get("isTor", False),
                    "last_reported": data.get("lastReportedAt"),
                    "verdict": (
                        "🔴 MALICIOUS" if data.get("abuseConfidenceScore", 0) >= 75
                        else "🟠 SUSPICIOUS" if data.get("abuseConfidenceScore", 0) >= 25
                        else "🟢 CLEAN"
                    )
                }
                self.cache.set("abuseipdb", ip, result)
                return result
            return {"ip": ip, "source": "AbuseIPDB", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"ip": ip, "source": "AbuseIPDB", "error": str(e)}

    # ─────────────────────────────────────────────────────────
    # FeodoTracker (botnet C2 IP list)
    # ─────────────────────────────────────────────────────────
    def _load_feodo_ips(self) -> set:
        """Télécharge et met en cache la liste FeodoTracker (TTL: 6h)"""
        now = time.time()
        if self._feodo_cache is not None and (now - self._feodo_loaded_at) < 21600:
            return self._feodo_cache

        with self._feodo_lock:
            # Double-check: un autre thread a pu charger la liste pendant l'attente
            if self._feodo_cache is not None and (time.time() - self._feodo_loaded_at) < 21600:
                return self._feodo_cache
            return self._download_feodo_ips()

    def _download_feodo_ips(self) -> set:
        try:
            resp = self.session.get(self.FEODOTRACKER_URL, timeout=15)
            ips: set = set()
            for line in resp.text.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    ips.add(line)
            self._feodo_cache = ips
            self._feodo_loaded_at = time.time()
            logger.info(f"FeodoTracker: {len(ips)} C2 IPs chargées")
            return ips
        except Exception as e:
            logger.warning(f"FeodoTracker download failed: {e}")
            return set()

    def check_feodotracker(self, ip: str) -> Dict[str, Any]:
        """Vérifie si une IP est dans la liste FeodoTracker (C2 botnet)"""
        feodo_ips = self._load_feodo_ips()
        in_list = ip in feodo_ips
        return {
            "ip": ip,
            "source": "FeodoTracker",
            "is_c2": in_list,
            "verdict": "🔴 C2 BOTNET CONNU" if in_list else "🟢 NON LISTÉ",
        }

    # ─────────────────────────────────────────────────────────
    # URLhaus (malicious domains)
    # ─────────────────────────────────────────────────────────
    def check_urlhaus(self, domain_or_ip: str) -> Dict[str, Any]:
        """Interroge URLhaus pour un domaine ou une IP"""
        cached = self.cache.get("urlhaus", domain_or_ip)
        if cached:
            return cached

        try:
            resp = self.session.post(
                self.URLHAUS_API,
                data={"host": domain_or_ip},
                timeout=8
            )
            if resp.status_code == 200:
                data = resp.json()
                query_status = data.get("query_status", "no_results")
                urls_online = [u for u in data.get("urls", []) if u.get("url_status") == "online"]

                result = {
                    "host": domain_or_ip,
                    "source": "URLhaus",
                    "query_status": query_status,
                    "url_count": len(data.get("urls", [])),
                    "urls_online": len(urls_online),
                    "blacklists": data.get("blacklists", {}),
                    "verdict": (
                        "🔴 MALICIOUS — URLhaus" if query_status == "is_host" and urls_online > 0
                        else "🟠 LISTED — URLhaus" if query_status == "is_host"
                        else "🟢 NOT LISTED"
                    )
                }
                self.cache.set("urlhaus", domain_or_ip, result)
                return result
            return {"host": domain_or_ip, "source": "URLhaus", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"host": domain_or_ip, "source": "URLhaus", "error": str(e)}

    # ─────────────────────────────────────────────────────────
    # CrowdSec
    # ─────────────────────────────────────────────────────────
    def check_crowdsec(self, ip: str) -> Dict[str, Any]:
        """Interroge CrowdSec CTI API pour une IP (nécessite CROWDSEC_API_KEY dans .env)"""
        cached = self.cache.get("crowdsec", ip)
        if cached:
            return cached

        if not self.crowdsec_key:
            return {"ip": ip, "source": "CrowdSec", "error": "No API key — set CROWDSEC_API_KEY in .env"}

        try:
            headers = {
                "x-api-key": self.crowdsec_key, 
                "Accept": "application/json",
                "User-Agent": "PCAP-Analyzer-Pro/2.0 (CrowdSec CTI Integration)"
            }
            resp = self.session.get(
                f"https://cti.api.crowdsec.net/v2/smoke/{ip}",
                headers=headers,
                timeout=8
            )
            if resp.status_code == 200:
                data = resp.json()
                scores = data.get("scores", {})
                overall_score = scores.get("overall", {}).get("total", 0)
                
                attack_details = data.get("attack_details", [])
                
                is_malicious = len(attack_details) > 0 or overall_score > 2
                
                result = {
                    "ip": ip,
                    "source": "CrowdSec",
                    "overall_score": overall_score,
                    "attack_details": attack_details,
                    "classifications": data.get("classifications", {}),
                    "verdict": "🔴 MALICIOUS" if is_malicious else "🟢 CLEAN",
                    "is_malicious": is_malicious
                }
                self.cache.set("crowdsec", ip, result)
                return result
            elif resp.status_code == 404:
                # IP non trouvée dans la base = Clean
                result = {
                    "ip": ip,
                    "source": "CrowdSec",
                    "verdict": "🟢 CLEAN",
                    "is_malicious": False
                }
                self.cache.set("crowdsec", ip, result)
                return result
            elif resp.status_code == 429:
                return {"ip": ip, "source": "CrowdSec", "error": "Rate limit exceeded (HTTP 429)"}

            return {"ip": ip, "source": "CrowdSec", "error": f"HTTP {resp.status_code}"}
        except Exception as e:
            return {"ip": ip, "source": "CrowdSec", "error": str(e)}

    # ─────────────────────────────────────────────────────────
    # Aggregated threat intel per task
    # ─────────────────────────────────────────────────────────
    def get_threat_intel_summary(
        self,
        ips: List[str],
        domains: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Aggrège toutes les sources Threat Intel pour une liste d'indicateurs.
        Retourne un résumé structuré avec scores de réputation.
        """
        ip_results: Dict[str, Dict[str, Any]] = {}
        domain_results: Dict[str, Dict[str, Any]] = {}
        critical_iocs: List[Dict[str, Any]] = []

        # Tri des IPs: privées traitées immédiatement, publiques vérifiées en ligne
        public_ips: List[str] = []
        for ip in list(set(ips))[:50]:
            try:
                import ipaddress
                addr = ipaddress.ip_address(ip)
                if addr.is_private or addr.is_loopback:
                    ip_results[ip] = {"ip": ip, "is_private": True}
                    continue
            except ValueError:
                continue
            public_ips.append(ip)

        unique_domains = list(set(domains or []))[:30]

        # Toutes les requêtes (4 sources × N IPs + URLhaus × M domaines) partent
        # en parallèle: le pire cas passe de « minutes » (série) à ~1 timeout (15s)
        from concurrent.futures import ThreadPoolExecutor

        lookups = {}  # (kind, indicator, source) -> future
        with ThreadPoolExecutor(max_workers=16, thread_name_prefix="threat-intel") as pool:
            for ip in public_ips:
                lookups[("ip", ip, "feodo")] = pool.submit(self.check_feodotracker, ip)
                lookups[("ip", ip, "abuseipdb")] = pool.submit(self.check_abuseipdb, ip)
                lookups[("ip", ip, "urlhaus")] = pool.submit(self.check_urlhaus, ip)
                lookups[("ip", ip, "crowdsec")] = pool.submit(self.check_crowdsec, ip)
            for domain in unique_domains:
                lookups[("domain", domain, "urlhaus")] = pool.submit(self.check_urlhaus, domain)

        def _lookup(kind: str, indicator: str, source: str) -> Dict[str, Any]:
            future = lookups.get((kind, indicator, source))
            try:
                return future.result() if future is not None else {}
            except Exception as e:
                return {"error": str(e)}

        for ip in public_ips:
            feodo = _lookup("ip", ip, "feodo")
            abuseipdb = _lookup("ip", ip, "abuseipdb")
            urlhaus = _lookup("ip", ip, "urlhaus")
            crowdsec = _lookup("ip", ip, "crowdsec")

            # Compute combined reputation score (0-100, higher = more malicious)
            rep_score = 0
            if feodo.get("is_c2"):
                rep_score += 80
            rep_score += min(20, int(abuseipdb.get("abuse_confidence_score", 0)) // 5)
            if urlhaus.get("query_status") == "is_host":
                rep_score += 30
                
            # Intégration du score CrowdSec
            if crowdsec.get("is_malicious"):
                rep_score += 50
            elif crowdsec.get("overall_score") and float(crowdsec.get("overall_score", 0)) > 0:
                rep_score += min(30, float(crowdsec.get("overall_score", 0)) * 10)
                
            rep_score = min(100, int(rep_score))

            ip_data = {
                "ip": ip,
                "is_private": False,
                "reputation_score": rep_score,
                "sources": {
                    "abuseipdb": abuseipdb,
                    "feodotracker": feodo,
                    "urlhaus": urlhaus,
                    "crowdsec": crowdsec,
                },
                "verdict": (
                    "🔴 MALICIOUS" if rep_score >= 70
                    else "🟠 SUSPICIOUS" if rep_score >= 30
                    else "🟢 CLEAN"
                )
            }
            ip_results[ip] = ip_data

            if rep_score >= 70:
                critical_iocs.append({"type": "ip", "value": ip, "score": rep_score})

        # Check unique domains (max 30) — résultats déjà récupérés en parallèle
        for domain in unique_domains:
            urlhaus = _lookup("domain", domain, "urlhaus")
            rep_score = 0
            if urlhaus.get("query_status") == "is_host":
                rep_score = 70 if urlhaus.get("urls_online", 0) > 0 else 40

            domain_data = {
                "domain": domain,
                "reputation_score": rep_score,
                "sources": {"urlhaus": urlhaus},
                "verdict": (
                    "🔴 MALICIOUS" if rep_score >= 70
                    else "🟠 SUSPICIOUS" if rep_score >= 30
                    else "🟢 CLEAN"
                )
            }
            domain_results[domain] = domain_data

            if rep_score >= 70:
                critical_iocs.append({"type": "domain", "value": domain, "score": rep_score})

        malicious_ips = [ip for ip, d in ip_results.items() if d.get("reputation_score", 0) >= 70]
        suspicious_ips = [ip for ip, d in ip_results.items() if 30 <= d.get("reputation_score", 0) < 70]

        return {
            "summary": {
                "total_ips_checked": len(ip_results),
                "total_domains_checked": len(domain_results),
                "malicious_ips": len(malicious_ips),
                "suspicious_ips": len(suspicious_ips),
                "critical_iocs": len(critical_iocs),
                "sources_used": ["FeodoTracker", "AbuseIPDB", "URLhaus", "CrowdSec"],
            },
            "ip_intel": ip_results,
            "domain_intel": domain_results,
            "critical_iocs": sorted(critical_iocs, key=lambda x: int(x["score"]), reverse=True),
            "top_malicious_ips": malicious_ips[:10],
        }


# Singleton for threat intel
_threat_intel_service: Optional["ThreatIntelService"] = None

def get_threat_intel_service() -> ThreatIntelService:
    """Get singleton ThreatIntelService instance"""
    global _threat_intel_service
    if _threat_intel_service is None:
        _threat_intel_service = ThreatIntelService()
    return _threat_intel_service
