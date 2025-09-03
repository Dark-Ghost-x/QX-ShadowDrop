#!/usr/bin/env python3
import json
import random
import time
import ssl
import re
import requests
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, urljoin
from requests.exceptions import RequestException
from .vulnerability_base import VulnerabilityModule

CDX_API_URL = "https://web.archive.org/cdx/search/cdx"
MAX_URLS = 200
DEFAULT_TIMEOUT = 15
WAYBACK_MACHINE_URL = "https://web.archive.org/web/"

class WaybackScanner(VulnerabilityModule):
    name = "wayback_scraper"
    description = "Advanced Wayback Machine historical data scanner with aggressive collection"
    risk = "low"
    useproxy = False
    enabled = True
    aggressive_mode = False
    bypass_protection = False
    custom_filters = []
    
    def __init__(self, *args, **kwargs):
        target = None
        session = None
        timeout = 10
        debug = False
        aggressive = False
        custom_filters = None
        bypass_protection = False
        stealth = None
        
        if len(args) >= 1:
            target = args[0]
        if len(args) >= 2:
            session = args[1]
        if len(args) >= 3:
            timeout = args[2]
        if len(args) >= 4:
            debug = args[3]
            
        if 'target' in kwargs:
            target = kwargs['target']
        if 'session' in kwargs:
            session = kwargs['session']
        if 'timeout' in kwargs:
            timeout = kwargs['timeout']
        if 'debug' in kwargs:
            debug = kwargs['debug']
        if 'aggressive' in kwargs:
            aggressive = kwargs['aggressive']
        if 'custom_filters' in kwargs:
            custom_filters = kwargs['custom_filters']
        if 'bypass_protection' in kwargs:
            bypass_protection = kwargs['bypass_protection']
        if 'stealth' in kwargs:
            stealth = kwargs['stealth']
            
        if session is None:
            session = requests.Session()
            
        super().__init__(target, session, timeout, debug)
        
        self.aggressive_mode = aggressive
        self.custom_filters = custom_filters if custom_filters else []
        
        if stealth is not None:
            self.bypass_protection = stealth
        else:
            self.bypass_protection = bypass_protection
            
        if self.bypass_protection:
            self.session.verify = False
            ssl._create_default_https_context = ssl._create_unverified_context
            requests.packages.urllib3.disable_warnings()
            self.session.headers.update({
                'User-Agent': random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
                ]),
                'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
                'X-Real-IP': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
                'Accept': 'text/html,application/json,application/xml',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive'
            })
    
    @staticmethod
    def normalize_domain(target: str) -> str:
        if not any(target.startswith(proto) for proto in ("http://", "https://")):
            target = f"http://{target}"
        parsed = urlparse(target)
        return (parsed.hostname or parsed.path).split(":")[0].lower()
    
    def fetch_cdx_data(self, domain: str, filters: List[str] = None) -> Optional[List[List[str]]]:
        if filters is None:
            filters = []
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey",
            "limit": "5000" if self.aggressive_mode else "1000"
        }
        try:
            time.sleep(0.5)
            response = self.session.get(
                CDX_API_URL,
                params=params,
                timeout=self.timeout,
                verify=not self.bypass_protection
            )
            response.raise_for_status()
            return response.json()
        except (RequestException, json.JSONDecodeError) as e:
            if self.debug:
                print(f"[WAYBACK] API request failed: {e}")
            return None
    
    def fetch_snapshots(self, url: str) -> Optional[List[Dict]]:
        snapshot_url = f"https://web.archive.org/cdx/search/cdx?url={url}&output=json&fl=timestamp,original"
        try:
            response = self.session.get(snapshot_url, timeout=self.timeout, verify=not self.bypass_protection)
            if response.status_code == 200:
                return response.json()[1:]
        except Exception as e:
            if self.debug:
                print(f"[WAYBACK] Snapshot fetch failed for {url}: {e}")
        return None
    
    def process_urls(self, data: List[List[str]]) -> Dict[str, Any]:
        if not data or len(data) <= 1:
            return {"domain": self.normalize_domain(self.target), "count": 0, "urls": [], "stats": {}}
        
        unique_urls = set()
        processed_urls = []
        stats = {
            "total_entries": len(data) - 1,
            "status_codes": {},
            "mime_types": {},
            "timeline": {}
        }
        
        for row in data[1:]:
            if len(processed_urls) >= (MAX_URLS * 2 if self.aggressive_mode else MAX_URLS):
                break
            if len(row) >= 4:
                url, timestamp, status_code, mimetype = row[0], row[1], row[2], row[3]
                if url not in unique_urls:
                    unique_urls.add(url)
                    url_info = {
                        "url": url,
                        "timestamp": timestamp,
                        "status_code": status_code,
                        "mimetype": mimetype,
                        "wayback_url": f"{WAYBACK_MACHINE_URL}{timestamp}/{url}" if timestamp else None
                    }
                    if self._apply_filters(url_info):
                        processed_urls.append(url_info)
                        stats["status_codes"][status_code] = stats["status_codes"].get(status_code, 0) + 1
                        stats["mime_types"][mimetype] = stats["mime_types"].get(mimetype, 0) + 1
                        year = timestamp[:4] if timestamp else "unknown"
                        stats["timeline"][year] = stats["timeline"].get(year, 0) + 1
        
        return {
            "domain": self.normalize_domain(self.target),
            "count": len(processed_urls),
            "urls": processed_urls,
            "stats": stats
        }
    
    def _apply_filters(self, url_info: Dict) -> bool:
        url = url_info["url"].lower()
        
        high_priority_filters = [
            "admin", "login", "config", "backup", "sql", "database",
            "password", "secret", "key", "token", "api", "endpoint",
            "wp-admin", "administrator", "phpmyadmin", "test", "debug",
            ".env", ".bak", ".old", ".backup", ".sql", ".zip", ".tar",
            "setup", "install", "configuration", "credentials"
        ]
        
        medium_priority_filters = [
            "user", "users", "account", "accounts", "profile", "profiles",
            "upload", "uploads", "download", "downloads", "file", "files",
            "includes", "include", "require", "requires", "lib", "libs"
        ]
        
        low_priority_filters = [
            "index", "home", "main", "default", "page", "pages",
            "css", "js", "javascript", "stylesheet", "image", "images",
            "img", "media", "video", "audio", "doc", "docs"
        ]
        
        for filter_term in high_priority_filters:
            if filter_term.lower() in url:
                return True
        
        if self.aggressive_mode:
            for filter_term in medium_priority_filters:
                if filter_term.lower() in url:
                    return True
        
        sensitive_extensions = [".php", ".asp", ".aspx", ".jsp", ".json", ".xml", ".config", ".yml", ".yaml", ".ini"]
        for ext in sensitive_extensions:
            if ext in url:
                return True
        
        sensitive_patterns = [
            r"/admin/.*\.php",
            r"/wp-admin/.*",
            r"/phpmyadmin/.*",
            r"/config/.*\.(php|conf|ini)",
            r"/backup/.*\.(sql|zip|tar)",
            r"/.*\.env",
            r"/.*\.bak",
            r"/.*\.old",
            r"/.*\.backup",
            r"/setup/.*",
            r"/install/.*",
            r"/test/.*",
            r"/debug/.*"
        ]
        
        for pattern in sensitive_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def _aggressive_analysis(self, domain: str):
        if not self.aggressive_mode:
            return {}
        analysis_results = {}
        subdomains = set()
        interesting_files = []
        sensitive_paths = []
        
        try:
            params = {
                "url": f"*.{domain}/*",
                "output": "json",
                "fl": "original",
                "collapse": "urlkey"
            }
            response = self.session.get(CDX_API_URL, params=params, timeout=self.timeout, verify=not self.bypass_protection)
            if response.status_code == 200:
                data = response.json()
                for row in data[1:]:
                    url = row[0]
                    parsed = urlparse(url)
                    if parsed.hostname and parsed.hostname != domain:
                        subdomains.add(parsed.hostname)
                    
                    if any(ext in url for ext in [".env", ".bak", ".old", ".backup", ".sql", ".zip", ".tar", ".conf", ".ini"]):
                        interesting_files.append(url)
                    
                    if any(path in url for path in ["/admin/", "/wp-admin/", "/phpmyadmin/", "/config/", "/backup/", "/setup/", "/install/"]):
                        sensitive_paths.append(url)
            
            analysis_results["subdomains"] = list(subdomains)[:20]
            analysis_results["interesting_files"] = interesting_files[:15]
            analysis_results["sensitive_paths"] = sensitive_paths[:15]
        except Exception as e:
            if self.debug:
                print(f"[WAYBACK] Aggressive analysis failed: {e}")
        
        return analysis_results
    
    def scan(self) -> Dict[str, Any]:
        domain = self.normalize_domain(self.target)
        if self.debug:
            print(f"[WAYBACK] Scanning domain: {domain}")
        
        cdx_data = self.fetch_cdx_data(domain)
        if not cdx_data or not isinstance(cdx_data, list) or len(cdx_data) <= 1:
            return {
                "ok": True,
                "risk": "low",
                "evidence": {
                    "domain": domain,
                    "count": 0,
                    "urls": [],
                    "stats": {},
                    "analysis": {}
                },
                "notes": "No historical data available for this domain in Wayback Machine"
            }
        
        evidence = self.process_urls(cdx_data)
        analysis = self._aggressive_analysis(domain)
        evidence["analysis"] = analysis
        
        risk_level = "low"
        vulnerability_indicators = 0
        
        if evidence["count"] > 0:
            high_priority_urls = [
                url for url in evidence["urls"]
                if any(term in url["url"].lower() for term in ["admin", "login", "config", "backup", "sql", "database", "password", "secret", "key", "token"])
            ]
            
            if high_priority_urls:
                vulnerability_indicators += 2
                risk_level = "high"
            elif evidence["count"] > 20:
                vulnerability_indicators += 1
                risk_level = "medium"
        
        if analysis.get("interesting_files"):
            vulnerability_indicators += 2
            risk_level = "high"
        
        if analysis.get("sensitive_paths"):
            vulnerability_indicators += 2
            risk_level = "high"
        
        if vulnerability_indicators == 0:
            risk_level = "low"
        
        notes = f"Found {evidence['count']} historical URLs from Wayback Machine"
        if analysis:
            notes += f" | {len(analysis.get('subdomains', []))} subdomains found"
            if analysis.get('interesting_files'):
                notes += f" | {len(analysis.get('interesting_files'))} potentially sensitive files found"
            if analysis.get('sensitive_paths'):
                notes += f" | {len(analysis.get('sensitive_paths'))} potentially sensitive paths found"
        
        return {
            "ok": True,
            "risk": risk_level,
            "evidence": evidence,
            "notes": notes
        }

Scanner = WaybackScanner
