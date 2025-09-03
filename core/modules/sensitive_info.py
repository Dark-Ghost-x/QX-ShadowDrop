#!/usr/bin/env python3
import re
import requests
import random
import ssl
import time
from typing import Dict, List, Any
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from .vulnerability_base import VulnerabilityModule
import settings

class SensitiveDataScanner(VulnerabilityModule):
    name = "sensitive_info_leak"
    description = "Advanced sensitive information detection scanner with aggressive testing"
    risk = "high"
    useproxy = getattr(settings, "USEPROXY", True)
    enabled = True
    max_sample_display = 3
    max_sample_length = 15
    scan_depth = 2
    timeout = getattr(settings, "TIMEOUT", 10)
    aggressive_mode = False
    bypass_protection = False
    custom_patterns = []
    
    PUBLIC_EMAIL_DOMAINS = [
        'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com', 'icloud.com',
        'mail.com', 'zoho.com', 'yandex.com', 'protonmail.com', 'gmx.com', 'live.com'
    ]
    
    BASE_PATTERNS = {
        "email": {
            "pattern": r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
            "validator": lambda x: len(x.split('@')[0]) >= 3 and '.' in x.split('@')[1] and len(x.split('@')[1]) >= 3
        },
        "api_key": {
            "pattern": r"(?i)(api[_-]?key|apikey)[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z]{16,45}[\"']",
            "validator": lambda x: sum(c.isupper() for c in x) >= 2 and sum(c.isdigit() for c in x) >= 3 and len(x) >= 16
        },
        "aws_key": {
            "pattern": r"(AKIA|ASIA)[0-9A-Z]{16}",
            "validator": lambda x: x.startswith(('AKIA', 'ASIA')) and len(x) == 20
        },
        "private_key": {
            "pattern": r"-----BEGIN (RSA|DSA|EC|PGP|OPENSSH) PRIVATE KEY-----",
            "validator": lambda x: "END" in x and "KEY" in x and len(x) > 100
        },
        "jwt_token": {
            "pattern": r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+",
            "validator": lambda x: x.count('.') == 2 and len(x) > 30 and len(x.split('.')[0]) > 10
        },
        "credit_card": {
            "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b",
            "validator": lambda number: SensitiveDataScanner._validate_credit_card(number)
        },
        "auth_token": {
            "pattern": r"(?i)(token|auth|session)[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z\-_]{24,}[\"']",
            "validator": lambda x: len(x) >= 24 and sum(c.isalnum() for c in x) >= 20
        },
        "database_connection": {
            "pattern": r"(?i)(mysql|postgresql|mongodb|redis)://[a-zA-Z0-9_]+:[^@]+@[a-zA-Z0-9.-]+:[0-9]+/[a-zA-Z0-9_]+",
            "validator": lambda x: "://" in x and "@" in x and ":" in x.split('@')[1] and len(x.split('@')[0].split(':')[0]) > 0
        },
        "ssh_key": {
            "pattern": r"ssh-(rsa|dss|ed25519) AAAA[0-9A-Za-z+/]+[=]{0,3}",
            "validator": lambda x: x.startswith(('ssh-rsa', 'ssh-dss', 'ssh-ed25519')) and len(x) > 100
        },
        "password": {
            "pattern": r"(?i)(password|passwd|pwd)[\"']?\s*[:=]\s*[\"'][^\"']{8,}[\"']",
            "validator": lambda x: len(x) >= 8 and any(c.isdigit() for c in x) and any(c.isalpha() for c in x)
        }
    }
    EXTRA_NORMAL = {
        "internal_ip": {
            "pattern": r"\b(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)\d{1,3}\.\d{1,3}\b",
            "validator": lambda x: all(0 <= int(part) <= 255 for part in x.split('.'))
        },
        "api_endpoint": {
            "pattern": r"(?i)(api|v[0-9])\.(example|test|local|dev)\.[a-z]{2,}",
            "validator": lambda x: any(domain in x for domain in ['.test.', '.local.', '.dev.'])
        },
        "access_key": {
            "pattern": r"(?i)access[_-]?key[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z]{16,}[\"']",
            "validator": lambda x: len(x) >= 16 and sum(c.isupper() for c in x) >= 2
        },
        "secret_key": {
            "pattern": r"(?i)secret[_-]?key[\"']?\s*[:=]\s*[\"'][0-9a-zA-Z]{16,}[\"']",
            "validator": lambda x: len(x) >= 16 and sum(c.isupper() for c in x) >= 2
        },
        "config_url": {
            "pattern": r"(?i)(config|setting)[\"']?\s*[:=]\s*[\"'][^\"']*\.(json|yml|yaml|xml|ini)[\"']",
            "validator": lambda x: any(ext in x for ext in ['.json', '.yml', '.yaml', '.xml', '.ini'])
        }
    }
    EXTRA_AGGRESSIVE = {
        "azure_key": {
            "pattern": r"[\"']?([a-zA-Z0-9+/]{43})[\"']?",
            "validator": lambda x: len(x) == 43 and x.isalnum() and x.endswith('=') and any(c.isupper() for c in x) and any(c.isdigit() for c in x)
        },
        "google_key": {
            "pattern": r"AIza[0-9A-Za-z\-_]{35}",
            "validator": lambda x: x.startswith('AIza') and len(x) == 39
        },
        "facebook_token": {
            "pattern": r"EAACEdEose0cBA[0-9A-Za-z]+",
            "validator": lambda x: x.startswith('EAAC') and len(x) > 50 and len(x) < 200
        },
        "twitter_token": {
            "pattern": r"[tT][wW][iI][tT][tT][eE][rR][\"']?\s*[:=]\s*[\"'][0-9a-zA-Z\-_]{35,}[\"']",
            "validator": lambda x: len(x) >= 35 and 'twitter' in x.lower()
        },
        "linkedin_token": {
            "pattern": r"[lL][iI][nN][kK][eE][dD][iI][nN][\"']?\s*[:=]\s*[\"'][0-9a-zA-Z\-_]{20,}[\"']",
            "validator": lambda x: len(x) >= 20 and 'linkedin' in x.lower()
        }
    }
    
    def __init__(self, *args, **kwargs):
        target = None
        session = None
        timeout = 10
        debug = False
        aggressive = False
        custom_patterns = None
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
        if 'custom_patterns' in kwargs:
            custom_patterns = kwargs['custom_patterns']
        if 'bypass_protection' in kwargs:
            bypass_protection = kwargs['bypass_protection']
        if 'stealth' in kwargs:
            stealth = kwargs['stealth']
            
        if session is None:
            session = requests.Session()
            
        super().__init__(target, session, timeout, debug)
        
        self.aggressive_mode = aggressive
        self.bypass_protection = bypass_protection
        self.custom_patterns = custom_patterns if custom_patterns else []
        self._visited_urls = set()
        self.PATTERNS = self.BASE_PATTERNS.copy()
        
        if stealth is not None:
            self.bypass_protection = stealth
        
        if self.aggressive_mode:
            self.PATTERNS.update(self.EXTRA_AGGRESSIVE)
            self.scan_depth = 3
            self.max_sample_display = 5
        else:
            self.PATTERNS.update(self.EXTRA_NORMAL)
            
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
                'Accept': 'text/html,application/xhtml+xml,application/json',
                'Accept-Language': 'en-US,en',
                'Connection': 'close'
            })
            
        self._compiled_patterns = {
            k: re.compile(v['pattern'])
            for k, v in self.PATTERNS.items()
        }
        
        for custom_pattern in self.custom_patterns:
            if 'name' in custom_pattern and 'pattern' in custom_pattern:
                try:
                    self._compiled_patterns[custom_pattern['name']] = re.compile(custom_pattern['pattern'])
                except re.error:
                    if self.debug:
                        print(f"Invalid custom pattern: {custom_pattern['pattern']}")
    
    @staticmethod
    def _validate_credit_card(number: str) -> bool:
        num = ''.join(filter(str.isdigit, number))
        if len(num) < 13 or len(num) > 19:
            return False
        
        valid_prefixes = ['4', '5', '3', '6', '2']
        if num[0] not in valid_prefixes:
            return False
            
        total = 0
        reverse_digits = num[::-1]
        for i, digit_char in enumerate(reverse_digits):
            digit = int(digit_char)
            if i % 2 == 1:
                digit = digit * 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0
    
    def _sanitize_sample(self, match: str) -> str:
        match = match.strip()
        if len(match) <= 8:
            return "*****"
        return match[:2] + "*****" + match[-2:]
    
    def _validate_finding(self, pattern_type: str, match: str) -> bool:
        if pattern_type == "credit_card":
            return self._validate_credit_card(match)
        
        if pattern_type == "email":
            domain = match.split('@')[1].lower()
            if domain in self.PUBLIC_EMAIL_DOMAINS:
                return False
        
        validator = self.PATTERNS.get(pattern_type, {}).get('validator')
        if validator:
            try:
                return validator(match)
            except:
                return False
        return True
    
    def _scan_content(self, content: str, base_url: str) -> List[Dict[str, Any]]:
        findings = []
        for pattern_type, regex in self._compiled_patterns.items():
            try:
                matches = regex.findall(content)
                valid_matches = []
                
                if len(matches) > 20:
                    continue
                    
                for match in matches:
                    match_str = match[0] if isinstance(match, tuple) else match
                    
                    if pattern_type == "azure_key":
                        if any(word in match_str.lower() for word in ['div', 'span', 'class', 'style', 'html', 'http', 'https', 'php', 'js', 'css']):
                            continue
                        if len(match_str) != 43 or not match_str.endswith('='):
                            continue
                    
                    if pattern_type == "credit_card":
                        if not re.match(r'^(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3[0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})$', match_str):
                            continue
                    
                    if self._validate_finding(pattern_type, match_str):
                        sanitized = self._sanitize_sample(match_str)
                        valid_matches.append(sanitized)
                        if len(valid_matches) >= self.max_sample_display:
                            break
                            
                if valid_matches:
                    findings.append({
                        "type": pattern_type,
                        "count": len(matches),
                        "samples": valid_matches,
                        "source": base_url
                    })
            except Exception as e:
                if self.debug:
                    print(f"Pattern {pattern_type} error: {e}")
                continue
        return findings
    
    def _crawl_links(self, html: str, base_url: str) -> List[str]:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            links = set()
            domain = urlparse(base_url).netloc
            for tag in soup.find_all(['a', 'link'], href=True):
                try:
                    url = tag['href']
                    if url.startswith(('javascript:', 'mailto:', 'tel:')):
                        continue
                    parsed = urlparse(url)
                    if not parsed.netloc or parsed.netloc == domain:
                        full_url = url if parsed.netloc else urljoin(base_url, url)
                        if full_url not in self._visited_urls:
                            links.add(full_url)
                except:
                    continue
            return list(links)[:10]
        except:
            return []
    
    def _aggressive_scan_paths(self, base_url: str) -> List[str]:
        aggressive_paths = [
            "/.env", "/.git/config", "/.htaccess", "/config/database.yml",
            "/wp-config.php", "/app/etc/local.xml", "/web.config",
            "/admin/config.yml", "/application/config/database.php",
            "/.DS_Store", "/.aws/credentials", "/.npmrc", "/.dockercfg",
            "/robots.txt", "/sitemap.xml", "/crossdomain.xml", "/phpinfo.php",
            "/info.php", "/server-status", "/debug", "/console",
            "/api/docs", "/swagger.json", "/graphql", "/.well-known/security.txt"
        ]
        if self.aggressive_mode:
            aggressive_paths.extend([
                "/.env.backup", "/.env.bak", "/.env.save", "/.env.old", "/.env.production",
                "/config.json", "/config.ini", "/config.php", "/config.yml", "/config.yaml",
                "/settings.json", "/settings.ini", "/settings.php", "/settings.yml", "/settings.yaml",
                "/backup/config.json", "/backup/config.ini", "/backup/config.php", "/backup/config.yml",
                "/backup/settings.json", "/backup/settings.ini", "/backup/settings.php", "/backup/settings.yml",
                "/admin/config.json", "/admin/config.ini", "/admin/config.php", "/admin/config.yml",
                "/api/config", "/api/settings", "/api/credentials", "/api/key", "/api/token",
                "/v1/config", "/v1/settings", "/v1/credentials", "/v1/key", "/v1/token",
                "/v2/config", "/v2/settings", "/v2/credentials", "/v2/key", "/v2/token",
                "/internal/config", "/internal/settings", "/internal/credentials", "/internal/key", "/internal/token",
                "/secure/config", "/secure/settings", "/secure/credentials", "/secure/key", "/secure/token",
                "/private/config", "/private/settings", "/private/credentials", "/private/key", "/private/token",
                "/secret/config", "/secret/settings", "/secret/credentials", "/secret/key", "/secret/token",
                "/auth/config", "/auth/settings", "/auth/credentials", "/auth/key", "/auth/token",
                "/login/config", "/login/settings", "/login/credentials", "/login/key", "/login/token",
                "/account/config", "/account/settings", "/account/credentials", "/account/key", "/account/token",
                "/user/config", "/user/settings", "/user/credentials", "/user/key", "/user/token",
                "/db/config", "/db/settings", "/db/credentials", "/db/key", "/db/token",
                "/database/config", "/database/settings", "/database/credentials", "/database/key", "/database/token",
                "/mysql/config", "/mysql/settings", "/mysql/credentials", "/mysql/key", "/mysql/token",
                "/postgres/config", "/postgres/settings", "/postgres/credentials", "/postgres/key", "/postgres/token",
                "/mongodb/config", "/mongodb/settings", "/mongodb/credentials", "/mongodb/key", "/mongodb/token",
                "/redis/config", "/redis/settings", "/redis/credentials", "/redis/key", "/redis/token",
                "/aws/config", "/aws/settings", "/aws/credentials", "/aws/key", "/aws/token",
                "/azure/config", "/azure/settings", "/azure/credentials", "/azure/key", "/azure/token",
                "/google/config", "/google/settings", "/google/credentials", "/google/key", "/google/token",
                "/facebook/config", "/facebook/settings", "/facebook/credentials", "/facebook/key", "/facebook/token",
                "/twitter/config", "/twitter/settings", "/twitter/credentials", "/twitter/key", "/twitter/token",
                "/github/config", "/github/settings", "/github/credentials", "/github/key", "/github/token",
                "/gitlab/config", "/gitlab/settings", "/gitlab/credentials", "/gitlab/key", "/gitlab/token",
                "/bitbucket/config", "/bitbucket/settings", "/bitbucket/credentials", "/bitbucket/key", "/bitbucket/token",
                "/docker/config", "/docker/settings", "/docker/credentials", "/docker/key", "/docker/token",
                "/k8s/config", "/k8s/settings", "/k8s/credentials", "/k8s/key", "/k8s/token",
                "/kubernetes/config", "/kubernetes/settings", "/kubernetes/credentials", "/kubernetes/key", "/kubernetes/token"
            ])
        else:
            aggressive_paths.extend([
                "/.env.backup", "/.env.bak", "/.env.save", "/.env.old",
                "/config.json", "/config.ini", "/config.php", "/config.yml",
                "/settings.json", "/settings.ini", "/settings.php", "/settings.yml",
                "/backup/config.json", "/backup/config.ini", "/backup/config.php",
                "/admin/config.json", "/admin/config.ini", "/admin/config.php",
                "/api/config", "/api/settings", "/api/credentials",
                "/v1/config", "/v1/settings", "/v1/credentials",
                "/internal/config", "/internal/settings", "/internal/credentials",
                "/secure/config", "/secure/settings", "/secure/credentials",
                "/private/config", "/private/settings", "/private/credentials",
                "/secret/config", "/secret/settings", "/secret/credentials",
                "/auth/config", "/auth/settings", "/auth/credentials",
                "/login/config", "/login/settings", "/login/credentials",
                "/account/config", "/account/settings", "/account/credentials",
                "/user/config", "/user/settings", "/user/credentials",
                "/db/config", "/db/settings", "/db/credentials",
                "/database/config", "/database/settings", "/database/credentials"
            ])
        test_urls = []
        for path in aggressive_paths:
            test_urls.append(urljoin(base_url, path))
        return test_urls
    
    def _deep_scan(self, url: str, depth: int = 0) -> List[Dict[str, Any]]:
        if depth > self.scan_depth or url in self._visited_urls:
            return []
        self._visited_urls.add(url)
        findings = []
        try:
            time.sleep(0.5)
            
            if self.debug:
                print(f"[SENSITIVE-DATA] Scanning URL: {url} (depth: {depth})")
            
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
                verify=not self.bypass_protection
            )
            
            if self.debug:
                print(f"[SENSITIVE-DATA] Response status: {response.status_code}")
            
            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '').lower()
                if 'text/html' in content_type:
                    content_findings = self._scan_content(response.text, url)
                    if content_findings:
                        findings.extend(content_findings)
                    
                    if depth < self.scan_depth:
                        links = self._crawl_links(response.text, url)
                        if self.debug:
                            print(f"[SENSITIVE-DATA] Found {len(links)} links to crawl")
                        for link in links:
                            findings.extend(self._deep_scan(link, depth + 1))
                elif any(x in content_type for x in ['text/', 'application/json', 'application/xml']):
                    content_findings = self._scan_content(response.text, url)
                    if content_findings:
                        findings.extend(content_findings)
            
            if depth == 0:
                aggressive_urls = self._aggressive_scan_paths(url)
                if self.debug:
                    print(f"[SENSITIVE-DATA] Testing {len(aggressive_urls)} aggressive paths")
                for test_url in aggressive_urls:
                    if test_url not in self._visited_urls:
                        try:
                            agg_response = self.session.get(test_url, timeout=5, verify=not self.bypass_protection)
                            if agg_response.status_code == 200:
                                content_findings = self._scan_content(agg_response.text, test_url)
                                if content_findings:
                                    findings.extend(content_findings)
                        except Exception as e:
                            if self.debug:
                                print(f"[SENSITIVE-DATA] Error testing {test_url}: {e}")
                            continue
        except Exception as e:
            if self.debug:
                print(f"[SENSITIVE-DATA] Scan error for {url}: {e}")
        return findings
    
    def scan(self) -> Dict[str, Any]:
        try:
            if self.debug:
                print(f"[SENSITIVE-DATA] Starting scan for {self.target}")
                print(f"[SENSITIVE-DATA] Aggressive mode: {self.aggressive_mode}")
                print(f"[SENSITIVE-DATA] Bypass protection: {self.bypass_protection}")
                print(f"[SENSITIVE-DATA] Scan depth: {self.scan_depth}")
            
            time.sleep(1)
            
            main_findings = self._deep_scan(self.target)
            
            if self.debug:
                print(f"[SENSITIVE-DATA] Scan completed. Found {len(main_findings)} findings")
            
            critical_count = sum(1 for f in main_findings if f['type'] in ['aws_key', 'private_key', 'database_connection', 'credit_card'])
            high_count = sum(1 for f in main_findings if f['type'] in ['api_key', 'auth_token', 'jwt_token', 'password'])
            risk = "critical" if critical_count > 0 else \
                   "high" if high_count > 0 else \
                   "medium" if main_findings else "low"
            
            stats = {
                "pages_scanned": len(self._visited_urls),
                "patterns_found": len(main_findings),
                "total_matches": sum(f['count'] for f in main_findings),
                "critical_findings": critical_count,
                "high_findings": high_count
            }
            
            return {
                "ok": True,
                "risk": risk,
                "evidence": main_findings,
                "stats": stats,
                "notes": f"Scanned {len(self._visited_urls)} resources. Found {len(main_findings)} pattern types."
            }
        except Exception as e:
            if self.debug:
                print(f"[SENSITIVE-DATA] Scan failed: {e}")
            return {
                "ok": False,
                "risk": "low",
                "evidence": [],
                "notes": f"Scan failed: {str(e)}"
            }

Scanner = SensitiveDataScanner
