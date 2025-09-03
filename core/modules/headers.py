#!/usr/bin/env python3
import requests
import random
import ssl
import time
import re
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urlparse
from .vulnerability_base import VulnerabilityModule
import settings
from requests.exceptions import ProxyError, ConnectTimeout, ReadTimeout, RequestException
SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
    "x-xss-protection",
    "x-permitted-cross-domain-policies",
    "expect-ct",
    "feature-policy"
]
SECURITY_HEADER_STANDARDS = {
    "content-security-policy": {"required": True, "risk": "high"},
    "x-frame-options": {"required": True, "risk": "high"},
    "strict-transport-security": {"required": True, "risk": "high"},
    "x-content-type-options": {"required": True, "risk": "medium"},
    "referrer-policy": {"required": False, "risk": "medium"},
    "permissions-policy": {"required": False, "risk": "medium"},
    "x-xss-protection": {"required": False, "risk": "low"},
    "x-permitted-cross-domain-policies": {"required": False, "risk": "low"},
    "expect-ct": {"required": False, "risk": "low"},
    "feature-policy": {"required": False, "risk": "low"}
}
ALTERNATIVE_HEADER_NAMES = {
    "x-frame-options": ["x-frame"],
    "content-security-policy": ["csp", "content-security"],
    "strict-transport-security": ["hsts", "sts"],
    "x-content-type-options": ["x-content-type"],
    "referrer-policy": ["referrer"]
}
HEADER_BYPASS_PAYLOADS = {
    "x-frame-options": ["ALLOW-FROM https://evil.com", "SAMEORIGIN", "DENY"],
    "content-security-policy": ["default-src *", "script-src *", "unsafe-inline", "unsafe-eval"],
    "access-control-allow-origin": ["*", "null"]
}
HEADER_INJECTION_PAYLOADS = [
    "X-Forwarded-Host: evil.com",
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /wp-admin",
    "X-Custom-IP-Authorization: 127.0.0.1",
    "X-Forwarded-Server: attacker.com",
    "X-Forwarded-Proto: https",
    "X-Real-IP: 127.0.0.1",
    "X-Client-IP: 127.0.0.1",
    "X-Host: evil.com",
    "X-Forwarded-For: 127.0.0.1",
    "Referer: https://evil.com",
    "Origin: https://evil.com",
    "Host: evil.com"
]
AGGRESSIVE_HEADER_PAYLOADS = [
    "X-Forwarded-Host: {target}.evil.com",
    "X-Forwarded-Server: {target}.attacker.com",
    "X-Forwarded-Proto: https",
    "X-Real-IP: 127.0.0.1",
    "X-Client-IP: 127.0.0.1",
    "X-Host: {target}.evil.com",
    "X-Forwarded-For: 127.0.0.1",
    "X-Original-URL: /admin",
    "X-Rewrite-URL: /wp-admin",
    "X-Custom-IP-Authorization: 127.0.0.1",
    "Referer: https://evil.com/{target}",
    "Origin: https://evil.com",
    "Host: {target}.evil.com",
    "X-Proxy-URL: /admin",
    "X-Remote-Addr: 127.0.0.1",
    "X-Remote-IP: 127.0.0.1",
    "X-Originating-IP: 127.0.0.1",
    "X-Remote-Host: localhost",
    "X-Client-IP: 127.0.0.1",
    "X-Host: evil.com",
    "X-Forwarded-Host: evil.com",
    "X-Forwarded-Server: evil.com",
    "X-Forwarded-For: 127.0.0.1",
    "True-Client-IP: 127.0.0.1",
    "X-Cluster-Client-IP: 127.0.0.1",
    "X-Api-Version: 1.0",
    "X-Request-ID: 12345",
    "X-Correlation-ID: 67890",
    "X-Requested-With: XMLHttpRequest",
    "X-CSRF-Token: bypass",
    "X-XSRF-Token: bypass",
    "X-CSRF-Key: bypass123",
    "X-Auth-Token: admin",
    "Authorization: Bearer bypass_token",
    "X-API-Key: admin123",
    "X-Api-Key: admin123",
    "X-Application-Key: app123",
    "X-Secret-Key: secret123",
    "X-Access-Key: access123",
    "X-Admin: true",
    "X-User: admin",
    "X-Role: administrator",
    "X-Privilege: superuser",
    "X-Permission: all",
    "X-Forwarded-Port: 443",
    "X-Forwarded-Scheme: https",
    "X-Url-Scheme: https",
    "X-Forwarded-Path: /admin",
    "X-Original-Path: /admin",
    "X-Rewrite-Path: /wp-admin",
    "X-Service: admin",
    "X-Endpoint: /api/admin",
    "X-Action: delete",
    "X-Command: execute",
    "X-Operation: privileged",
    "X-Method: POST",
    "X-HTTP-Method: POST",
    "X-HTMP-Method-Override: POST",
    "X-Method-Override: POST",
    "X-Request-Method: POST",
    "X-Http-Method-Override: POST",
    "X-Http-Request-Method: POST",
    "X-Proxy-Method: POST",
    "X-Forwarded-Method: POST",
    "X-Original-Method: POST",
    "X-Remote-Method: POST",
    "X-Action-Method: POST",
    "X-Operation-Method: POST",
    "X-Service-Method: POST",
    "X-Endpoint-Method: POST",
    "X-API-Method: POST",
    "X-Resource-Method: POST",
    "X-Object-Method: POST",
    "X-Entity-Method: POST",
    "X-Data-Method: POST",
    "X-Content-Method: POST",
    "X-Payload-Method: POST",
    "X-Body-Method: POST",
    "X-Form-Method: POST",
    "X-Query-Method: POST",
    "X-Parameter-Method: POST",
    "X-Input-Method: POST",
    "X-Output-Method: POST",
    "X-Result-Method: POST",
    "X-Response-Method: POST",
    "X-Status-Method: POST",
    "X-Code-Method: POST",
    "X-Error-Method: POST",
    "X-Exception-Method: POST",
    "X-Debug-Method: POST",
    "X-Log-Method: POST",
    "X-Trace-Method: POST",
    "X-Monitor-Method: POST",
    "X-Audit-Method: POST",
    "X-Security-Method: POST",
    "X-Auth-Method: POST",
    "X-Login-Method: POST",
    "X-Session-Method: POST",
    "X-Token-Method: POST",
    "X-Key-Method: POST",
    "X-Certificate-Method: POST",
    "X-Signature-Method: POST",
    "X-Hash-Method: POST",
    "X-Encryption-Method: POST",
    "X-Decryption-Method: POST",
    "X-Encoding-Method: POST",
    "X-Compression-Method: POST",
    "X-Decompression-Method: POST",
    "X-Transfer-Method: POST",
    "X-Transport-Method: POST",
    "X-Protocol-Method: POST",
    "X-Network-Method: POST",
    "X-Connection-Method: POST",
    "X-Socket-Method: POST",
    "X-Port-Method: POST",
    "X-Address-Method: POST",
    "X-Host-Method: POST",
    "X-Domain-Method: POST",
    "X-URL-Method: POST",
    "X-URI-Method: POST",
    "X-Path-Method: POST",
    "X-Query-String-Method: POST",
    "X-Fragment-Method: POST",
    "X-Scheme-Method: POST",
    "X-Protocol-Version: HTTP/2.0",
    "X-HTTP-Version: 2.0",
    "X-API-Version: 2.0",
    "X-Version: 2.0",
    "X-Release: latest",
    "X-Build: 123",
    "X-Revision: 456",
    "X-Commit: abcdef",
    "X-Branch: master",
    "X-Environment: production",
    "X-Deployment: prod",
    "X-Stage: production",
    "X-Phase: live",
    "X-Mode: production",
    "X-Config: production",
    "X-Settings: production",
    "X-Options: privileged",
    "X-Features: all",
    "X-Capabilities: full",
    "X-Permissions: all",
    "X-Rights: administrator",
    "X-Privileges: superuser",
    "X-Access: full",
    "X-Control: complete",
    "X-Management: full",
    "X-Administration: enabled",
    "X-Superuser: true",
    "X-Root: true",
    "X-System: true",
    "X-Kernel: true",
    "X-Core: true",
    "X-Internal: true",
    "X-Local: true",
    "X-Private: true",
    "X-Protected: true",
    "X-Secret: true",
    "X-Confidential: true",
    "X-Sensitive: true",
    "X-Classified: true",
    "X-Restricted: true",
    "X-Limited: true",
    "X-Exclusive: true",
    "X-Premium: true",
    "X-Enterprise: true",
    "X-Professional: true",
    "X-Advanced: true",
    "X-Elite: true",
    "X-Ultimate: true",
    "X-Extreme: true",
    "X-Maximum: true",
    "X-Full: true",
    "X-Complete: true",
    "X-Total: true",
    "X-Absolute: true",
    "X-Ultimate: true",
    "X-Final: true",
    "X-Last: true",
    "X-End: true",
    "X-Finish: true",
    "X-Complete: true",
    "X-Done: true",
    "X-Ready: true",
    "X-Set: true",
    "X-Go: true",
    "X-Start: true",
    "X-Begin: true",
    "X-Init: true",
    "X-Create: true",
    "X-New: true",
    "X-Add: true",
    "X-Insert: true",
    "X-Update: true",
    "X-Edit: true",
    "X-Modify: true",
    "X-Change: true",
    "X-Delete: true",
    "X-Remove: true",
    "X-Drop: true",
    "X-Truncate: true",
    "X-Alter: true",
    "X-Adjust: true",
    "X-Fix: true",
    "X-Repair: true",
    "X-Recover: true",
    "X-Restore: true",
    "X-Reset: true",
    "X-Reboot: true",
    "X-Restart: true",
    "X-Reload: true",
    "X-Refresh: true"
]
ERROR_SIGNATURES = {
    "unix": ["sh: 1:", "/bin/sh:", "bash:", "zsh:", "fish:", "syntax error",
             "unexpected token", "cannot execute", "permission denied",
             "no such file or directory", "command not found", "unexpected EOF"],
    "windows": ["is not recognized as an internal or external command",
                "the system cannot find the path specified", "cmd.exe",
                "powershell", "term not recognized", "was unexpected at this time"],
    "database": ["sql syntax", "mysql_fetch_array", "postgresql", "ora-", "pl/sql"]
}
class Scanner(VulnerabilityModule):
    name = "security_headers"
    description = "Advanced security headers analysis with bypass testing"
    risk = "low"
    useproxy = getattr(settings, "USEPROXY", False)
    enabled = True
    aggressive_mode = False
    bypass_protection = False
    custom_headers = []
    def __init__(self, target, session=None, timeout=15, debug=False, verbose=False,
                 proxy=None, aggressive=False, stealth=False, custom_payloads=None,
                 bypass_protection=False, custom_headers=None, **kwargs):
        super().__init__(target, session=session, timeout=timeout, debug=debug, verbose=verbose,
                        proxy=proxy, aggressive=aggressive, stealth=stealth,
                        custom_payloads=custom_payloads, bypass_protection=bypass_protection, **kwargs)
        self.aggressive_mode = aggressive
        self.bypass_protection = bypass_protection
        self.custom_headers = custom_headers if custom_headers else []
        self.stealth = stealth
        self.original_timeout = timeout
        self.timeout = timeout
        
        if self.aggressive_mode:
            self.timeout = 30
        
        if self.bypass_protection:
            self.session.verify = False
            ssl._create_default_https_context = ssl._create_unverified_context
            requests.packages.urllib3.disable_warnings()
        
        stealth_headers = {
            'User-Agent': random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
            ]),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        }
        
        current_headers = self.session.headers.copy()
        current_headers.update(stealth_headers)
        self.session.headers = current_headers
    def _clean_response_content(self, content: str) -> str:
        patterns_to_remove = [
            r'<script[^>]*>.*?</script>',
            r'<style[^>]*>.*?</style>',
            r'<!--.*?-->',
            r'<!\[CDATA\[.*?\]\]>',
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\d{2}/\d{2}/\d{4}',
            r'\d{2}:\d{2}:\d{2}',
            r'\b\d{10,}\b',
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
            r'csrf_token[^=]*=[^&]*',
            r'csrf-token[^=]*=[^&]*',
            r'csrf[^=]*=[^&]*',
            r'session[^=]*=[^&]*',
            r'sessionid[^=]*=[^&]*',
            r'phpsessid[^=]*=[^&]*',
            r'rand[^=]*=[^&]*',
            r'random[^=]*=[^&]*',
            r'token[^=]*=[^&]*',
            r'google_analytics[^;]*;',
            r'gtag[^;]*;',
            r'fbq[^;]*;'
        ]
        
        cleaned_content = content
        for pattern in patterns_to_remove:
            cleaned_content = re.sub(pattern, '', cleaned_content, flags=re.DOTALL | re.IGNORECASE)
        
        cleaned_content = re.sub(r'\s+', ' ', cleaned_content).strip()
        return cleaned_content
    def _calculate_content_similarity(self, content1: str, content2: str) -> float:
        words1 = set(content1.split())
        words2 = set(content2.split())
        
        if not words1 and not words2:
            return 1.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0
    def _check_significant_changes(self, response_content: str, baseline_content: str) -> bool:
        cleaned_response = self._clean_response_content(response_content).lower()
        cleaned_baseline = self._clean_response_content(baseline_content).lower()
        
        if cleaned_response == cleaned_baseline:
            return False
        
        error_indicators = ["error", "exception", "warning", "traceback", "stack trace", "fatal", "failure"]
        for indicator in error_indicators:
            if indicator in cleaned_response and indicator not in cleaned_baseline:
                return True
        
        length_diff = abs(len(response_content) - len(baseline_content))
        if length_diff > len(baseline_content) * 0.3:
            return True
        
        return False
    def _validate_vulnerability(self, test_result, baseline_content: str) -> bool:
        if not test_result.get('vulnerable', False):
            return False
        
        if test_result.get('error_type'):
            return True
        
        response_content = test_result.get('response_content', '')
        baseline_content = baseline_content
        
        length_diff = abs(len(response_content) - len(baseline_content))
        if length_diff > len(baseline_content) * 0.5:
            return True
        
        content_similarity = self._calculate_content_similarity(
            self._clean_response_content(response_content),
            self._clean_response_content(baseline_content)
        )
        
        has_significant_changes = self._check_significant_changes(response_content, baseline_content)
        
        return content_similarity < 0.6 and has_significant_changes
    def _analyze_boolean_test(self, response_content: str, baseline_content: str,
                             response_status: int, baseline_status: int) -> bool:
        clean_response = self._clean_response_content(response_content)
        clean_baseline = self._clean_response_content(baseline_content)
        
        if clean_response == clean_baseline:
            return False
            
        length_diff = abs(len(clean_response) - len(clean_baseline))
        if length_diff < 50:
            return False
            
        if response_status != baseline_status:
            return False
            
        error_detected, _ = self._analyze_error_based(response_content)
        if error_detected:
            return True
            
        content_diff_ratio = length_diff / max(len(clean_baseline), 1)
        if content_diff_ratio < 0.05:
            return False
            
        return True
    def _analyze_error_based(self, response_content: str) -> Tuple[bool, str]:
        content_lower = response_content.lower()
        
        for db_type, patterns in ERROR_SIGNATURES.items():
            for pattern in patterns:
                if pattern in content_lower:
                    return True, db_type
        
        return False, ""
    def _safe_get(self, url, headers=None, timeout=None, allow_redirects=True):
        timeout = timeout or self.timeout
        try:
            request_headers = self.session.headers.copy()
            if headers:
                request_headers.update(headers)
            
            response = self.session.get(
                url,
                timeout=timeout,
                verify=not self.bypass_protection,
                headers=request_headers,
                allow_redirects=allow_redirects
            )
            return response
        except (ProxyError, ConnectTimeout, ReadTimeout):
            try:
                fallback_session = requests.Session()
                fallback_headers = self.session.headers.copy()
                if headers:
                    fallback_headers.update(headers)
                fallback_session.headers.update(fallback_headers)
                
                return fallback_session.get(
                    url,
                    timeout=timeout,
                    verify=not self.bypass_protection,
                    allow_redirects=allow_redirects
                )
            except Exception:
                return None
        except RequestException:
            return None
    def _analyze_header_strength(self, header_name, header_value):
        analysis = {"strength": "strong", "vulnerabilities": []}
        header_value_lower = header_value.lower()
        
        if header_name == "x-frame-options":
            if header_value_lower in ["deny", "sameorigin"]:
                analysis["strength"] = "strong"
            elif "allow-from" in header_value_lower:
                analysis["strength"] = "weak"
                analysis["vulnerabilities"].append("X-Frame-Options with ALLOW-FROM can be bypassed")
            else:
                analysis["strength"] = "invalid"
                analysis["vulnerabilities"].append("Invalid X-Frame-Options value")
        
        elif header_name == "content-security-policy":
            unsafe_directives = ["unsafe-inline", "unsafe-eval", "*", "data:", "http:", "https:"]
            unsafe_found = [directive for directive in unsafe_directives if directive in header_value_lower]
            
            if unsafe_found:
                analysis["strength"] = "weak"
                analysis["vulnerabilities"].append(f"CSP contains unsafe directives: {', '.join(unsafe_found)}")
            
            if "'none'" not in header_value_lower and "default-src" not in header_value_lower:
                analysis["vulnerabilities"].append("Missing default-src directive in CSP")
            
            if "script-src" not in header_value_lower:
                analysis["vulnerabilities"].append("Missing script-src directive in CSP")
        
        elif header_name == "strict-transport-security":
            if "max-age=0" in header_value_lower:
                analysis["strength"] = "weak"
                analysis["vulnerabilities"].append("HSTS with max-age=0 is ineffective")
            elif "max-age=" not in header_value_lower:
                analysis["strength"] = "invalid"
                analysis["vulnerabilities"].append("HSTS missing max-age directive")
            else:
                max_age_match = re.search(r'max-age=(\d+)', header_value_lower)
                if max_age_match:
                    max_age_value = int(max_age_match.group(1))
                    if max_age_value < 15768000:
                        analysis["vulnerabilities"].append("HSTS max-age too short (less than 6 months)")
                
                if "includesubdomains" not in header_value_lower:
                    analysis["vulnerabilities"].append("HSTS missing includeSubDomains directive")
                elif "preload" not in header_value_lower:
                    analysis["vulnerabilities"].append("HSTS missing preload directive")
        
        elif header_name == "x-content-type-options":
            if header_value_lower != "nosniff":
                analysis["strength"] = "invalid"
                analysis["vulnerabilities"].append("Invalid X-Content-Type-Options value")
        
        elif header_name == "x-xss-protection":
            if "0" in header_value_lower:
                analysis["strength"] = "weak"
                analysis["vulnerabilities"].append("X-XSS-Protection disabled")
            elif "1; mode=block" not in header_value_lower:
                analysis["vulnerabilities"].append("X-XSS-Protection not configured with mode=block")
        
        return analysis
    def _test_header_bypass(self, original_headers, baseline_response):
        bypass_results = []
        baseline_content = baseline_response.text if baseline_response else ""
        
        if self.debug:
            print(f"[SECHEADERS] Running header bypass tests on {self.target}")
        
        for header_name, payloads in HEADER_BYPASS_PAYLOADS.items():
            for payload in payloads:
                try:
                    test_headers = {header_name: payload}
                    response = self._safe_get(self.target, test_headers, timeout=15)
                    
                    if response and response.status_code < 500:
                        test_headers_lower = {k.lower(): v for k, v in response.headers.items()}
                        
                        if header_name.lower() in test_headers_lower:
                            original_value = original_headers.get(header_name.lower(), "")
                            test_value = test_headers_lower[header_name.lower()]
                            
                            if test_value != original_value:
                                error_detected, error_type = self._analyze_error_based(response.text)
                                
                                test_result = {
                                    'vulnerable': True,
                                    'error_type': error_type if error_detected else None,
                                    'response_content': response.text
                                }
                                
                                is_vulnerable = self._validate_vulnerability(test_result, baseline_content)
                                
                                if is_vulnerable:
                                    bypass_results.append({
                                        "header": header_name,
                                        "injected_value": payload,
                                        "response_value": test_value,
                                        "bypassed": True,
                                        "status_code": response.status_code,
                                        "content_length": len(response.content)
                                    })
                except Exception as e:
                    if self.debug:
                        print(f"[SECHEADERS] Bypass test failed for {header_name}: {e}")
                    continue
        
        return bypass_results
    def _test_header_injection(self, baseline_response):
        injection_results = []
        baseline_content = baseline_response.text if baseline_response else ""
        
        if self.debug:
            print(f"[SECHEADERS] Running header injection tests on {self.target}")
        
        if self.aggressive_mode:
            test_headers = AGGRESSIVE_HEADER_PAYLOADS[:100] + self.custom_headers
        else:
            test_headers = HEADER_INJECTION_PAYLOADS[:30] + self.custom_headers
        
        target_domain = urlparse(self.target).netloc
        
        for header_line in test_headers:
            try:
                if ":" in header_line:
                    header_name, header_value = header_line.split(":", 1)
                    header_name = header_name.strip()
                    header_value = header_value.strip().replace("{target}", target_domain)
                    
                    test_headers_dict = {header_name: header_value}
                    response = self._safe_get(self.target, test_headers_dict, timeout=12)
                    
                    if response:
                        error_detected, error_type = self._analyze_error_based(response.text)
                        
                        test_result = {
                            'vulnerable': True,
                            'error_type': error_type if error_detected else None,
                            'response_content': response.text
                        }
                        
                        is_vulnerable = self._validate_vulnerability(test_result, baseline_content)
                        
                        if is_vulnerable:
                            injection_results.append({
                                "header": header_name,
                                "value": header_value,
                                "status_code": response.status_code,
                                "content_length": len(response.content),
                                "response_time": response.elapsed.total_seconds(),
                                "vulnerable": True,
                                "error_type": error_type if error_detected else None
                            })
            except Exception as e:
                if self.debug:
                    print(f"[SECHEADERS] Injection test failed for {header_line}: {e}")
                continue
        
        return injection_results
    def _test_host_header_injection(self, baseline_response):
        host_injection_results = []
        baseline_content = baseline_response.text if baseline_response else ""
        target_domain = urlparse(self.target).netloc
        
        if self.debug:
            print(f"[SECHEADERS] Running host header injection tests on {self.target}")
        
        host_payloads = [
            "evil.com",
            "localhost",
            "127.0.0.1",
            "localhost:8080",
            "127.0.0.1:8080",
            target_domain + ".evil.com",
            "attacker.com",
            "example.com"
        ]
        
        for host_value in host_payloads:
            try:
                test_headers = {"Host": host_value}
                response = self._safe_get(self.target, test_headers, timeout=12)
                
                if response:
                    error_detected, error_type = self._analyze_error_based(response.text)
                    
                    test_result = {
                        'vulnerable': True,
                        'error_type': error_type if error_detected else None,
                        'response_content': response.text
                    }
                    
                    is_vulnerable = self._validate_vulnerability(test_result, baseline_content)
                    
                    if is_vulnerable:
                        host_injection_results.append({
                            "header": "Host",
                            "value": host_value,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "response_time": response.elapsed.total_seconds(),
                            "vulnerable": True,
                            "error_type": error_type if error_detected else None
                        })
            except Exception as e:
                if self.debug:
                    print(f"[SECHEADERS] Host injection test failed for {host_value}: {e}")
                continue
        
        return host_injection_results
    def scan(self):
        if self.debug:
            print(f"[SECHEADERS] Scanning {self.target}")
            if self.aggressive_mode:
                print(f"[SECHEADERS] Aggressive mode enabled with timeout: {self.timeout}s")
        
        try:
            start_time = time.time()
            
            retries = 3
            baseline_response = None
            headers = {}
            
            for i in range(retries):
                try:
                    if self.debug:
                        print(f"[SECHEADERS] Attempt {i+1}/{retries} to get baseline response")
                    
                    initial_response = self._safe_get(self.target, timeout=self.timeout, allow_redirects=False)
                    
                    if initial_response:
                        if initial_response.is_redirect:
                            if self.debug:
                                print(f"[SECHEADERS] Redirect detected, following to final destination")
                            final_response = self._safe_get(self.target, timeout=self.timeout, allow_redirects=True)
                            headers = {**{k.lower(): v for k, v in initial_response.headers.items()},
                                      **{k.lower(): v for k, v in final_response.headers.items()}}
                            baseline_response = final_response
                        else:
                            headers = {k.lower(): v for k, v in initial_response.headers.items()}
                            baseline_response = initial_response
                    
                    if baseline_response:
                        if self.debug:
                            print(f"[SECHEADERS] Baseline response received with status: {baseline_response.status_code}")
                        break
                    else:
                        if self.debug:
                            print(f"[SECHEADERS] No response received in attempt {i+1}")
                        
                except Exception as e:
                    if i == retries - 1:
                        raise e
                    if self.debug:
                        print(f"[SECHEADERS] Attempt {i+1} failed: {e}")
                    time.sleep(1)
            
            scan_time = time.time() - start_time
            
            if not baseline_response:
                return {
                    "ok": False,
                    "risk": "low",
                    "evidence": [],
                    "notes": "Failed to get response from target after retries",
                    "status": "failed",
                    "module": self.name,
                    "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f")
                }
            
            for alt_name, standard_names in ALTERNATIVE_HEADER_NAMES.items():
                for header in headers:
                    if any(name in header.lower() for name in standard_names):
                        headers[alt_name] = headers[header]
                        if self.debug:
                            print(f"[SECHEADERS] Found alternative header {header} mapped to {alt_name}")
                        break
            
            present_headers = []
            missing_headers = []
            header_analysis = {}
            
            for header in SECURITY_HEADERS:
                if header in headers:
                    present_headers.append(header)
                    header_analysis[header] = self._analyze_header_strength(header, headers[header])
                    if self.debug:
                        print(f"[SECHEADERS] Found header {header}: {headers[header]}")
                else:
                    missing_headers.append(header)
                    header_analysis[header] = {"strength": "missing", "vulnerabilities": ["Header not present"]}
            
            bypass_results = []
            injection_results = []
            host_injection_results = []
            
            if self.aggressive_mode:
                if self.debug:
                    print(f"[SECHEADERS] Starting aggressive security tests")
                
                aggressive_start = time.time()
                bypass_results = self._test_header_bypass(headers, baseline_response)
                injection_results = self._test_header_injection(baseline_response)
                host_injection_results = self._test_host_header_injection(baseline_response)
                aggressive_time = time.time() - aggressive_start
                
                if self.debug:
                    print(f"[SECHEADERS] Aggressive tests completed in {aggressive_time:.2f}s")
                    print(f"[SECHEADERS] Bypass results: {len(bypass_results)}")
                    print(f"[SECHEADERS] Injection results: {len(injection_results)}")
                    print(f"[SECHEADERS] Host injection results: {len(host_injection_results)}")
            
            risk_score = 0
            
            for header, analysis in header_analysis.items():
                if analysis["strength"] == "missing":
                    if SECURITY_HEADER_STANDARDS[header]["required"]:
                        risk_score += 3
                    else:
                        risk_score += 1
                elif analysis["strength"] in ["weak", "invalid"]:
                    risk_score += 2
            
            confirmed_vulnerabilities = (
                len([r for r in bypass_results if r.get("bypassed", False)]) +
                len([r for r in injection_results if r.get("vulnerable", False)]) +
                len([r for r in host_injection_results if r.get("vulnerable", False)])
            )
            
            if confirmed_vulnerabilities > 0:
                risk_score += confirmed_vulnerabilities * 3
            
            if risk_score >= 15:
                risk_level = "critical"
            elif risk_score >= 10:
                risk_level = "high"
            elif risk_score >= 5:
                risk_level = "medium"
            else:
                risk_level = "low"
            
            evidence = {
                "present_headers": present_headers,
                "missing_headers": missing_headers,
                "header_analysis": header_analysis,
                "all_headers": headers,
                "bypass_attempts": bypass_results,
                "header_injection_tests": injection_results,
                "host_header_tests": host_injection_results,
                "risk_score": risk_score,
                "response_time": scan_time,
                "status_code": baseline_response.status_code,
                "content_length": len(baseline_response.content)
            }
            
            notes = f"Security headers analysis completed. Found {len(present_headers)} security headers out of {len(SECURITY_HEADERS)}."
            
            if self.aggressive_mode:
                notes += f" Confirmed vulnerabilities: {confirmed_vulnerabilities}"
            
            result = {
                "ok": confirmed_vulnerabilities == 0,
                "risk": risk_level,
                "evidence": evidence,
                "notes": notes,
                "status": "success",
                "module": self.name,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f")
            }
            
            if self.debug:
                print(f"[SECHEADERS] Scan completed. Risk level: {risk_level}, Score: {risk_score}")
            
            return result
        
        except RequestException as e:
            if self.debug:
                print(f"[SECHEADERS] Request error: {e}")
            
            return {
                "ok": False,
                "risk": "low",
                "evidence": [],
                "notes": f"Request failed: {str(e)}",
                "status": "failed",
                "module": self.name,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f")
            }
        
        except Exception as e:
            if self.debug:
                print(f"[SECHEADERS] Unexpected error: {e}")
            
            return {
                "ok": False,
                "risk": "low",
                "evidence": [],
                "notes": f"Unexpected error: {str(e)}",
                "status": "failed",
                "module": self.name,
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.%f")
            }
