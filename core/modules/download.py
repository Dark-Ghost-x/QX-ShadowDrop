#!/usr/bin/env python3
import requests
import random
import ssl
import time
from typing import Dict, Any, List, Optional
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

HEADER_BYPASS_PAYLOADS = {
    "x-frame-options": [
        "ALLOW-FROM https://evil.com", "SAMEORIGIN", "DENY", "invalid",
        "ALLOW-FROM http://attacker.com", "ALLOWALL", "SAME-ORIGIN",
        "ALLOW FROM https://malicious.com", "null", "*", "https://*",
        "http://*", "javascript:alert(1)", "data:text/html,<script>alert(1)</script>",
        "ALLOW-FROM https://", "ALLOW-FROM http://", "ALLOW-FROM //attacker.com",
        "ALLOW-FROM /\\attacker.com", "ALLOW-FROM https://attacker.com\\",
        "ALLOW-FROM https://attacker.com/", "ALLOW-FROM https://attacker.com?",
        "ALLOW-FROM https://attacker.com#", "ALLOW-FROM https://attacker.com/"
    ],
    "content-security-policy": [
        "default-src *", "script-src *", "unsafe-inline", "unsafe-eval",
        "default-src 'self'", "script-src 'none'", "style-src *",
        "img-src *", "connect-src *", "frame-src *", "media-src *",
        "object-src *", "prefetch-src *", "form-action *", "base-uri *",
        "plugin-types *", "sandbox allow-forms", "report-uri /csp",
        "upgrade-insecure-requests", "block-all-mixed-content",
        "require-sri-for script", "reflected-xss block", "referrer no-referrer",
        "frame-ancestors *", "frame-ancestors 'none'", "frame-ancestors 'self'",
        "frame-ancestors https://*", "frame-ancestors http://*"
    ],
    "access-control-allow-origin": [
        "*", "null", "https://attacker.com", "http://attacker.com",
        "https://evil.com", "http://evil.com", "https://",
        "http://", "//attacker.com", "/\\attacker.com", "https://attacker.com\\",
        "https://attacker.com/", "https://attacker.com?", "https://attacker.com#",
        "javascript:alert(1)", "data:", "*.attacker.com", "attacker.com",
        "null.attacker.com", "https://null", "http://null", "https://example.com",
        "http://example.com", "https://example.com:80", "http://example.com:443"
    ]
}

HEADER_INJECTION_PAYLOADS = [
    "X-Forwarded-Host: evil.com", "X-Original-URL: /admin", "X-Rewrite-URL: /wp-admin",
    "X-Custom-IP-Authorization: 127.0.0.1", "X-Forwarded-Server: attacker.com",
    "X-Forwarded-Proto: https", "X-Real-IP: 127.0.0.1", "X-Client-IP: 127.0.0.1",
    "X-Host: evil.com", "X-Forwarded-For: 127.0.0.1", "Referer: https://evil.com",
    "Origin: https://evil.com", "Host: evil.com", "X-Forwarded-Port: 80",
    "X-Forwarded-Port: 443", "X-Forwarded-Scheme: http", "X-Forwarded-Scheme: https",
    "X-Requested-With: XMLHttpRequest", "X-CSRF-Token: invalid", "X-HTTP-Method-Override: PUT",
    "X-HTTP-Method-Override: DELETE", "X-HTTP-Method-Override: CONNECT", "X-Originating-IP: 127.0.0.1",
    "X-Remote-IP: 127.0.0.1", "X-Remote-Addr: 127.0.0.1", "X-Client-IP: 127.0.0.1",
    "True-Client-IP: 127.0.0.1", "X-Cluster-Client-IP: 127.0.0.1", "X-Api-Version: 1.0",
    "X-Api-Key: invalid", "X-Auth-Token: invalid", "X-Correlation-ID: invalid",
    "User-Agent: Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)",
    "Accept: application/json", "Accept: text/xml", "Accept-Language: en-US,en;q=0.9",
    "Accept-Encoding: gzip, deflate", "Accept-Charset: utf-8", "Authorization: Basic YWRtaW46YWRtaW4=",
    "Cookie: session=invalid", "Cookie: admin=true", "Cookie: user=admin",
    "Content-Type: application/x-www-form-urlencoded", "Content-Type: application/json",
    "Content-Type: text/xml", "Content-Length: 0", "Connection: close",
    "Cache-Control: no-cache", "Pragma: no-cache", "TE: trailers", "Upgrade: HTTP/2.0",
    "Via: 1.1 attacker.com", "Warning: 199 -", "DNT: 1", "Forwarded: for=127.0.0.1",
    "Forwarded: host=attacker.com", "Forwarded: proto=https", "X-ATT-DeviceId: invalid",
    "X-Wap-Profile: http://attacker.com/wap.xml", "Proxy-Connection: keep-alive",
    "X-UIDH: invalid", "X-Do-Not-Track: 1", "X-Forwarded-Host: attacker.com",
    "X-Forwarded-For: 192.168.1.1", "X-Forwarded-For: 10.0.0.1", "X-Forwarded-For: 172.16.0.1",
    "X-Forwarded-For: 0.0.0.0", "X-Forwarded-For: 255.255.255.255", "X-Forwarded-For: 0:0:0:0:0:0:0:1",
    "X-Forwarded-For: ::1", "X-Forwarded-For: localhost", "X-Forwarded-For: example.com",
    "X-Forwarded-For: 123.123.123.123", "X-Forwarded-For: 1.1.1.1", "X-Forwarded-For: 8.8.8.8",
    "X-Forwarded-For: 9.9.9.9", "X-Forwarded-For: 127.0.0.1, 8.8.8.8", "X-Forwarded-For: 127.0.0.1, 1.1.1.1",
    "X-Forwarded-For: 127.0.0.1, 9.9.9.9", "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 1.1.1.1",
    "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 9.9.9.9", "X-Forwarded-For: 127.0.0.1, 1.1.1.1, 9.9.9.9",
    "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 1.1.1.1, 9.9.9.9", "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 1.1.1.1, 9.9.9.9, 10.0.0.1",
    "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 1.1.1.1, 9.9.9.9, 10.0.0.1, 192.168.1.1",
    "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 1.1.1.1, 9.9.9.9, 10.0.0.1, 192.168.1.1, 172.16.0.1",
    "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 1.1.1.1, 9.9.9.9, 10.0.0.1, 192.168.1.1, 172.16.0.1, 0.0.0.0",
    "X-Forwarded-For: 127.0.0.1, 8.8.8.8, 1.1.1.1, 9.9.9.9, 10.0.0.1, 192.168.1.1, 172.16.0.1, 0.0.0.0, 255.255.255.255"
]

class Scanner(VulnerabilityModule):
    name = "security_headers"
    description = "Advanced security headers analysis with bypass testing"
    risk = "low"
    useproxy = getattr(settings, "USEPROXY", False)
    enabled = True
    aggressive_mode = False
    bypass_protection = False
    custom_headers = []
    CHUNK_SIZE = 1024

    def __init__(self, target, session=None, timeout=10, retries=2, debug=False, aggressive=False,
                 custom_headers=None, bypass_protection=False, stealth=False, verbose=False):
        if session is None:
            session = requests.Session()
        super().__init__(target, session, timeout, retries, debug, aggressive, stealth, verbose)
        self.aggressive_mode = aggressive
        self.bypass_protection = bypass_protection
        self.custom_headers = custom_headers if custom_headers else []
        self.stealth = stealth
        self.session = session
        self.timeout = timeout
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
            'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
            'X-Real-IP': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
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

    def _safe_get(self, url, headers=None, timeout=None):
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
                allow_redirects=True
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
                    allow_redirects=True
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
            elif "includesubdomains" not in header_value_lower:
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

    def _test_header_bypass(self, original_headers):
        bypass_results = []
        for header_name, payloads in HEADER_BYPASS_PAYLOADS.items():
            selected_payloads = payloads[:150] if self.aggressive_mode else payloads[:50]
            for payload in selected_payloads:
                try:
                    test_headers = {header_name: payload}
                    response = self._safe_get(self.target, test_headers, timeout=10)
                    if response and response.status_code < 500:
                        test_headers_lower = {k.lower(): v for k, v in response.headers.items()}
                        if header_name.lower() in test_headers_lower:
                            original_value = original_headers.get(header_name.lower(), "")
                            test_value = test_headers_lower[header_name.lower()]
                            if test_value != original_value:
                                bypass_results.append({
                                    "header": header_name,
                                    "injected_value": payload,
                                    "response_value": test_value,
                                    "bypassed": True,
                                    "status_code": response.status_code,
                                    "content_length": len(response.content)
                                })
                except Exception:
                    continue
        return bypass_results

    def _test_header_injection(self):
        injection_results = []
        test_headers = HEADER_INJECTION_PAYLOADS[:150] + self.custom_headers if self.aggressive_mode else HEADER_INJECTION_PAYLOADS[:50] + self.custom_headers
        for header_line in test_headers:
            try:
                if ":" in header_line:
                    header_name, header_value = header_line.split(":", 1)
                    header_name = header_name.strip()
                    header_value = header_value.strip()
                    test_headers_dict = {header_name: header_value}
                    response = self._safe_get(self.target, test_headers_dict, timeout=8)
                    if response:
                        injection_results.append({
                            "header": header_name,
                            "value": header_value,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "response_headers": dict(response.headers),
                            "response_time": response.elapsed.total_seconds()
                        })
            except Exception:
                continue
        return injection_results

    def _test_host_header_injection(self):
        host_injection_results = []
        host_payloads = [
            "evil.com", "localhost:80", "127.0.0.1:8080", "localhost:443",
            "example.com", f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
        ] * 30
        selected_payloads = host_payloads[:150] if self.aggressive_mode else host_payloads[:50]
        for host_value in selected_payloads:
            try:
                test_headers = {"Host": host_value}
                response = self._safe_get(self.target, test_headers, timeout=8)
                if response:
                    host_injection_results.append({
                        "header": "Host",
                        "value": host_value,
                        "status_code": response.status_code,
                        "content_length": len(response.content),
                        "response_time": response.elapsed.total_seconds()
                    })
            except Exception:
                continue
        return host_injection_results

    def scan(self):
        if self.debug:
            print(f"[SECHEADERS] Scanning {self.target}")
        try:
            start_time = time.time()
            response = self._safe_get(self.target, timeout=self.timeout)
            scan_time = time.time() - start_time
            if not response:
                return {
                    "ok": False,
                    "risk": "low",
                    "evidence": [],
                    "notes": "Failed to get response from target",
                    "status": "failed",
                    "module": self.name
                }
            headers = {k.lower(): v for k, v in response.headers.items()}
            present_headers = []
            missing_headers = []
            header_analysis = {}
            for header in SECURITY_HEADERS:
                if header in headers:
                    present_headers.append(header)
                    header_analysis[header] = self._analyze_header_strength(header, headers[header])
                else:
                    missing_headers.append(header)
                    header_analysis[header] = {"strength": "missing", "vulnerabilities": ["Header not present"]}
            bypass_results = []
            injection_results = []
            host_injection_results = []
            if self.aggressive_mode or self.bypass_protection or self.stealth:
                bypass_results = self._test_header_bypass(headers)
                injection_results = self._test_header_injection()
                host_injection_results = self._test_host_header_injection()
            risk_score = 0
            for header, analysis in header_analysis.items():
                if analysis["strength"] == "missing" and SECURITY_HEADER_STANDARDS[header]["required"]:
                    risk_score += 3
                elif analysis["strength"] in ["weak", "invalid"]:
                    risk_score += 2
                elif analysis["strength"] == "missing" and not SECURITY_HEADER_STANDARDS[header]["required"]:
                    risk_score += 1
            if bypass_results:
                risk_score += len(bypass_results) * 2
            if injection_results:
                risk_score += len(injection_results) * 1
            if risk_score >= 12:
                risk_level = "critical"
            elif risk_score >= 8:
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
                "status_code": response.status_code,
                "content_length": len(response.content)
            }
            notes = f"Security headers analysis completed. Found {len(present_headers)} security headers out of {len(SECURITY_HEADERS)}."
            if self.aggressive_mode or self.bypass_protection or self.stealth:
                notes += f" Bypass tests: {len(bypass_results)} attempts, Injection tests: {len(injection_results) + len(host_injection_results)} attempts."
            return {
                "ok": True,
                "risk": risk_level,
                "evidence": evidence,
                "notes": notes,
                "status": "success",
                "module": self.name
            }
        except RequestException as e:
            if self.debug:
                print(f"[SECHEADERS] Request error: {e}")
            return {
                "ok": False,
                "risk": "low",
                "evidence": [],
                "notes": f"Request failed: {str(e)}",
                "status": "failed",
                "module": self.name
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
                "module": self.name
            }
