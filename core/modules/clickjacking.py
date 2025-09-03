#!/usr/bin/env python3
import re
import random
import time
import ssl
from typing import Dict, Any, List, Optional, Tuple
import requests
from urllib.parse import urlparse, urljoin
from .vulnerability_base import VulnerabilityModule
from config import settings

class Scanner(VulnerabilityModule):
    name = "clickjacking"
    description = "Advanced Clickjacking protection detection with aggressive testing"
    risk = "low"
    enabled = True
    timeout = getattr(settings, "TIMEOUT", 10)
    user_agent = getattr(settings, "USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    aggressive_mode = False
    bypass_protection = False
    
    def __init__(self, target, **kwargs):
        super().__init__(target, **kwargs)
        self.aggressive_mode = kwargs.get('aggressive', False)
        self.bypass_protection = kwargs.get('bypass_protection', False)
        self.custom_payloads = kwargs.get('custom_payloads', [])
        self.debug = kwargs.get('debug', False)
        self.session = requests.Session()
        self.base_response = None
        
        if self.bypass_protection:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()
        
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        if getattr(settings, "USE_PROXY", False):
            proxy_config = getattr(settings, "PROXY_SETTINGS", {})
            self.session.proxies.update(proxy_config)
    
    def _get_base_response(self):
        try:
            self.base_response = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=not self.bypass_protection
            )
            return True
        except Exception as e:
            if self.debug:
                print(f"Base request error: {e}")
            return False
    
    def _is_html_response(self, response):
        if not response:
            return False
        content_type = response.headers.get("Content-Type", "").lower()
        return "text/html" in content_type
    
    def _get_secure_headers(self, headers):
        secure = False
        reasons = []
        frame_ancestors = None
        
        x_frame_options = headers.get("x-frame-options", "").lower()
        if x_frame_options in ["deny", "sameorigin"]:
            secure = True
            reasons.append(f"X-Frame-Options: {x_frame_options}")
        
        csp = headers.get("content-security-policy", "").lower()
        if "frame-ancestors" in csp:
            match = re.search(r"frame-ancestors\s+([^;]+)", csp)
            if match:
                frame_ancestors = match.group(1).strip().strip("'")
                if frame_ancestors.lower() != "*":
                    secure = True
                    reasons.append(f"CSP frame-ancestors: {frame_ancestors}")
        
        return secure, reasons, frame_ancestors
    
    def _is_relevant_bypass_technique(self, headers):
        relevant_headers = [
            "host", "x-forwarded-host", "x-forwarded-for", "referer", "origin",
            "x-real-ip", "x-client-ip", "x-host", "x-forwarded-server",
            "x-original-url", "x-rewrite-url", "x-custom-ip-authorization",
            "x-requested-with", "x-csrf-token", "x-xsrf-token", "cookie"
        ]
        
        for header in headers.keys():
            if header.lower() in relevant_headers:
                return True
        return False
    
    def _is_error_page(self, content):
        error_indicators = [
            "403 forbidden", "404 not found", "500 internal server error",
            "access denied", "permission denied", "error", "not found",
            "forbidden", "unauthorized", "bad request", "service unavailable"
        ]
        
        content_lower = content.lower()
        for indicator in error_indicators:
            if indicator in content_lower:
                return True
        return False
    
    def _verify_bypass_effectiveness(self, response, original_headers, injected_headers):
        if not response or response.status_code != 200:
            return False
        
        if not self._is_html_response(response):
            return False
        
        if not self._is_relevant_bypass_technique(injected_headers):
            return False
        
        test_headers_lower = {k.lower(): v for k, v in response.headers.items()}
        test_secure, test_reasons, _ = self._get_secure_headers(test_headers_lower)
        
        if test_secure:
            return False
        
        if self.base_response and response.text == self.base_response.text:
            return False
        
        if self._is_error_page(response.text):
            return False
        
        return True
    
    def _test_bypass_methods(self, original_headers):
        bypass_results = []
        
        test_headers = [
            {"X-Frame-Options": "ALLOW-FROM https://evil.com"},
            {"Content-Security-Policy": "frame-ancestors *"},
            {"Content-Security-Policy": "frame-ancestors 'none'"},
            {"X-Frame-Options": "invalid-value"},
            {}
        ]
        
        for test_header in test_headers:
            try:
                test_response = self.session.get(
                    self.target,
                    headers=test_header,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if self._verify_bypass_effectiveness(test_response, original_headers, test_header):
                    bypass_results.append({
                        "method": "Header Manipulation",
                        "injected_header": test_header,
                        "bypassed": True,
                        "status_code": test_response.status_code
                    })
            except Exception as e:
                if self.debug:
                    print(f"Bypass test error: {e}")
                continue
        
        return bypass_results
    
    def _test_aggressive_bypass(self, original_headers):
        if not self.aggressive_mode:
            return []
        
        bypass_results = []
        test_cases = [
            {"X-Forwarded-Host": "evil.com"},
            {"X-Original-URL": self.target},
            {"X-Rewrite-URL": self.target},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Forwarded-Server": "attacker.com"},
            {"X-Forwarded-Proto": "https"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Client-IP": "127.0.0.1"},
            {"X-Host": "evil.com"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"Referer": "https://evil.com"},
            {"Origin": "https://evil.com"},
            {"Host": "evil.com"},
            {"X-Requested-With": "XMLHttpRequest"},
            {"X-CSRF-Token": "bypass"},
            {"X-XSRF-Token": "null"},
            {"Cookie": "sessionid=bypassed; csrftoken=evil"},
            {"User-Agent": "Mozilla/5.0 (compatible; ClickjackTester/1.0)"},
            {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
            {"Accept-Language": "en-US,en;q=0.9"},
            {"Connection": "keep-alive"},
            {"Upgrade-Insecure-Requests": "1"},
            {"Cache-Control": "no-cache"},
            {"Pragma": "no-cache"},
            {"DNT": "1"},
            {"Sec-Fetch-Dest": "document"},
            {"Sec-Fetch-Mode": "navigate"},
            {"Sec-Fetch-Site": "none"},
            {"Sec-Fetch-User": "?1"},
            {"Sec-GPC": "1"},
            {"X-Request-ID": "1337"},
            {"X-Correlation-ID": "1337"},
            {"X-Request-Start": "t=1337"},
            {"X-Request-Time": "1337ms"},
            {"X-Response-Time": "1337ms"},
            {"X-Process-Time": "1337ms"},
            {"X-Powered-By": "PHP/7.4"},
            {"X-AspNet-Version": "4.0.30319"},
            {"X-AspNetMvc-Version": "5.2"},
            {"Server": "Apache/2.4.41"},
            {"Via": "1.1 evil.com"},
            {"X-Cache": "MISS"},
            {"X-Cache-Hits": "0"},
            {"X-Content-Type-Options": "nosniff"},
            {"X-Frame-Options": "ALLOW-FROM https://evil.com"},
            {"X-XSS-Protection": "0"},
            {"Content-Security-Policy": "default-src * 'unsafe-inline' 'unsafe-eval'"},
            {"Strict-Transport-Security": "max-age=0"},
            {"Feature-Policy": "geolocation *"},
            {"Permissions-Policy": "geolocation=*"},
            {"X-Permitted-Cross-Domain-Policies": "all"},
            {"X-Download-Options": "noopen"},
            {"X-DNS-Prefetch-Control": "off"}
        ]
        
        for test_case in test_cases:
            try:
                test_response = self.session.get(
                    self.target,
                    headers=test_case,
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if self._verify_bypass_effectiveness(test_response, original_headers, test_case):
                    bypass_results.append({
                        "method": "Advanced Header Injection",
                        "injected_header": test_case,
                        "bypassed": True,
                        "status_code": test_response.status_code
                    })
            except Exception as e:
                if self.debug:
                    print(f"Aggressive bypass test error: {e}")
                continue
        
        return bypass_results
    
    def _test_protocol_bypass(self):
        if not self.aggressive_mode:
            return []
        
        bypass_results = []
        protocols = ["http://", "https://", "//", ""]
        domains = ["evil.com", "localhost", "127.0.0.1", "0.0.0.0", "example.com", "google.com"]
        paths = ["/", "/admin", "/login", "/dashboard", "/secure", "/private"]
        
        test_urls = []
        for protocol in protocols:
            for domain in domains:
                for path in paths:
                    test_urls.append(f"{protocol}{domain}{path}")
        
        for test_url in test_urls[:30]:
            try:
                test_response = self.session.get(
                    self.target,
                    headers={"Referer": test_url, "Origin": test_url},
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if self._verify_bypass_effectiveness(test_response, {}, {"Referer": test_url, "Origin": test_url}):
                    bypass_results.append({
                        "method": "Protocol Bypass",
                        "test_url": test_url,
                        "bypassed": True,
                        "status_code": test_response.status_code
                    })
            except Exception as e:
                if self.debug:
                    print(f"Protocol bypass test error: {e}")
                continue
        
        return bypass_results
    
    def _test_waf_bypass(self):
        if not self.aggressive_mode:
            return []
        
        bypass_results = []
        waf_payloads = [
            "https://google.com%00@evil.com",
            "https://google.com%0a@evil.com",
            "https://google.com%0d@evil.com",
            "https://google.com%09@evil.com",
            "https://google.com%23@evil.com",
            "https://google.com%3f@evil.com",
            "https://google.com%3a@evil.com",
            "https://google.com%2f@evil.com",
            "https://google.com%5c@evil.com",
            "https://google.com%2e@evil.com",
            "https://google.com%252e@evil.com",
            "https://google.com%ff@evil.com",
            "https://google.com%0d%0a@evil.com",
            "https://google.com%0a%0d@evil.com",
            "https://google.com%u002f%u002fevil.com",
            "https://google.com%u005c%u005cevil.com",
            "https://google.com%u002eevil.com",
            "https://google.com%u00252eevil.com",
            "https://google.com%u00252fevil.com",
            "https://google.com%u00255cevil.com"
        ]
        
        for payload in waf_payloads:
            try:
                test_response = self.session.get(
                    self.target,
                    headers={"Referer": payload, "Origin": payload},
                    timeout=self.timeout,
                    allow_redirects=False
                )
                
                if self._verify_bypass_effectiveness(test_response, {}, {"Referer": payload, "Origin": payload}):
                    bypass_results.append({
                        "method": "WAF Bypass",
                        "payload": payload,
                        "bypassed": True,
                        "status_code": test_response.status_code
                    })
            except Exception as e:
                if self.debug:
                    print(f"WAF bypass test error: {e}")
                continue
        
        return bypass_results
    
    def _get_response(self):
        try:
            return self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=not self.bypass_protection
            )
        except (requests.RequestException, ValueError) as e:
            if self.debug:
                print(f"Request error: {e}")
            return None
    
    def scan(self):
        if not self._get_base_response():
            return {"ok": False, "risk": "low", "evidence": [], "notes": "Request failed"}
        
        response = self._get_response()
        if not response:
            return {"ok": False, "risk": "low", "evidence": [], "notes": "Request failed"}
        
        headers = {k.lower(): v for k, v in response.headers.items()}
        is_html = self._is_html_response(response)
        secure, reasons, frame_ancestors = self._get_secure_headers(headers)
        
        bypass_results = []
        if not secure:
            bypass_results = self._test_bypass_methods(headers)
            if self.aggressive_mode:
                aggressive_bypass = self._test_aggressive_bypass(headers)
                protocol_bypass = self._test_protocol_bypass()
                waf_bypass = self._test_waf_bypass()
                bypass_results.extend(aggressive_bypass)
                bypass_results.extend(protocol_bypass)
                bypass_results.extend(waf_bypass)
        
        risk = "low"
        if not secure:
            risk = "high" if is_html else "medium"
        if bypass_results:
            risk = "critical"
        
        if not reasons:
            reasons = ["No clickjacking protection headers detected"]
        
        evidence = {
            "secure": secure,
            "reasons": reasons,
            "x_frame_options": headers.get("x-frame-options"),
            "csp_frame_ancestors": frame_ancestors,
            "is_html": is_html,
            "status_code": response.status_code,
            "bypass_attempts": bypass_results
        }
        
        notes = f"Clickjacking assessment: {len(bypass_results)} bypass techniques successful"
        if not secure:
            notes += " | No protection headers detected"
        
        return {
            "ok": True,
            "risk": risk,
            "evidence": evidence,
            "notes": notes
        }
    
    def run(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self.scan()
