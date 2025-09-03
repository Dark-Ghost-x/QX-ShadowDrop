#!/usr/bin/env python3
import re
import time
import urllib.parse
import requests
from typing import Dict, Any, List, Optional, Set
from .vulnerability_base import VulnerabilityModule
from config import settings

FORM_RE = re.compile(r"<form\b[^>]*>(.*?)</form>", re.IGNORECASE | re.DOTALL)
TOKEN_INPUT_RE = re.compile(
    r"<input\b[^>]*\b(?:name|id)\s*=\s*['\"](?:csrf[_-]?token|_token|authenticity_token|__requestverificationtoken|_csrf|csrfmiddlewaretoken)['\"][^>]*>",
    re.IGNORECASE
)
META_CSRF_RE = re.compile(
    r"<meta\b[^>]*\bname\s*=\s*['\"](?:csrf[_-]token|csrf_token|_csrf)['\"][^>]*>",
    re.IGNORECASE
)

class Scanner(VulnerabilityModule):
    name = "csrf_token_check"
    enabled = True
    timeout = getattr(settings, "TIMEOUT", 15)
    user_agent = getattr(settings, "USER_AGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
    debug_mode = getattr(settings, "DEBUG", False)
    aggressive = getattr(settings, "AGGRESSIVE", False)
    
    CSRF_COOKIE_NAMES = {
        "csrftoken", "xsrf-token", "csrf-token", "x-csrf-token",
        "__requestverificationtoken", "antiforgery", "_csrf", "_xsrf",
        "csrf", "xsrf", "csrf_param", "x-csrf-token"
    }
    
    CSRF_HEADER_NAMES = {
        "x-csrf-token", "x-xsrf-token", "csrf-token", "xsrf-token",
        "x-csrf-header", "x-xsrf-header", "x-csrf-protection"
    }
    
    ADVANCED_CSRF_PAYLOADS = [
        {"header": "X-CSRF-Token", "value": "null"},
        {"header": "X-CSRF-Token", "value": "undefined"},
        {"header": "X-CSRF-Token", "value": "0"},
        {"header": "X-CSRF-Token", "value": "123456"},
        {"header": "X-XSRF-Token", "value": "null"},
        {"header": "X-XSRF-Token", "value": "undefined"},
        {"header": "X-Requested-With", "value": "XMLHttpRequest"},
        {"header": "Referer", "value": "https://attacker.com"},
        {"header": "Origin", "value": "https://attacker.com"},
        {"header": "Cookie", "value": "csrf_token=bypass123"},
        {"header": "Cookie", "value": "XSRF-TOKEN=bypass123"},
        {"header": "X-HTTP-Method-Override", "value": "POST"},
        {"header": "X-Method-Override", "value": "POST"},
        {"header": "X-CSRF-Key", "value": "bypass123"},
        {"header": "X-Auth-Token", "value": "admin"},
        {"header": "Authorization", "value": "Bearer bypass_token"}
    ]
    
    def __init__(self, target: str, **kwargs):
        super().__init__(target, **kwargs)
        self.target_domain = urllib.parse.urlparse(target).netloc
        self.session.headers.update({
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.session.verify = False
    
    def _clean_response_content(self, content: str) -> str:
        patterns_to_remove = [
            r'<script[^>]*>.*?</script>',
            r'<style[^>]*>.*?</style>',
            r'<!--.*?-->',
            r'<![CDATA[.*?]]>',
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
    
    def _analyze_boolean_test(self, response_content: str, baseline_content: str, 
                             response_status: int, baseline_status: int) -> bool:
        clean_response = self._clean_response_content(response_content)
        clean_baseline = self._clean_response_content(baseline_content)
        
        if len(clean_response) < 100 or len(clean_baseline) < 100:
            return False
            
        length_diff = abs(len(clean_response) - len(clean_baseline))
        content_diff = clean_response != clean_baseline
        
        max_len = max(len(clean_response), len(clean_baseline))
        if max_len > 0 and (length_diff / max_len) > 0.9:
            return False
        
        success_indicators = ['success', 'completed', 'updated', 'created', 'deleted', 'done', 'ok', 'saved']
        error_indicators = ['error', 'failed', 'invalid', 'denied', 'forbidden', 'unauthorized']
        
        content_lower = clean_response.lower()
        has_success_indicator = any(indicator in content_lower for indicator in success_indicators)
        has_error_indicator = any(indicator in content_lower for indicator in error_indicators)
        
        return (
            content_diff and
            length_diff > 30 and
            response_status == baseline_status and
            has_success_indicator and
            not has_error_indicator
        )
    
    def _get_response(self) -> Optional[Any]:
        try:
            response = self.session.get(
                self.target,
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            if response.status_code >= 400:
                if self.debug_mode:
                    print(f"Request failed with status code: {response.status_code}")
                return None
            return response
        except Exception as e:
            if self.debug_mode:
                print(f"Request failed: {e}")
            return None
    
    def _is_internal_form(self, form_action: str) -> bool:
        if not form_action or form_action.strip() in ['', '#', 'javascript:void(0)']:
            return True
            
        try:
            if form_action.startswith('/'):
                return True
                
            if form_action.startswith(self.target):
                return True
                
            parsed_action = urllib.parse.urlparse(form_action)
            if not parsed_action.netloc:
                return True
                
            action_domain = parsed_action.netloc
            return action_domain == self.target_domain
                    
        except:
            pass
            
        return False
    
    def _is_sensitive_form(self, form: str) -> bool:
        sensitive_keywords = [
            'password', 'email', 'username', 'login', 'signin', 'auth',
            'delete', 'remove', 'update', 'change', 'modify', 'edit',
            'add', 'create', 'new', 'submit', 'save', 'upload'
        ]
        
        form_lower = form.lower()
        return any(keyword in form_lower for keyword in sensitive_keywords)
    
    def _analyze_forms(self, text: str) -> Dict[str, Any]:
        forms = FORM_RE.findall(text)
        analysis = {
            "forms_total": len(forms),
            "internal_forms": 0,
            "external_forms": 0,
            "post_forms": 0,
            "post_forms_with_token": 0,
            "post_forms_without_token": 0,
            "get_forms": 0,
            "get_forms_with_token": 0,
            "get_forms_without_token": 0,
            "sensitive_forms": 0,
            "vulnerable_forms": []
        }
        
        for form in forms:
            method_match = re.search(r"method\s*=\s*['\"]([^'\"]*)['\"]", form, re.IGNORECASE)
            method = method_match.group(1).lower() if method_match else "get"
            
            action_match = re.search(r"action\s*=\s*['\"]([^'\"]*)['\"]", form, re.IGNORECASE)
            action = action_match.group(1) if action_match else self.target
            
            has_token = bool(TOKEN_INPUT_RE.search(form))
            is_internal = self._is_internal_form(action)
            is_sensitive = self._is_sensitive_form(form)
            
            if not is_internal:
                analysis["external_forms"] += 1
                continue
                
            analysis["internal_forms"] += 1
            
            if is_sensitive:
                analysis["sensitive_forms"] += 1
            
            if method == "post":
                analysis["post_forms"] += 1
                if has_token:
                    analysis["post_forms_with_token"] += 1
                else:
                    analysis["post_forms_without_token"] += 1
                    if self.aggressive:
                        analysis["vulnerable_forms"].append({
                            "type": "missing_csrf_token",
                            "form_action": action,
                            "payload": "POST request without CSRF protection"
                        })
            else:
                analysis["get_forms"] += 1
                if has_token:
                    analysis["get_forms_with_token"] += 1
                else:
                    analysis["get_forms_without_token"] += 1
                    if is_sensitive and self.aggressive:
                        analysis["vulnerable_forms"].append({
                            "type": "missing_csrf_token",
                            "form_action": action,
                            "payload": "GET request without CSRF protection"
                        })
        
        return analysis
    
    def _check_csrf_meta(self, text: str) -> bool:
        return bool(META_CSRF_RE.search(text))
    
    def _check_csrf_cookies(self, response: Any) -> bool:
        cookie_keys = {k.lower() for k in response.cookies.keys()}
        return any(cookie_name in cookie_keys for cookie_name in self.CSRF_COOKIE_NAMES)
    
    def _check_csrf_headers(self, response: Any) -> bool:
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        return any(header_name in headers_lower for header_name in self.CSRF_HEADER_NAMES)
    
    def _advanced_csrf_testing(self, response: Any, text: str) -> List[Dict[str, Any]]:
        if not self.aggressive:
            return []
            
        vulnerabilities = []
        forms = FORM_RE.findall(text)
        
        for form in forms:
            method_match = re.search(r"method\s*=\s*['\"]([^'\"]*)['\"]", form, re.IGNORECASE)
            method = method_match.group(1).lower() if method_match else "get"
            
            action_match = re.search(r"action\s*=\s*['\"]([^'\"]*)['\"]", form, re.IGNORECASE)
            action = action_match.group(1) if action_match else self.target
            
            has_token = bool(TOKEN_INPUT_RE.search(form))
            is_internal = self._is_internal_form(action)
            is_sensitive = self._is_sensitive_form(form)
            
            if not is_internal:
                continue
                
            if (method == "post" and not has_token) or (is_sensitive and self.aggressive):
                for payload in self.ADVANCED_CSRF_PAYLOADS:
                    time.sleep(0.3)
                    test_response = self._test_csrf_bypass(action, method, payload)
                    
                    if test_response and test_response.status_code < 500:
                        clean_comparison = self._analyze_boolean_test(
                            test_response.text, text, 
                            test_response.status_code, response.status_code
                        )
                        
                        if clean_comparison:
                            vulnerabilities.append({
                                "type": "csrf_bypass_successful",
                                "form_action": action,
                                "method": method,
                                "payload": f"{payload['header']}: {payload['value']}",
                                "status_code": test_response.status_code,
                                "risk": "critical"
                            })
                            break
        
        if self.aggressive:
            parsed_target = urllib.parse.urlparse(self.target)
            query_params = urllib.parse.parse_qs(parsed_target.query)
            
            test_params = {
                'action': ['delete', 'update', 'add', 'create'],
                'id': ['1', 'admin', '0'],
                'status': ['disabled', 'enabled', 'deleted'],
                'confirm': ['yes', 'true', '1']
            }
            
            for param, values in test_params.items():
                for value in values:
                    modified_params = query_params.copy()
                    modified_params[param] = [value]
                    
                    modified_query = urllib.parse.urlencode(modified_params, doseq=True)
                    modified_url = urllib.parse.urlunparse((
                        parsed_target.scheme,
                        parsed_target.netloc,
                        parsed_target.path,
                        parsed_target.params,
                        modified_query,
                        parsed_target.fragment
                    ))
                    
                    test_response = self._test_csrf_bypass(modified_url, "get", 
                                                          {"header": "Referer", "value": "https://attacker.com"})
                    
                    if test_response and test_response.status_code < 500:
                        clean_comparison = self._analyze_boolean_test(
                            test_response.text, text, 
                            test_response.status_code, response.status_code
                        )
                        
                        if clean_comparison:
                            vulnerabilities.append({
                                "type": "csrf_bypass_successful",
                                "form_action": modified_url,
                                "method": "get",
                                "payload": f"URL parameter manipulation: {param}={value}",
                                "status_code": test_response.status_code,
                                "risk": "critical"
                            })
                            break
        
        return vulnerabilities
    
    def _test_csrf_bypass(self, action: str, method: str, payload: Dict[str, str]) -> Optional[Any]:
        try:
            if not urllib.parse.urlparse(action).netloc:
                action = urllib.parse.urljoin(self.target, action)
                
            headers = {payload['header']: payload['value']}
            
            if method.lower() == 'post':
                return self.session.post(action, headers=headers, timeout=self.timeout, allow_redirects=False, verify=False)
            else:
                return self.session.get(action, headers=headers, timeout=self.timeout, allow_redirects=False, verify=False)
        except:
            return None
    
    def _determine_risk(self, analysis: Dict[str, Any], meta_found: bool,
                       cookies_found: bool, headers_found: bool, advanced_vulns: List[Dict[str, Any]]) -> str:
        if advanced_vulns:
            return "critical"
        if analysis["post_forms_without_token"] > 0:
            return "high"
        if analysis["sensitive_forms"] > 0 and analysis["get_forms_without_token"] > 0:
            return "high"
        if analysis["post_forms"] > 0 and analysis["post_forms_with_token"] == analysis["post_forms"]:
            return "low"
        if analysis["internal_forms"] == 0:
            return "informational"
        return "medium"
    
    def scan(self) -> Dict[str, Any]:
        start_time = time.time()
        response = self._get_response()
        
        if not response:
            return self.standard_result(False, "low", [], "Request failed")
            
        text = response.text
        form_analysis = self._analyze_forms(text)
        meta_found = self._check_csrf_meta(text)
        cookies_found = self._check_csrf_cookies(response)
        headers_found = self._check_csrf_headers(response)
        advanced_vulns = self._advanced_csrf_testing(response, text)
        risk = self._determine_risk(form_analysis, meta_found, cookies_found, headers_found, advanced_vulns)
        
        evidence = {
            "forms_total": form_analysis["forms_total"],
            "internal_forms": form_analysis["internal_forms"],
            "external_forms": form_analysis["external_forms"],
            "post_forms": form_analysis["post_forms"],
            "post_forms_with_token": form_analysis["post_forms_with_token"],
            "post_forms_without_token": form_analysis["post_forms_without_token"],
            "get_forms": form_analysis["get_forms"],
            "get_forms_with_token": form_analysis["get_forms_with_token"],
            "get_forms_without_token": form_analysis["get_forms_without_token"],
            "sensitive_forms": form_analysis["sensitive_forms"],
            "csrf_meta_found": meta_found,
            "csrf_cookies_found": cookies_found,
            "csrf_headers_found": headers_found,
            "vulnerabilities_found": advanced_vulns
        }
        
        scan_duration = time.time() - start_time
        notes = f"CSRF scan completed in {scan_duration:.2f}s. Found {form_analysis['internal_forms']} internal forms, {len(advanced_vulns)} vulnerabilities."
        
        return self.standard_result(
            ok=len(advanced_vulns) == 0,
            risk=risk,
            evidence=evidence,
            notes=notes
        )
    
    def run(self) -> Dict[str, Any]:
        return self.scan()
