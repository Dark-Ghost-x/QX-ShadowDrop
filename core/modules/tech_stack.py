#!/usr/bin/env python3
import re
import random
import time
import ssl
from typing import List, Dict, Any
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from .vulnerability_base import VulnerabilityModule

HEADERS_KEYS = [
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-drupal-cache",
    "x-generator",
    "x-runtime",
    "x-backend-server",
    "x-server-software",
    "x-technology-stack"
]
BACKEND_HINTS = {
    "php": "PHP",
    "asp.net": "ASP.NET",
    "express": "Node.js (Express)",
    "django": "Python (Django)",
    "flask": "Python (Flask)",
    "ruby": "Ruby",
    "laravel": "PHP (Laravel)",
    "symfony": "PHP (Symfony)",
    "spring": "Java (Spring)",
    "wordpress": "WordPress",
    "joomla": "Joomla",
    "drupal": "Drupal",
    "magento": "Magento",
    "shopify": "Shopify",
    "prestashop": "PrestaShop",
    "opencart": "OpenCart",
    "woocommerce": "WooCommerce",
    "rails": "Ruby on Rails",
    "fastapi": "Python (FastAPI)",
    "nestjs": "Node.js (NestJS)",
    "next.js": "Next.js",
    "nuxt.js": "Nuxt.js"
}
JS_LIBRARIES = {
    "jquery": "jQuery",
    "react": "React",
    "vue": "Vue.js",
    "angular": "Angular",
    "bootstrap": "Bootstrap",
    "ember": "Ember.js",
    "backbone": "Backbone.js",
    "svelte": "Svelte",
    "alpine": "Alpine.js",
    "stimulus": "Stimulus",
    "three": "Three.js",
    "chart": "Chart.js",
    "d3": "D3.js",
    "moment": "Moment.js",
    "lodash": "Lodash",
    "underscore": "Underscore.js"
}
CSS_FRAMEWORKS = {
    "bootstrap": "Bootstrap CSS",
    "tailwind": "Tailwind CSS",
    "bulma": "Bulma CSS",
    "foundation": "Foundation CSS",
    "materialize": "Materialize CSS",
    "semantic": "Semantic UI",
    "uikit": "UIkit",
    "antd": "Ant Design",
    "chakra": "Chakra UI",
    "material-ui": "Material-UI"
}
AGGRESSIVE_PAYLOADS = [
    "/.env",
    "/.git/config",
    "/.htaccess",
    "/wp-config.php",
    "/config/database.yml",
    "/application/config/database.php",
    "/admin/config.yml",
    "/app/etc/local.xml",
    "/web.config",
    "/phpinfo.php",
    "/info.php",
    "/server-status",
    "/debug",
    "/console",
    "/api/users",
    "/api/config",
    "/admin/admin",
    "/administrator/index.php"
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

class TechStackScanner(VulnerabilityModule):
    name = "tech_stack"
    description = "Advanced technology stack detection scanner"
    risk = "low"
    useproxy = False
    enabled = True
    aggressive_mode = False
    custom_payloads = []
    bypass_protection = False
    
    def __init__(self, *args, **kwargs):
        target = None
        session = None
        timeout = 10
        debug = False
        aggressive = False
        custom_payloads = None
        bypass_protection = False
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
        if 'custom_payloads' in kwargs:
            custom_payloads = kwargs['custom_payloads']
        if 'bypass_protection' in kwargs:
            bypass_protection = kwargs['bypass_protection']
        if 'stealth' in kwargs:
            stealth = kwargs['stealth']
            
        if session is None:
            import requests
            session = requests.Session()
            
        super().__init__(target, session, timeout, debug)
        
        self.aggressive_mode = aggressive
        self.custom_payloads = custom_payloads if custom_payloads else []
        
        if stealth is not None:
            self.bypass_protection = stealth
        else:
            self.bypass_protection = bypass_protection
            
        if self.bypass_protection:
            self.session.verify = False
            ssl._create_default_https_context = ssl._create_unverified_context
            self.session.headers.update({
                'User-Agent': random.choice(USER_AGENTS),
                'X-Forwarded-For': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'X-Real-IP': f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Accept-Encoding': 'gzip, deflate',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                'Cache-Control': 'max-age=0'
            })
    
    def detect_js_libs(self, html: str) -> List[str]:
        libs = set()
        script_patterns = [
            r'<script[^>]+src=["\']([^"\']+)["\']',
            r'import\s+.*from\s+["\']([^"\']+)["\']',
            r'require\(["\']([^"\']+)["\']\)'
        ]
        for pattern in script_patterns:
            for match in re.findall(pattern, html, flags=re.I):
                src = match.lower()
                for lib_key, lib_name in JS_LIBRARIES.items():
                    if lib_key in src:
                        libs.add(lib_name)
        return sorted(libs)
    
    def detect_css_frameworks(self, html: str) -> List[str]:
        css = set()
        link_patterns = [
            r'<link[^>]+href=["\']([^"\']+)["\']',
            r'@import\s+url\(["\']?([^"\'\)]+)["\']?\)'
        ]
        for pattern in link_patterns:
            for match in re.findall(pattern, html, flags=re.I):
                href = match.lower()
                for css_key, css_name in CSS_FRAMEWORKS.items():
                    if css_key in href:
                        css.add(css_name)
        return sorted(css)
    
    def detect_backend(self, html: str, headers: Dict[str, str]) -> List[str]:
        found = set()
        content_lower = html.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        for key, name in BACKEND_HINTS.items():
            if key in content_lower:
                found.add(name)
        for header_value in headers_lower.values():
            for key, name in BACKEND_HINTS.items():
                if key in header_value:
                    found.add(name)
        return sorted(found)
    
    def detect_database_hints(self, html: str, headers: Dict[str, str]) -> List[str]:
        databases = set()
        content_lower = html.lower()
        db_patterns = {
            "mysql": ["mysql", "mysqli"],
            "postgresql": ["postgres", "pgsql"],
            "sqlite": ["sqlite"],
            "mongodb": ["mongodb", "mongoose"],
            "redis": ["redis"],
            "oracle": ["oracle"],
            "mssql": ["mssql", "sql server"]
        }
        for db_name, patterns in db_patterns.items():
            for pattern in patterns:
                if pattern in content_lower:
                    databases.add(db_name)
                    break
        return sorted(databases)
    
    def detect_security_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        security_headers = {}
        security_keys = [
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "strict-transport-security",
            "x-xss-protection",
            "referrer-policy"
        ]
        for key in security_keys:
            if key in headers:
                security_headers[key] = headers[key]
        return security_headers
    
    def aggressive_scan(self, base_url: str) -> Dict[str, Any]:
        results = {"sensitive_files": [], "endpoints": []}
        all_payloads = AGGRESSIVE_PAYLOADS + self.custom_payloads
        for payload in all_payloads:
            try:
                test_url = urljoin(base_url, payload)
                if self.debug:
                    print(f"Testing: {test_url}")
                time.sleep(0.2)
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=False)
                if response.status_code == 200 and len(response.content) > 0:
                    content_sample = response.text[:200].lower()
                    sensitive_indicators = [
                        "database", "password", "secret", "key", "token", "api",
                        "config", "settings", "env", "environment", "connection",
                        "username", "user", "admin", "root", "credential"
                    ]
                    is_sensitive = any(indicator in content_sample for indicator in sensitive_indicators)
                    if is_sensitive:
                        results["sensitive_files"].append({
                            "url": test_url,
                            "status": response.status_code,
                            "size": len(response.content),
                            "content_sample": content_sample
                        })
                elif response.status_code in [301, 302, 307, 308]:
                    redirect_url = response.headers.get("Location", "")
                    if redirect_url:
                        parsed_original = urlparse(test_url)
                        parsed_redirect = urlparse(redirect_url)
                        
                        is_suspicious_redirect = False
                        
                        if parsed_original.netloc != parsed_redirect.netloc and parsed_redirect.netloc:
                            is_suspicious_redirect = True
                        
                        sensitive_paths = ["/admin", "/administrator", "/wp-admin", "/cpanel", "/phpmyadmin"]
                        if any(sensitive in parsed_redirect.path.lower() for sensitive in sensitive_paths):
                            is_suspicious_redirect = True
                        
                        normal_redirects = [
                            (r"/administrator/index\.php", r"/administrator/"),
                            (r"/wp-admin/index\.php", r"/wp-admin/"),
                            (r"/admin/index\.php", r"/admin/"),
                            (r"/login\.php", r"/login/"),
                            (r"/index\.php", r"/")
                        ]
                        
                        is_normal_redirect = False
                        for pattern, replacement in normal_redirects:
                            if (re.search(pattern, parsed_original.path, re.IGNORECASE) and 
                                re.search(replacement, parsed_redirect.path, re.IGNORECASE)):
                                is_normal_redirect = True
                                break
                        
                        if is_suspicious_redirect and not is_normal_redirect:
                            results["endpoints"].append({
                                "url": test_url,
                                "status": response.status_code,
                                "redirect": redirect_url,
                                "is_suspicious": True
                            })
            except Exception as e:
                if self.debug:
                    print(f"Error testing {payload}: {e}")
                continue
        return results
    
    def scan(self) -> Dict[str, Any]:
        try:
            response = self.session.get(self.target, timeout=self.timeout)
            headers_found = {
                k: v for k, v in response.headers.items()
                if k.lower() in HEADERS_KEYS
            }
            soup = BeautifulSoup(response.text, "lxml")
            generator_meta = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
            generator = generator_meta.get("content") if generator_meta and generator_meta.has_attr("content") else None
            js_libs = self.detect_js_libs(response.text)
            css_frameworks = self.detect_css_frameworks(response.text)
            backend_hints = self.detect_backend(response.text, headers_found)
            database_hints = self.detect_database_hints(response.text, headers_found)
            security_headers = self.detect_security_headers(dict(response.headers))
            
            evidence = {
                "status_code": response.status_code,
                "headers": headers_found,
                "security_headers": security_headers,
                "generator": generator,
                "js_libs": js_libs,
                "css_frameworks": css_frameworks,
                "backend_hints": backend_hints,
                "database_hints": database_hints,
                "content_length": len(response.text),
                "response_time": response.elapsed.total_seconds()
            }
            
            risk_level = "low"
            
            if self.aggressive_mode:
                aggressive_results = self.aggressive_scan(self.target)
                
                if aggressive_results["sensitive_files"] or aggressive_results["endpoints"]:
                    evidence["aggressive_scan"] = aggressive_results
                    
                    if aggressive_results["sensitive_files"]:
                        risk_level = "high"
                    elif aggressive_results["endpoints"]:
                        risk_level = "medium"
            
            return {
                "ok": True,
                "risk": risk_level,
                "evidence": evidence,
                "notes": "Advanced passive detection from headers, JS/CSS assets, HTML source, and security headers."
            }
        except Exception as e:
            if self.debug:
                print(f"Error: {e}")
            return {
                "ok": False,
                "risk": "low",
                "evidence": {},
                "notes": f"Error occurred: {e}"
            }

Scanner = TechStackScanner
