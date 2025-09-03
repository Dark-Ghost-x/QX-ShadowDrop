

#!/usr/bin/env python3
import os
import re
import random
import time
import urllib3
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, List, Optional
import requests
from requests.exceptions import RequestException
import ssl
from .vulnerability_base import VulnerabilityModule
from config import settings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner(VulnerabilityModule):
    name = "admin_panels"
    description = "Advanced admin panel discovery scanner"
    useproxy = getattr(settings, "ADMINPANEL_USEPROXY", True)
    enabled = getattr(settings, "ADMINPANEL_ENABLED", True)
    timeout = min(float(getattr(settings, "TIMEOUT", 30.0)), 60.0)
    max_paths = getattr(settings, "ADMINPANEL_MAX_PATHS", 100)
    scan_delay = (max(0.0, float(getattr(settings, "SCAN_DELAY", 0.1))),
                 max(0.0, float(getattr(settings, "SCAN_DELAY", 0.3))))
    aggressive = getattr(settings, "AGGRESSIVE", False)
    debug_mode = getattr(settings, "DEBUG", False)
    DEFAULT_PATHS = [
        "/admin", "/admin/login", "/admin/signin", "/administrator",
        "/adminpanel", "/admincp", "/admin/dashboard", "/login",
        "/user/login", "/auth/login", "/manage", "/management",
        "/backend", "/dashboard", "/wp-admin", "/wp-login.php",
        "/cpanel", "/console", "/admin_area", "/secret", "/controlpanel",
        "/admincenter", "/adminportal", "/adminweb", "/sysadmin",
        "/admin-login", "/admin_login", "/admin/auth", "/admin/console",
        "/admin/control", "/admin/manage", "/admin/portal", "/admin/system",
        "/admin/access", "/admin/secure", "/admin/panel", "/admin/area",
        "/admin/interface", "/admin/portal", "/admin/manager", "/admin/root",
        "/admin/master", "/admin/super", "/admin/main", "/admin/home",
        "/admin/index", "/admin/default", "/admin/base", "/admin/core",
        "/panel", "/control", "/system", "/manager", "/webadmin",
        "/administer", "/administration", "/admin_tools", "/admin-tools",
        "/useradmin", "/user_admin", "/usr", "/operator", "/operate",
        "/moderator", "/moderate", "/config", "/configuration",
        "/setup", "/install", "/installation", "/maintenance",
        "/webmaster", "/web-master", "/superuser", "/super-user",
        "/root", "/master", "/supervisor", "/director", "/editor",
        "/publisher", "/author", "/contributor", "/subscriber",
        "/member", "/account", "/profile", "/settings", "/preferences",
        "/options", "/parameters", "/security", "/secure", "/protected",
        "/private", "/hidden", "/restricted", "/internal", "/intranet",
        "/portal", "/gateway", "/access", "/entry", "/signin", "/sign-in",
        "/authenticate", "/authentication", "/auth", "/login", "/log-in",
        "/signon", "/sign-on", "/register", "/registration", "/join",
        "/enroll", "/enrollment", "/activate", "/activation",
        "/verify", "/verification", "/validate", "/validation",
        "/recover", "/recovery", "/reset", "/password", "/passwd",
        "/credential", "/credentials", "/token", "/key", "/certificate",
        "/license", "/licence", "/permit", "/permission", "/authorization",
        "/privilege", "/right", "/access", "/entrypoint", "/endpoint",
        "/api", "/graphql", "/rest", "/soap", "/xmlrpc", "/jsonrpc",
        "/rpc", "/remote", "/service", "/services", "/web-service",
        "/webservice", "/interface", "/console", "/terminal", "/shell",
        "/command", "/cmd", "/exec", "/execute", "/run", "/start",
        "/begin", "/init", "/initialize", "/setup", "/install",
        "/uninstall", "/remove", "/delete", "/update", "/upgrade",
        "/downgrade", "/patch", "/fix", "/repair", "/maintain",
        "/monitor", "/monitoring", "/log", "/logs", "/logging",
        "/audit", "/auditing", "/report", "/reporting", "/analytics",
        "/analysis", "/statistics", "/stats", "/metrics", "/measure",
        "/track", "/tracking", "/trace", "/tracing", "/debug",
        "/debugging", "/test", "/testing", "/validate", "/validation",
        "/check", "/checking", "/verify", "/verification", "/scan",
        "/scanning", "/inspect", "/inspection", "/review", "/revision",
        "/version", "/versions", "/history", "/historic", "/archive",
        "/archives", "/backup", "/backups", "/restore", "/restoration",
        "/recover", "/recovery", "/retrieve", "/retrieval", "/fetch",
        "/import", "/export", "/upload", "/download", "/transfer",
        "/transmit", "/receive", "/sync", "/synchronize", "/mirror",
        "/copy", "/duplicate", "/clone", "/move", "/rename",
        "/modify", "/modification", "/change", "/alter", "/adjust",
        "/configure", "/configuration", "/setting", "/settings",
        "/option", "/options", "/preference", "/preferences",
        "/property", "/properties", "/attribute", "/attributes",
        "/parameter", "/parameters", "/variable", "/variables",
        "/environment", "/env", "/config", "/conf", "/cfg",
        "/ini", "/xml", "/json", "/yaml", "/yml", "/toml"
    ]
    LOGIN_INDICATORS = {
        "login", "sign in", "sign-in", "signin", "password",
        "username", "admin", "administrator", "two-factor", "otp",
        "authentication", "credentials", "auth", "panel", "dashboard",
        "email", "user", "account", "access", "secure", "control",
        "manage", "system", "console", "portal", "interface"
    }
    PROTECTION_HEADERS = {
        "x-frame-options", "content-security-policy",
        "strict-transport-security", "x-content-type-options",
        "x-xss-protection", "x-permitted-cross-domain-policies",
        "referrer-policy", "feature-policy", "permissions-policy"
    }

    def __init__(self, target, session=None, timeout=30, debug=False, verbose=False,
                 proxy=None, aggressive=False, stealth=False, custom_payloads=None,
                 bypass_protection=False, custom_headers=None, **kwargs):
        super().__init__(target, session=session, timeout=timeout, debug=debug, verbose=verbose,
                        proxy=proxy, aggressive=aggressive, stealth=stealth,
                        custom_payloads=custom_payloads, bypass_protection=bypass_protection, **kwargs)
        self.aggressive_mode = aggressive or stealth
        self.debug = debug
        self.custom_paths = custom_payloads if custom_payloads else []
        self.bypass_protection = bypass_protection or stealth
        self.stealth = stealth
        self.verbose = verbose
        self.timeout = timeout
        if self.aggressive_mode:
            self.max_paths = 300
            self.scan_delay = (0.05, 0.15)
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
        self.base_url = self._normalize_url(target)

    def _normalize_url(self, target):
        parsed = urlparse(target)
        return urlunparse((parsed.scheme, parsed.netloc, "", "", "", ""))

    def _load_custom_paths(self):
        custom_paths = []
        try:
            custom = getattr(settings, "CUSTOM_ADMIN_PATHS", None)
            if custom and isinstance(custom, list):
                custom_paths = [f"/{path}" if not path.startswith("/") else path for path in custom]
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Error loading custom paths: {e}")
        return custom_paths

    def _get_scan_paths(self):
        paths = list(set(self.DEFAULT_PATHS + self._load_custom_paths() + self.custom_paths))
        random.shuffle(paths)
        return paths[:self.max_paths]

    def _is_login_page(self, response):
        if not response or not hasattr(response, 'text') or not response.text:
            return False
        content = response.text.lower()[:8192]
        title = self._extract_title(response.text).lower()
        content_indicators = sum(1 for indicator in self.LOGIN_INDICATORS if indicator in content)
        title_indicators = sum(1 for indicator in self.LOGIN_INDICATORS if indicator in title)
        return content_indicators >= 2 or title_indicators >= 1

    def _has_protection_headers(self, response):
        if not response or not hasattr(response, 'headers'):
            return False
        return any(
            header.lower() in response.headers
            for header in self.PROTECTION_HEADERS
        )

    def _extract_title(self, html):
        if not html:
            return ""
        match = re.search(r"<title[^>]*>(.*?)</title>", html, flags=re.IGNORECASE | re.DOTALL)
        if not match:
            return ""
        return re.sub(r"\s+", " ", match.group(1)).strip()[:200]

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
                allow_redirects=False
            )
            return response
        except (RequestException, ConnectionError, TimeoutError, ssl.SSLError):
            try:
                fallback_session = requests.Session()
                fallback_headers = self.session.headers.copy()
                if headers:
                    fallback_headers.update(headers)
                fallback_session.headers.update(fallback_headers)
                if self.proxy:
                    fallback_session.proxies = {"http": self.proxy, "https": self.proxy}
                return fallback_session.get(
                    url,
                    timeout=timeout,
                    verify=not self.bypass_protection,
                    allow_redirects=False
                )
            except Exception:
                return None
        except Exception:
            return None

    def _scan_url(self, path):
        url = f"{self.base_url}{path}"
        try:
            time.sleep(random.uniform(*self.scan_delay))
            response = self._safe_get(url)
            if not response:
                return {
                    "url": url,
                    "error": "Request failed",
                    "probable_panel": False,
                    "reason": "request_error"
                }
            result = {
                "url": url,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "location": response.headers.get("Location", ""),
                "title": self._extract_title(response.text),
                "protected": self._has_protection_headers(response),
                "response_time": response.elapsed.total_seconds() if hasattr(response, 'elapsed') else 0
            }
            if response.status_code in [301, 302, 303, 307, 308]:
                location = response.headers.get("Location", "").lower()
                result["probable_panel"] = any(
                    x in location for x in ["login", "admin", "signin", "auth", "dashboard"]
                )
                result["reason"] = "redirect_to_login"
            elif response.status_code in [401, 403]:
                result["probable_panel"] = True
                result["reason"] = "protected_resource"
            elif response.status_code == 200:
                result["probable_panel"] = self._is_login_page(response)
                result["reason"] = "login_page_indicators"
            elif response.status_code == 404:
                result["probable_panel"] = False
                result["reason"] = "not_found"
            else:
                result["probable_panel"] = False
                result["reason"] = "unusual_status"
            return result
        except Exception as e:
            if self.debug:
                print(f"[DEBUG] Request failed: {url} - {e}")
            return {
                "url": url,
                "error": str(e),
                "probable_panel": False,
                "reason": "request_error"
            }

    def scan(self):
        try:
            if self.debug:
                print(f"[DEBUG] Starting admin panel scan for: {self.base_url}")
                print(f"[DEBUG] Aggressive mode: {self.aggressive_mode}")
                print(f"[DEBUG] Max paths: {self.max_paths}")
            scan_paths = self._get_scan_paths()
            if self.debug:
                print(f"[DEBUG] Testing {len(scan_paths)} paths")
            results = []
            found_panels = []
            for i, path in enumerate(scan_paths):
                if self.debug and i % 50 == 0:
                    print(f"[DEBUG] Testing path {i+1}/{len(scan_paths)}: {path}")
                result = self._scan_url(path)
                results.append(result)
                if result.get("probable_panel"):
                    found_panels.append(result)
                    if self.debug:
                        print(f"[FOUND] Potential admin panel: {result['url']}")
            risk = "high" if found_panels else "low"
            if len(found_panels) > 3:
                risk = "critical"
            return {
                "ok": True,
                "risk": risk,
                "evidence": found_panels,
                "notes": f"Found {len(found_panels)} potential admin panels out of {len(results)} tested",
                "status": "success",
                "module": self.name,
                "found_panels": len(found_panels),
                "total_tested": len(results),
                "protected_panels": sum(1 for r in found_panels if r.get("protected"))
            }
        except Exception as e:
            if self.debug:
                print(f"[CRITICAL ERROR] {str(e)}")
            return {
                "ok": False,
                "risk": "low",
                "evidence": [],
                "notes": f"Unexpected error: {str(e)}",
                "status": "failed",
                "module": self.name
            }

    def run(self, **kwargs):
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
        return self.scan()
