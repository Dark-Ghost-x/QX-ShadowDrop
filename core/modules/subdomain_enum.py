#!/usr/bin/env python3
import socket
import random
import time
from urllib.parse import urlparse
from typing import List, Dict, Any, Tuple, Optional
from .vulnerability_base import VulnerabilityModule

DEFAULT_WORDLIST = [
    "www", "mail", "dev", "test", "api", "staging", "beta", "demo",
    "blog", "shop", "ftp", "vpn", "adm", "admin", "support", "webmail",
    "gateway", "secure", "static", "cdn", "m", "img", "assets"
]

EXTRA_NORMAL = [
    "account", "accounts", "app", "backup", "cpanel", "dashboard", "db", "dns", "documentation", "download",
    "email", "files", "forum", "forums", "help", "host", "imap", "irc", "login", "manage",
    "manager", "marketing", "mobile", "mysql", "news", "ns1", "ns2", "ns3", "ns4", "panel",
    "partner", "partners", "phpmyadmin", "pop", "portal", "private", "proxy", "router", "rss", "server",
    "signup", "smtp", "sql", "ssh", "status", "store", "subdomain", "survey", "telnet", "webdisk"
]

EXTRA_AGGRESSIVE = [
    "about", "access", "admin1", "admin2", "admin3", "administrator", "alpha", "app1", "app2", "archive",
    "auth", "beta", "blog1", "blog2", "cache", "calendar", "chat", "client", "cloud", "community",
    "config", "connect", "contact", "content", "control", "customer", "data", "demo1", "demo2", "dev1",
    "dev2", "development", "direct", "directory", "docs", "domain", "downloads", "edit", "editor", "engine",
    "events", "example", "exchange", "faq", "feed", "file", "finance", "ftp1", "ftp2", "game",
    "games", "git", "group", "groups", "guide", "home", "hosting", "image", "images", "img1",
    "img2", "info", "internal", "invoice", "ip", "ipv6", "lab", "labs", "list", "live",
    "local", "log", "logs", "mail1", "mail2", "mail3", "management", "member", "members", "message",
    "messages", "monitor", "movie", "movies", "music", "my", "net", "network", "new", "newsletter",
    "old", "online", "order", "orders", "owa", "payment", "payments", "photo", "photos", "pic",
    "pics", "picture", "pictures", "pop3", "post", "postfix", "postgresql", "preview", "price", "private",
    "profile", "project", "projects", "public", "register", "registration", "remote", "root", "sale", "sales",
    "sample", "samples", "search", "secure", "service", "services", "setting", "settings", "shop1", "shop2",
    "signin", "signout", "site", "sites", "software", "staff", "stage", "staging1", "staging2", "start",
    "stat", "static", "stats", "student", "students", "support1", "support2", "system", "tech", "test1",
    "test2", "testing", "tool", "tools", "train", "training", "upload", "uploads", "user", "users",
    "video", "videos", "vpn1", "vpn2", "web", "web1", "web2", "website", "widget", "wiki",
    "wordpress", "work", "workshop", "www1", "www2", "xml", "xmlrpc", "yahoo", "youtube", "zabbix"
]

class Scanner(VulnerabilityModule):
    name = "subdomain_enum"
    description = "Lightweight subdomain enumerator with DNS resolution"
    risk = "low"
    useproxy = False
    enabled = True

    def __init__(self, target: str, **kwargs):
        super().__init__(target, **kwargs)
        self.target = target
        self.aggressive = kwargs.get('aggressive', False)

        self.wordlist = DEFAULT_WORDLIST
        self.limit = 100
        self.timeout = 3
        self.delay_range = (0.05, 0.15)

        if kwargs.get('wordlist'):
            self.wordlist = kwargs['wordlist']
        if kwargs.get('limit'):
            self.limit = kwargs['limit']
        if kwargs.get('timeout'):
            self.timeout = kwargs['timeout']
        if kwargs.get('delay_range'):
            self.delay_range = kwargs['delay_range']

        if self.aggressive:
            self.wordlist += EXTRA_AGGRESSIVE
            self.limit = 300
            self.delay_range = (0.02, 0.08)
        else:
            self.wordlist += EXTRA_NORMAL

    def scan(self) -> Dict[str, Any]:
        try:
            domain = self._extract_domain(self.target)
            if not domain:
                return {
                    "ok": False,
                    "error": "Invalid target domain",
                    "risk": "low"
                }

            wildcard_ip = self._detect_wildcard(domain)
            found_subs = []

            for sub in self.wordlist[:self.limit]:
                fqdn = f"{sub}.{domain}"
                ip = self._resolve(fqdn)
                time.sleep(random.uniform(*self.delay_range))

                if ip and ip != wildcard_ip:
                    found_subs.append({"subdomain": fqdn, "ip": ip})

            return {
                "ok": True,
                "domain": domain,
                "wildcard_detected": bool(wildcard_ip),
                "wildcard_ip": wildcard_ip,
                "subdomains": found_subs,
                "count": len(found_subs),
                "risk": "low"
            }

        except Exception as e:
            return {
                "ok": False,
                "error": str(e),
                "risk": "low"
            }

    def _extract_domain(self, target: str) -> str:
        if "://" not in target:
            target = f"http://{target}"
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        return host.split("@")[-1].split(":")[0].strip().lower()

    def _resolve(self, host: str) -> Optional[str]:
        try:
            socket.setdefaulttimeout(self.timeout)
            return socket.gethostbyname(host)
        except (socket.gaierror, socket.timeout):
            return None
        finally:
            socket.setdefaulttimeout(None)

    def _detect_wildcard(self, domain: str) -> Optional[str]:
        test_label = f"{random.randint(100000, 999999)}-qx-test"
        return self._resolve(f"{test_label}.{domain}")
