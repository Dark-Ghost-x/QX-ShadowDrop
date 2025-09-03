#!/usr/bin/env python3
import socket
import concurrent.futures
import time
import random
from urllib.parse import urlparse
from typing import List, Dict, Any, Optional, Set
from ipaddress import ip_address, IPv4Address, IPv6Address
from .vulnerability_base import VulnerabilityModule
from config import settings

class Scanner(VulnerabilityModule):
    name = "advanced_port_scan"
    enabled = True
    useproxy = False
    max_workers = getattr(settings, "PORTSCAN_WORKERS", 100)
    timeout = min(float(getattr(settings, "TIMEOUT", 2.0)), 5.0)
    aggressive = getattr(settings, "AGGRESSIVE", False)
    debug_mode = getattr(settings, "DEBUG", False)
    scan_delay = max(0.0, float(getattr(settings, "SCAN_DELAY", 0.1)))
    DEFAULT_PORTS = {
        "web": [80, 443, 8080, 8443, 8888, 8000, 8008, 8081, 8090, 8880, 8444],
        "database": [3306, 5432, 27017, 6379, 1433, 1521, 26257, 9042, 9200, 11211],
        "admin": [22, 21, 23, 3389, 2222, 222, 22222, 2375, 2376, 4848, 9000],
        "services": [25, 53, 110, 143, 995, 465, 587, 993, 119, 563, 123, 161, 162, 389, 636],
        "files": [139, 445, 2049, 111, 135, 137, 138],
        "vpn": [500, 1701, 1723, 4500, 51820],
        "industrial": [502, 44818, 1911, 1962, 2404, 4000, 4840, 4911],
        "full": list(range(1, 1024)) + [1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 27017]
    }
    AGGRESSIVE_PORTS = {
        "critical_services": [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 27017, 2375, 2376, 4848, 11211, 9200, 5900, 2049, 111, 161, 162],
        "industrial_control": [502, 1911, 1962, 2404, 4000, 4840, 4911, 44818, 55000, 55555, 56001],
        "iot_devices": [1883, 8883, 5683, 5684, 8083, 8084, 8884, 4443, 4840, 49152, 54321, 65535],
        "cloud_services": [2375, 2376, 2377, 2379, 2380, 4001, 6443, 7474, 7687, 8001, 8086, 8091, 8094, 8140, 8200, 8300, 8400, 8500, 8600, 9000, 9042, 9092, 9200, 9300, 11211, 27017, 28015, 50000],
        "vpn_protocols": [500, 1194, 1701, 1723, 1812, 1813, 4500, 5000, 51820, 61900, 61901],
        "database_services": [1433, 1434, 1521, 1830, 2483, 2484, 26257, 3050, 3306, 3351, 4444, 5000, 5432, 5984, 6379, 7199, 7200, 7473, 7474, 7687, 8000, 8087, 8091, 8098, 8099, 8123, 8182, 8529, 8629, 8649, 8983, 9042, 9071, 9092, 9160, 9200, 9300, 11211, 11214, 11215, 27017, 27018, 27019, 28015, 29015],
        "monitoring_services": [3000, 4242, 5601, 6000, 6066, 7077, 8088, 8090, 8125, 8126, 8181, 9090, 9091, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100, 9115, 9125, 9126, 9130, 9200, 9250, 9300, 9400, 9402, 9403, 9779, 9876, 10000, 10050, 10051, 10114, 10250, 10255, 10256, 10443, 11211, 14250, 14265, 15000, 15001, 15002, 15003, 15004, 15010, 15151, 15432, 15672, 15692, 15720, 16010, 16020, 16030, 16225, 16379, 18080, 18081, 18126, 19001, 19100, 19200, 19531, 20000, 21000, 22000, 23000, 24000, 25000, 26000, 27000, 28000, 29000, 30000],
        "security_services": [512, 513, 514, 515, 1080, 1434, 1720, 1723, 2000, 2049, 2121, 2222, 2375, 2376, 3128, 3389, 3632, 4369, 4786, 4800, 5000, 5060, 5061, 5432, 5631, 5632, 5666, 5800, 5900, 6000, 6001, 6379, 6443, 6481, 6482, 6646, 7000, 7001, 7002, 7070, 7071, 7080, 7081, 7090, 7091, 7100, 7101, 7200, 7201, 7272, 7273, 7280, 7281, 7290, 7291, 7300, 7301, 7310, 7311, 7320, 7321, 7330, 7331, 7340, 7341, 7350, 7351, 7360, 7361, 7370, 7371, 7380, 7381, 7390, 7391, 7400, 7401, 7410, 7411, 7420, 7421, 7430, 7431, 7440, 7441, 7450, 7451, 7460, 7461, 7470, 7471, 7480, 7481, 7490, 7491, 7500, 7501, 7510, 7511, 7520, 7521, 7530, 7531, 7540, 7541, 7550, 7551, 7560, 7561, 7570, 7571, 7580, 7581, 7590, 7591, 7600, 7601, 7610, 7611, 7620, 7621, 7630, 7631, 7640, 7641, 7650, 7651, 7660, 7661, 7670, 7671, 7680, 7681, 7690, 7691, 7700, 7701, 7710, 7711, 7720, 7721, 7730, 7731, 7740, 7741, 7750, 7751, 7760, 7761, 7770, 7771, 7780, 7781, 7790, 7791, 7800]
    }
    SERVICE_MAP = {
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp", 68: "dhcp",
        69: "tftp", 80: "http", 110: "pop3", 111: "rpcbind", 119: "nntp", 123: "ntp", 135: "msrpc",
        139: "netbios-ssn", 143: "imap", 161: "snmp", 162: "snmptrap", 389: "ldap", 443: "https",
        445: "microsoft-ds", 465: "smtps", 587: "smtp-submission", 636: "ldaps", 993: "imaps",
        995: "pop3s", 1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs", 2375: "docker",
        2376: "docker-tls", 3306: "mysql", 3389: "rdp", 4500: "ipsec-nat-t", 4848: "glassfish",
        5432: "postgresql", 5900: "vnc", 6379: "redis", 8000: "http-alt", 8008: "http-alt",
        8080: "http-proxy", 8081: "http-alt", 8443: "https-alt", 8888: "http-alt", 9000: "sonarqube",
        9200: "elasticsearch", 11211: "memcache", 27017: "mongodb", 51820: "wireguard"
    }
    RISK_LEVELS = {
        "critical": {21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 6379, 27017, 2375, 2376, 4848, 11211, 9200, 5900, 2049, 111, 161, 162},
        "high": {3306, 5432, 27017, 6379, 11211, 9200, 5900, 2049, 111, 161, 162, 502, 44818, 1911, 1962, 2404, 4000, 4840, 4911},
        "medium": {80, 443, 8080, 8443, 8000, 8888, 25, 110, 143, 389, 636, 993, 995, 500, 1701, 1723, 4500, 51820},
        "low": {53, 123, 500, 1701, 1723, 4500, 51820, 67, 68, 69, 119, 135, 137, 138, 161, 162, 389, 636}
    }
    VULNERABILITY_TESTS = {
        21: ["anonymous_login", "banner_analysis", "brute_force"],
        22: ["weak_ssh_keys", "banner_analysis", "brute_force", "ssh_version_detect"],
        23: ["banner_analysis", "default_credentials", "brute_force"],
        25: ["open_relay", "banner_analysis", "smtp_user_enum"],
        53: ["dns_zone_transfer", "dns_cache_poisoning", "dns_amplification"],
        80: ["http_methods", "security_headers", "directory_traversal", "http_vulnerabilities", "web_app_tests"],
        110: ["pop3_brute_force", "banner_analysis"],
        143: ["imap_brute_force", "banner_analysis"],
        443: ["ssl_tls_test", "security_headers", "heartbleed", "poodle", "freak", "logjam", "ccs_injection", "ssl_v2_v3", "weak_ciphers"],
        445: ["smb_vulnerabilities", "eternalblue", "smb_brute_force", "smb_shares", "smb_version"],
        993: ["imap_ssl_test", "banner_analysis"],
        995: ["pop3_ssl_test", "banner_analysis"],
        1433: ["default_credentials", "banner_analysis", "mssql_brute_force"],
        1521: ["default_credentials", "banner_analysis", "oracle_brute_force"],
        3306: ["default_credentials", "banner_analysis", "mysql_brute_force"],
        3389: ["bluekeep", "banner_analysis", "rdp_brute_force"],
        5432: ["default_credentials", "banner_analysis", "postgres_brute_force"],
        6379: ["unauthorized_access", "banner_analysis", "redis_brute_force"],
        27017: ["unauthorized_access", "banner_analysis", "mongodb_brute_force"],
        11211: ["unauthorized_access", "memcache_stats"],
        9200: ["unauthorized_access", "elasticsearch_info"]
    }
    
    def __init__(self, *args, **kwargs):
        target = None
        session = None
        timeout = 2.0
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
            
        self.target = target
        self.session = session
        self.timeout = timeout
        self.debug_mode = debug
        self.aggressive = aggressive
        
        if stealth is not None:
            self.bypass_protection = stealth
        else:
            self.bypass_protection = False
            
        self.custom_ports = self._load_custom_ports()
        self.scan_stats = {
            "total_ports": 0,
            "open_ports": 0,
            "closed_ports": 0,
            "filtered_ports": 0,
            "vulnerable_ports": 0
        }
        self.vulnerable_ports = []
        
    def _load_custom_ports(self):
        custom = getattr(settings, "CUSTOM_PORTS", None)
        return set(custom) if custom else set()
        
    def _resolve_host(self, target):
        try:
            if "://" not in target:
                target = f"http://{target}"
            parsed = urlparse(target)
            host = parsed.hostname or target.split("/")[0].split(":")[0]
            try:
                ip = ip_address(host)
                return str(ip)
            except ValueError:
                try:
                    return socket.gethostbyname(host)
                except socket.gaierror:
                    try:
                        return socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
                    except:
                        raise ValueError(f"Cannot resolve host: {host}")
        except Exception as e:
            raise ValueError(f"Host resolution failed: {str(e)}")
            
    def _get_ports_to_scan(self, profile=None, custom_ports=None):
        if custom_ports:
            ports = list(set(custom_ports))
        elif profile and profile in self.DEFAULT_PORTS:
            ports = self.DEFAULT_PORTS[profile]
        else:
            ports = []
            for pgroup in self.DEFAULT_PORTS.values():
                if isinstance(pgroup, list):
                    ports.extend(pgroup)
        if self.custom_ports:
            ports.extend(self.custom_ports)
        if self.aggressive:
            for aggressive_group in self.AGGRESSIVE_PORTS.values():
                ports.extend(aggressive_group)
            if profile != "full":
                ports.extend(self.DEFAULT_PORTS["services"])
                ports.extend(self.DEFAULT_PORTS["admin"])
                ports.extend(self.DEFAULT_PORTS["industrial"])
                ports.extend(self.DEFAULT_PORTS["vpn"])
        return sorted(set(ports))
        
    def _test_vulnerability(self, host, port, service):
        if not self.aggressive:
            return None
        if port not in self.VULNERABILITY_TESTS:
            return None
        tests = self.VULNERABILITY_TESTS[port]
        vulnerabilities = []
        try:
            for test in tests:
                if test == "anonymous_login" and service == "ftp":
                    vuln_result = self._test_ftp_anonymous(host, port)
                    if vuln_result:
                        vulnerabilities.append(vuln_result)
                elif test == "ssl_tls_test" and service == "https":
                    vuln_result = self._test_ssl_vulnerabilities(host, port)
                    if vuln_result:
                        vulnerabilities.append(vuln_result)
                elif test == "unauthorized_access" and service in ["redis", "mongodb"]:
                    vuln_result = self._test_unauthorized_access(host, port, service)
                    if vuln_result:
                        vulnerabilities.append(vuln_result)
                elif test == "smb_vulnerabilities" and service == "microsoft-ds":
                    vuln_result = self._test_smb_vulnerabilities(host, port)
                    if vuln_result:
                        vulnerabilities.append(vuln_result)
                elif test == "http_vulnerabilities" and service == "http":
                    vuln_result = self._test_http_vulnerabilities(host, port)
                    if vuln_result:
                        vulnerabilities.append(vuln_result)
                elif test == "dns_zone_transfer" and service == "dns":
                    vuln_result = self._test_dns_zone_transfer(host, port)
                    if vuln_result:
                        vulnerabilities.append(vuln_result)
        except Exception as e:
            if self.debug_mode:
                print(f"[DEBUG] Vulnerability test error for port {port}: {str(e)}")
        return vulnerabilities if vulnerabilities else None
        
    def _test_ftp_anonymous(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    sock.send(b"USER anonymous\r\n")
                    response = sock.recv(1024).decode(errors="ignore")
                    if "331" in response:
                        sock.send(b"PASS anonymous\r\n")
                        response = sock.recv(1024).decode(errors="ignore")
                        if "230" in response:
                            return "ftp_anonymous_login"
        except:
            pass
        return None
        
    def _test_ssl_vulnerabilities(self, host, port):
        try:
            import ssl
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    return f"ssl_tls_vulnerability:{ssock.version()}"
        except:
            return "ssl_tls_vulnerability"
        
    def _test_unauthorized_access(self, host, port, service):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    if service == "redis":
                        sock.send(b"PING\r\n")
                        response = sock.recv(1024).decode(errors="ignore")
                        if "PONG" in response:
                            return "redis_unauthorized_access"
                    elif service == "mongodb":
                        sock.send(b"\x3a\x00\x00\x00\xa7\x00\x00\x00\x00\x00\x00\x00\xd4\x07\x00\x00\x00\x00\x00\x00admin.$cmd\x00\x00\x00\x00\x00\xff\xff\xff\xff\x13\x00\x00\x00\x10isMaster\x00\x01\x00\x00\x00\x00")
                        time.sleep(0.5)
                        response = sock.recv(1024)
                        if response:
                            return "mongodb_unauthorized_access"
                    elif service == "memcache":
                        sock.send(b"stats\r\n")
                        response = sock.recv(1024).decode(errors="ignore")
                        if "STAT" in response:
                            return "memcache_unauthorized_access"
        except:
            pass
        return None
        
    def _test_smb_vulnerabilities(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    sock.send(b"\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00")
                    response = sock.recv(1024)
                    if response:
                        return "smb_version_detected"
        except:
            pass
        return None
        
    def _test_http_vulnerabilities(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    sock.send(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
                    response = sock.recv(4096).decode(errors="ignore")
                    if "Server:" in response:
                        return f"http_server_info:{response.split('Server:')[1].split('\r\n')[0].strip()}"
        except:
            pass
        return None
        
    def _test_dns_zone_transfer(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    sock.send(b"\x00\x1a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07\x65\x78\x61\x6d\x70\x6c\x65\x03\x63\x6f\x6d\x00\x00\xfc\x00\x01")
                    response = sock.recv(4096)
                    if len(response) > 12:
                        return "dns_zone_transfer_possible"
        except:
            pass
        return None
        
    def _scan_port(self, host, port):
        result = {
            "port": port,
            "status": "closed",
            "service": self.SERVICE_MAP.get(port, "unknown"),
            "banner": None,
            "response_time": None,
            "vulnerabilities": []
        }
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                connection_result = sock.connect_ex((host, port))
                if connection_result == 0:
                    result["status"] = "open"
                    result["banner"] = self._get_banner(sock, port)
                    if self.aggressive:
                        vulns = self._test_vulnerability(host, port, result["service"])
                        if vulns:
                            result["vulnerabilities"] = vulns
                            self.scan_stats["vulnerable_ports"] += 1
                            self.vulnerable_ports.append({
                                "port": port,
                                "service": result["service"],
                                "vulnerabilities": vulns
                            })
                    self.scan_stats["open_ports"] += 1
                elif connection_result == 111:
                    result["status"] = "filtered"
                    self.scan_stats["filtered_ports"] += 1
                else:
                    self.scan_stats["closed_ports"] += 1
        except socket.timeout:
            result["status"] = "filtered"
            self.scan_stats["filtered_ports"] += 1
        except Exception as e:
            if self.debug_mode:
                print(f"[DEBUG] Port {port} scan error: {str(e)}")
            result["status"] = "error"
            result["error"] = str(e)
        result["response_time"] = round(time.time() - start_time, 3)
        return result
        
    def _get_banner(self, sock, port):
        try:
            sock.settimeout(2.0)
            if port in [21, 22, 25, 110, 143, 587, 993, 995]:
                banner = sock.recv(1024).decode(errors="ignore").strip()
                return banner[:500] if banner else None
            elif port == 80 or port == 8080 or port == 8081:
                sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                return sock.recv(1024).decode(errors="ignore").strip()[:500]
            elif port == 443 or port == 8443:
                return "SSL/TLS Service Detected"
            else:
                sock.send(b"\r\n\r\n")
                time.sleep(0.1)
                return sock.recv(512).decode(errors="ignore").strip()[:200]
        except Exception:
            return None
            
    def _assess_risk(self, open_ports):
        open_port_nums = {p["port"] for p in open_ports}
        for risk_level, ports in self.RISK_LEVELS.items():
            if open_port_nums & ports:
                if risk_level == "critical":
                    return "critical"
                elif risk_level == "high":
                    return "high"
        if any(p["banner"] for p in open_ports):
            return "medium"
        return "low" if open_ports else "informational"
        
    def _get_risk_analysis(self, open_ports):
        analysis = {}
        open_port_nums = {p["port"] for p in open_ports}
        for risk_level, ports in self.RISK_LEVELS.items():
            found_ports = open_port_nums & ports
            if found_ports:
                analysis[risk_level] = sorted(found_ports)
        return analysis
        
    def _confirm_open_port(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                if sock.connect_ex((host, port)) == 0:
                    return True
        except:
            pass
        return False
        
    def scan(self, target=None, profile=None, ports=None, **kwargs):
        target_host = target or self.target
        if not target_host:
            return {
                "status": "failed",
                "error": "No target specified",
                "risk_level": "low"
            }
        try:
            host = self._resolve_host(target_host)
            port_list = self._get_ports_to_scan(profile, ports)
            self.scan_stats["total_ports"] = len(port_list)
            if self.debug_mode:
                print(f"[DEBUG] Scanning {host} with {len(port_list)} ports")
                print(f"[DEBUG] Profile: {profile}, Aggressive: {self.aggressive}")
            results = []
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_port = {
                    executor.submit(self._scan_port, host, port): port
                    for port in port_list
                }
                for future in concurrent.futures.as_completed(future_to_port):
                    if self.scan_delay > 0:
                        time.sleep(self.scan_delay * random.uniform(0.5, 1.5))
                    results.append(future.result())
            open_ports = [r for r in results if r["status"] == "open"]
            
            # تأیید مجدد پورت‌های باز برای اطمینان از باز بودن آنها
            confirmed_open_ports = []
            for port_result in open_ports:
                if self._confirm_open_port(host, port_result["port"]):
                    confirmed_open_ports.append(port_result)
            
            risk = self._assess_risk(confirmed_open_ports)
            risk_analysis = self._get_risk_analysis(confirmed_open_ports)
            
            # ایجاد خروجی نهایی با اطمینان از باز بودن پورت‌ها
            final_evidence = []
            for port_result in confirmed_open_ports:
                port_info = {
                    "port": port_result["port"],
                    "service": port_result["service"],
                    "status": "open",
                    "response_time": port_result["response_time"],
                    "confirmed": True
                }
                if port_result["banner"]:
                    port_info["banner"] = port_result["banner"]
                if port_result["vulnerabilities"]:
                    port_info["vulnerabilities"] = port_result["vulnerabilities"]
                final_evidence.append(port_info)
            
            return {
                "status": "completed",
                "target": target_host,
                "resolved_ip": host,
                "scan_stats": self.scan_stats,
                "vulnerable_ports": self.vulnerable_ports,
                "risk_level": risk,
                "risk_analysis": risk_analysis,
                "evidence": final_evidence,
                "configuration": {
                    "timeout": self.timeout,
                    "workers": self.max_workers,
                    "profile": profile or "custom",
                    "aggressive_mode": self.aggressive,
                    "scan_delay": self.scan_delay
                }
            }
        except Exception as e:
            return {
                "status": "failed",
                "error": str(e),
                "target": target_host,
                "risk_level": "low"
            }
            
    def run(self, **kwargs):
        return self.scan(**kwargs)
