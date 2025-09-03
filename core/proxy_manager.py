#!/usr/bin/env python3
import os
import random
import threading
from typing import List, Optional, Iterable
import requests
from config import settings, paths

MANUAL_PROXIES_FILE = os.environ.get("QX_PROXY_FILE", os.path.join(paths.CONFIG_DIR, "manual_proxies.txt"))
DEFAULT_PROXY_SOURCES: List[str] = []
_env_sources = os.environ.get("QX_PROXY_SOURCES", "").strip()
if _env_sources:
    DEFAULT_PROXY_SOURCES = [s.strip() for s in _env_sources.split(",") if s.strip()]
PROXY_SOURCES: List[str] = getattr(settings, "PROXY_SOURCES", DEFAULT_PROXY_SOURCES)
REQUEST_TIMEOUT: int = int(getattr(settings, "TIMEOUT", 6))

_LOCK = threading.RLock()
_ALL_PROXIES: List[str] = []
_VALID_PROXIES: List[str] = []
_INITIALIZED = False

def _normalize_proxy(p: str) -> Optional[str]:
    p = p.strip()
    if not p:
        return None
    if "://" not in p:
        p = f"http://{p}"
    if p.startswith(("http://", "https://", "socks5://", "socks5h://")):
        return p
    return None

def _dedupe(seq: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def load_manual_proxies() -> List[str]:
    if not os.path.exists(MANUAL_PROXIES_FILE):
        return []
    with open(MANUAL_PROXIES_FILE, "r", encoding="utf-8") as f:
        items = [line.strip() for line in f if line.strip()]
    norm = [_normalize_proxy(p) for p in items]
    return [p for p in norm if p]

def fetch_from_source(url: str) -> List[str]:
    try:
        r = requests.get(url, timeout=REQUEST_TIMEOUT)
        if r.ok:
            lines = [ln.strip() for ln in r.text.splitlines() if ln.strip()]
            norm = [_normalize_proxy(p) for p in lines]
            return [p for p in norm if p]
    except Exception:
        return []
    return []

def fetch_proxies() -> List[str]:
    proxies: List[str] = []
    proxies.extend(load_manual_proxies())
    for src in PROXY_SOURCES:
        proxies.extend(fetch_from_source(src))
    return _dedupe(proxies)

def _is_proxy_alive(proxy: str, timeout: int = REQUEST_TIMEOUT) -> bool:
    test_url = "https://httpbin.org/ip"
    proxies = {"http": proxy, "https": proxy}
    try:
        r = requests.get(test_url, proxies=proxies, timeout=timeout)
        return r.ok
    except Exception:
        return False

def _ensure_initialized() -> None:
    global _INITIALIZED, _ALL_PROXIES, _VALID_PROXIES
    with _LOCK:
        if _INITIALIZED:
            return
        _ALL_PROXIES = fetch_proxies()
        manual = load_manual_proxies()
        ordered = manual + [p for p in _ALL_PROXIES if p not in manual]
        _ALL_PROXIES = _dedupe(ordered)
        _VALID_PROXIES.clear()
        _INITIALIZED = True

def get_random_proxy() -> Optional[str]:
    _ensure_initialized()
    with _LOCK:
        if not _VALID_PROXIES and _ALL_PROXIES:
            sample = _ALL_PROXIES[:32]
            alive = [p for p in sample if _is_proxy_alive(p)]
            if alive:
                _VALID_PROXIES.extend(_dedupe(alive))
        pool = _VALID_PROXIES or _ALL_PROXIES
        return random.choice(pool) if pool else None

def update_valid_proxies(new_valid: Optional[Iterable[str]] = None) -> None:
    _ensure_initialized()
    with _LOCK:
        if new_valid is not None:
            norm = [_normalize_proxy(p) for p in new_valid if p]
            norm = [p for p in norm if p]
            _VALID_PROXIES[:] = _dedupe(norm) if norm else []
            return
        if _ALL_PROXIES:
            sample = _ALL_PROXIES[:64]
            alive = [p for p in sample if _is_proxy_alive(p)]
            _VALID_PROXIES[:] = _dedupe(alive)

def refresh_all_proxies() -> None:
    global _ALL_PROXIES, _VALID_PROXIES
    with _LOCK:
        _ALL_PROXIES = fetch_proxies()
        _VALID_PROXIES.clear()
