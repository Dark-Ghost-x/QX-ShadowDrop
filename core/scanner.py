#!/usr/bin/env python3
import os
import importlib
import traceback
from typing import Dict, Any, Tuple, List, Optional, Type
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from config.paths import MODULES_DIR
from config import settings
from core.proxy_manager import get_random_proxy, update_valid_proxies

class Scanner:
    def __init__(self, target, session=None, proxies=None, config=None, report_dir=None):
        self.target = target
        self.session = session
        self.proxies = proxies
        self.config = config
        self.report_dir = report_dir

IGNORE_FILES = {"__init__.py", "vulnerability_base.py"}

PREFERRED_ORDER = [
    "subdomain_enum",
    "tech_stack",
    "headers",
    "wayback_scraper",
    "sensitive_info",
    "port_scan",
    "download",
    "admin_panels",
    "open_redirect",
    "clickjacking",
    "csrf",
    "directory_traversal",
    "lfi",
    "rfi",
    "command_injection",
    "sql_injection",
    "xss"
]

def _get_setting(name: str, alt: Optional[str] = None, default: Any = None) -> Any:
    if hasattr(settings, name):
        return getattr(settings, name)
    if alt and hasattr(settings, alt):
        return getattr(settings, alt)
    return default

def debug(msg: str) -> None:
    if _get_setting("DEBUG", default=False):
        print(f"[DEBUG] {msg}")

def _module_wants_proxy(mod_cls: Type) -> bool:
    if hasattr(mod_cls, "useproxy"):
        return bool(getattr(mod_cls, "useproxy"))
    if hasattr(mod_cls, "use_proxy"):
        return bool(getattr(mod_cls, "use_proxy"))
    return False

def _module_name(mod_cls: Type, fallback: Optional[str] = None) -> str:
    if hasattr(mod_cls, "name"):
        return str(getattr(mod_cls, "name"))
    return fallback or mod_cls.__name__.lower()

def load_modules() -> List[Type]:
    modules: List[Type] = []
    try:
        entries = sorted(os.listdir(MODULES_DIR))
    except FileNotFoundError:
        debug(f"MODULES_DIR not found: {MODULES_DIR}")
        return modules
    for fname in entries:
        if not fname.endswith(".py") or fname in IGNORE_FILES:
            continue
        mod_name = fname[:-3]
        try:
            mod = importlib.import_module(f"core.modules.{mod_name}")
        except Exception as e:
            debug(f"Failed to import {mod_name}: {e}")
            if _get_setting("DEBUG", default=False):
                traceback.print_exc()
            continue
        mod_cls = getattr(mod, "Scanner", None) or getattr(mod, "MODULE", None)
        if mod_cls is None:
            debug(f"Skipping {mod_name}: no Scanner/MODULE class found")
            continue
        if getattr(mod_cls, "enabled", True) is False:
            debug(f"Skipping {mod_name}: disabled")
            continue
        modules.append(mod_cls)
    return order_modules(modules)

def order_modules(modules: List[Type]) -> List[Type]:
    by_name = {_module_name(m): m for m in modules}
    ordered: List[Type] = []
    for name in PREFERRED_ORDER:
        if name in by_name:
            ordered.append(by_name.pop(name))
    for name in sorted(by_name.keys()):
        ordered.append(by_name[name])
    debug("Final module order: " + ", ".join(_module_name(m) for m in ordered))
    return ordered

def make_session() -> requests.Session:
    s = requests.Session()
    s.trust_env = True
    ua = _get_setting("USERAGENT", alt="USER_AGENT", default="QX-ShadowDrop/2.0")
    s.headers.update({"User-Agent": ua})
    return s

def _resolve_proxies(wants_proxy: bool) -> Optional[Dict[str, str]]:
    use_proxy_glob = bool(_get_setting("USE_PROXY", alt="USEPROXY", default=False))
    if not wants_proxy or not use_proxy_glob:
        return None
    p = get_random_proxy()
    if p:
        return {"http": p, "https": p}
    try:
        debug("No proxies available; refreshing proxy pool")
        update_valid_proxies()
    except Exception as e:
        debug(f"Proxy refresh failed: {e}")
    p2 = get_random_proxy()
    return {"http": p2, "https": p2} if p2 else None

def _coerce_result(out: Any) -> Dict[str, Any]:
    if isinstance(out, dict):
        ok = out.get("ok")
        risk = out.get("risk")
        evidence = out.get("evidence")
        notes = out.get("notes")
        if ok is None:
            ok = True
        if risk is None:
            risk = "low"
        if evidence is None:
            evidence = []
        if notes is None and "error" in out:
            notes = str(out.get("error"))
        if notes is None:
            notes = ""
        base = {"ok": ok, "risk": risk, "evidence": evidence, "notes": notes}
        rest = {k: v for k, v in out.items() if k not in base}
        return {**base, **rest}
    return {"ok": True, "risk": "low", "evidence": [], "notes": ""}

def _run_single_module(mod_cls: Type, target: str) -> Tuple[str, Dict[str, Any]]:
    name = _module_name(mod_cls)
    wants_proxy = _module_wants_proxy(mod_cls)
    session = make_session()
    proxies = _resolve_proxies(wants_proxy)
    try:
        instance = mod_cls(target, session=session, proxies=proxies)
        result = instance.run() if hasattr(instance, 'run') else instance.scan()
        return name, _coerce_result(result)
    except Exception as e:
        if _get_setting("DEBUG", default=False):
            traceback.print_exc()
        return name, {"ok": False, "risk": "low", "evidence": [], "notes": str(e)}

def scan_target(target: str) -> Dict[str, Any]:
    results: Dict[str, Any] = {"target": target, "modules": {}}
    modules = load_modules()
    if _get_setting("USE_PROXY", alt="USEPROXY", default=False) and not get_random_proxy():
        try:
            debug("Proxy requested; warming up proxy pool")
            update_valid_proxies()
        except Exception as e:
            debug(f"Proxy warm-up failed: {e}")
    parallel = bool(_get_setting("PARALLEL", default=True))
    if not parallel:
        debug("Running modules sequentially")
        for mod in modules:
            name, output = _run_single_module(mod, target)
            results["modules"][name] = output
        return results
    max_workers = max(1, min(len(modules), int(_get_setting("MAX_WORKERS", default=4))))
    if bool(_get_setting("STEALTH_ONLY", default=False)):
        max_workers = min(max_workers, 2)
    debug(f"Running modules in parallel with max_workers={max_workers}")
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_run_single_module, mod, target): mod for mod in modules}
        for future in as_completed(futures):
            name, output = future.result()
            results["modules"][name] = output
    return results
