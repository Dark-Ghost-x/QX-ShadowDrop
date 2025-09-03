#!/usr/bin/env python3
import os
import json
import re
from datetime import datetime

from config import paths

def safe_name(name: str) -> str:
    name = name.replace("://", "_")
    name = re.sub(r"[^\w\.-]+", "_", name)
    return name.strip("_") or "report"

def save_report(domain: str, module_name: str, data: dict, timestamp: str = None) -> str:
    os.makedirs(paths.OUTPUT_DIR, exist_ok=True)
    ts = timestamp or datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_domain = safe_name(domain)
    filename = f"{safe_domain}.json"
    filepath = os.path.join(paths.OUTPUT_DIR, filename)

    report = None
    if os.path.exists(filepath):
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                report = json.load(f)
        except (json.JSONDecodeError, OSError):
            backup = os.path.join(paths.OUTPUT_DIR, f"{safe_domain}.corrupt")
            try:
                os.replace(filepath, backup)
            except OSError:
                pass
            report = None

    if not report:
        report = {"domain": domain, "created_at": ts, "modules": {}}

    report["modules"][module_name] = {
        "timestamp": ts,
        "data": data
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return filepath

if __name__ == "__main__":
    path = save_report(
        "https://example.com",
        "headers",
        {"ok": True, "headers": {"Server": "nginx"}},
    )
    print(f"[+] Saved: {path}")
