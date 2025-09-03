#!/usr/bin/env python3
import argparse
import concurrent.futures
import importlib
import json
import logging
import os
import re
import sys
import traceback
from datetime import datetime
from urllib.parse import urlparse

VERSION = "1.0"
DEBUG = False
VERBOSE = False

BASEDIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(BASEDIR, "core"))
sys.path.insert(0, os.path.join(BASEDIR, "config"))
sys.path.insert(0, os.path.join(BASEDIR, "utils"))

class Colors:
    PURPLE = "\033[95m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    RESET = "\033[0m"

    @classmethod
    def print(cls, text, color):
        color_code = getattr(cls, color.upper(), "")
        print(f"{color_code}{text}{cls.RESET}")

def show_banner():
    banner = r"""
      .      .       .*     .        🌑  .      .      .   ·      ☆   
        *       .         .    ○    .     .       *        .
    .      .     ★   .    .       ·      .    🪐      °      *   
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
              QX-ShadowDrop v{version}
    Created By: Red:Telegram)t.me/Red_Rooted_Ghost
    ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    """.format(version=VERSION)
    Colors.print(banner, "RED")

def parse_arguments():
    parser = argparse.ArgumentParser(
        description=f"QX-ShadowDrop v{VERSION} - Advanced Security Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-t", "--target", required=True, help="Target to scan (URL, domain or IP)")
    parser.add_argument("-m", "--module", help="Specific module(s) to run (comma-separated)")
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("--aggressive", action="store_true", help="Enable aggressive scanning mode")
    scan_group.add_argument("--stealth", action="store_true", help="Enable stealth mode (slower but less detectable)")
    advanced_group = parser.add_argument_group("Advanced Options")
    advanced_group.add_argument("--workers", type=int, default=10, help="Number of parallel workers")
    advanced_group.add_argument("--timeout", type=int, default=15, help="Request timeout in seconds")
    advanced_group.add_argument("--retries", type=int, default=2, help="Number of retries for failed requests")
    debug_group = parser.add_argument_group("Debugging")
    debug_group.add_argument("--debug", action="store_true", help="Enable debug output")
    debug_group.add_argument("--verbose", action="store_true", help="Show detailed output")
    return parser.parse_args()

def validate_target(target):
    try:
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', target):
            return f"http://{target}"
        if not re.match(r'^https?://', target):
            target = f"http://{target}"
        parsed = urlparse(target)
        if not parsed.netloc:
            raise ValueError("Invalid target format")
        return f"{parsed.scheme}://{parsed.netloc}"
    except Exception as e:
        Colors.print(f"[!] Invalid target: {str(e)}", "RED")
        sys.exit(1)

def load_modules():
    modules = {}
    modules_dir = os.path.join(BASEDIR, "core", "modules")
    if not os.path.exists(modules_dir):
        Colors.print(f"[!] Modules directory not found: {modules_dir}", "RED")
        return modules
    for module_file in sorted(os.listdir(modules_dir)):
        if module_file.endswith(".py") and not module_file.startswith("_"):
            module_name = module_file[:-3]
            module_path = f"core.modules.{module_name}"
            try:
                module = importlib.import_module(module_path)
                if hasattr(module, "Scanner"):
                    module.name = module_name
                    modules[module_name] = module
                    if DEBUG:
                        Colors.print(f"[*] Successfully loaded module: {module_name}", "CYAN")
                else:
                    if DEBUG:
                        Colors.print(f"[!] Module {module_name} doesn't have Scanner class", "YELLOW")
            except Exception as e:
                if DEBUG:
                    Colors.print(f"[!] Failed to load {module_name}: {str(e)}", "RED")
                    traceback.print_exc()
    return modules

def run_module(module, target, **kwargs):
    try:
        scanner = module.Scanner(target, **kwargs)
        result = scanner.scan()
        if not isinstance(result, dict):
            result = {"data": result}
        result.update({
            "status": "success",
            "module": module.name,
            "timestamp": datetime.now().isoformat()
        })
        return result
    except Exception as e:
        if DEBUG:
            traceback.print_exc()
        return {
            "status": "error",
            "error": str(e),
            "module": module.name,
            "timestamp": datetime.now().isoformat()
        }

def save_report(target, data, scan_type="full_scan"):
    try:
        reports_dir = os.path.join(BASEDIR, "reports")
        os.makedirs(reports_dir, exist_ok=True)
        domain = urlparse(target).netloc
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_{domain}_{timestamp}_{scan_type}.json"
        report_path = os.path.join(reports_dir, filename)
        with open(report_path, 'w') as f:
            json.dump(data, f, indent=2)
        return report_path
    except Exception as e:
        raise Exception(f"Failed to save report: {str(e)}")

def main():
    global DEBUG, VERBOSE
    show_banner()
    args = parse_arguments()
    DEBUG = args.debug
    VERBOSE = args.verbose
    target = validate_target(args.target)
    Colors.print(f"[*] Target: {target}", "CYAN")
    Colors.print("[*] Loading modules...", "CYAN")
    all_modules = load_modules()
    if not all_modules:
        Colors.print("[!] No modules could be loaded", "RED")
        sys.exit(1)
    Colors.print(f"[+] Successfully loaded {len(all_modules)} modules", "GREEN")
    selected_modules = {}
    if args.module:
        requested_modules = [m.strip() for m in args.module.split(",")]
        for module_name in requested_modules:
            if module_name in all_modules:
                selected_modules[module_name] = all_modules[module_name]
                Colors.print(f"[*] Selected module: {module_name}", "CYAN")
            else:
                Colors.print(f"[!] Module not found: {module_name}", "YELLOW")
    else:
        selected_modules = all_modules
    if not selected_modules:
        Colors.print("[!] No valid modules selected", "RED")
        sys.exit(1)
    common_kwargs = {
        "aggressive": args.aggressive,
        "stealth": args.stealth,
        "timeout": args.timeout,
        "retries": args.retries,
        "debug": DEBUG,
        "verbose": VERBOSE
    }
    Colors.print("[*] Starting scan...", "CYAN")
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = {executor.submit(run_module, mod, target, **common_kwargs): name for name, mod in selected_modules.items()}
        for future in concurrent.futures.as_completed(futures):
            module_name = futures[future]
            try:
                module_result = future.result()
                results[module_name] = module_result
                if module_result.get("status") == "success":
                    Colors.print(f"[+] {module_name} completed successfully", "GREEN")
                    if VERBOSE and "data" in module_result:
                        print(json.dumps(module_result["data"], indent=2))
                else:
                    Colors.print(f"[!] {module_name} failed: {module_result.get('error', 'Unknown error')}", "YELLOW")
            except Exception as e:
                Colors.print(f"[!] Critical error in {module_name}: {str(e)}", "RED")
                results[module_name] = {"status": "critical_error", "error": str(e), "module": module_name}
    report_data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "settings": common_kwargs,
        "results": results
    }
    try:
        report_path = save_report(target=target, data=report_data, scan_type="full_scan" if not args.module else "custom_scan")
        Colors.print(f"[+] Report saved to: {report_path}", "GREEN")
    except Exception as e:
        Colors.print(f"[!] Failed to save report: {str(e)}", "RED")
    success = sum(1 for r in results.values() if r.get("status") == "success")
    failed = len(results) - success
    Colors.print("\n[+] Scan Summary:", "CYAN")
    Colors.print(f"  - Modules executed: {len(results)}", "CYAN")
    Colors.print(f"  - Successful: {success}", "GREEN")
    Colors.print(f"  - Failed: {failed}", "RED" if failed > 0 else "GREEN")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        Colors.print("\n[!] Scan interrupted by user", "RED")
        sys.exit(1)
    except Exception as e:
        Colors.print(f"[!] Critical error: {str(e)}", "RED")
        if DEBUG:
            traceback.print_exc()
        sys.exit(1)

