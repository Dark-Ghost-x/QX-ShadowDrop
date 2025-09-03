#!/usr/bin/env python3
import os
import sys
import subprocess
import pkg_resources

REQUIRED_LIBS = [
    "requests",
    "colorama",
    "rich",
    "beautifulsoup4",
    "lxml",
    "validators",
    "urllib3",
    "tqdm"
]

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REQUIRED_DIRS = [
    os.path.join(BASE_DIR, "output", "ShadowDrop"),
    os.path.join(BASE_DIR, "config"),
    os.path.join(BASE_DIR, "core", "modules"),
    os.path.join(BASE_DIR, "utils"),
    os.path.join(BASE_DIR, "logs")
]

def check_pip_installed() -> bool:
    """Check if pip is installed and available."""
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "--version"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return True
    except Exception:
        print("[!] pip is not installed or not available on this system.")
        return False

def get_installed_packages() -> set:
    """Return a set of currently installed packages."""
    return {pkg.key for pkg in pkg_resources.working_set}

def install_missing_packages(missing: list) -> bool:
    """Install missing Python packages via pip."""
    print(f"[+] Installing missing packages: {', '.join(missing)}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", *missing])
        print("[✓] All missing packages installed successfully.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Error installing packages: {e}")
        return False

def ensure_directories_exist():
    """Ensure all required directories exist."""
    for directory in REQUIRED_DIRS:
        try:
            os.makedirs(directory, exist_ok=True)
            print(f"[✓] Directory ready: {directory}")
        except Exception as e:
            print(f"[!] Error creating directory {directory}: {e}")

def main():
    print("=== QX-ShadowDrop Environment Setup ===\n")

    ensure_directories_exist()

    if not check_pip_installed():
        print("Please install pip and ensure it is available before running this script.")
        sys.exit(1)

    installed_packages = get_installed_packages()
    missing_packages = [
        pkg for pkg in REQUIRED_LIBS if pkg.lower() not in installed_packages
    ]

    if not missing_packages:
        print("[✓] All required packages are already installed.")
    else:
        if not install_missing_packages(missing_packages):
            print("[!] Some packages could not be installed. Please check manually.")
            sys.exit(1)

    print("\n[✓] Environment setup complete — You can now run run.py 🚀")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Unexpected error: {e}")
        sys.exit(1)
