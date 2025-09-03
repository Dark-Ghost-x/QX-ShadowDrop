import os

BASEDIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TIMEOUT = 10
MAX_WORKERS = 20
USER_AGENT = "QX-ShadowDrop/1.0 (Ethical-Scan)"
USE_PROXY = False
STEALTH_ONLY = False
ANTI_DECEPTION = False
PARALLEL = True
DEBUG = False
MAX_RETRIES = 3
AGGRESSIVE = False

PROXYLISTFILE = os.path.join(BASEDIR, "config", "valid_proxies.json")
MANUAL_PROXIES_FILE = os.path.join(BASEDIR, "config", "manual_proxies.txt")
PROXY_SOURCES = [
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    "https://raw.githubusercontent.com/mertguvencli/http-proxy-list/main/proxy-list/data.txt",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000&country=all"
]

OUTPUTDIR = os.path.join(BASEDIR, "output", "ShadowDrop")
LOGFILEPATH = os.path.join(BASEDIR, "logs", "scan.log")

os.makedirs(OUTPUTDIR, exist_ok=True)
os.makedirs(os.path.dirname(LOGFILEPATH), exist_ok=True)

COLOR_HIGH = "\033[91m"
COLOR_MEDIUM = "\033[93m"
COLOR_LOW = "\033[92m"
COLOR_RESET = "\033[0m"

ETHICALUSEONLY = True
