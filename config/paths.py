#!/usr/bin/env python3
import logging
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULES_DIR = os.path.join(BASE_DIR, "core", "modules")
OUTPUT_DIR = os.path.join(BASE_DIR, "output", "ShadowDrop")
CONFIG_DIR = os.path.join(BASE_DIR, "config")
LOGS_DIR = os.path.join(BASE_DIR, "logs")

VALID_PROXIES_FILE = os.path.join(CONFIG_DIR, "valid_proxies.json")
LOG_FILE_PATH = os.path.join(LOGS_DIR, "shadowdrop.log")

for path in (MODULES_DIR, OUTPUT_DIR, CONFIG_DIR, LOGS_DIR):
    os.makedirs(path, exist_ok=True)

if __name__ == "__main__":
    logging.debug(f"BASE_DIR: {BASE_DIR}")
    logging.debug(f"MODULES_DIR: {MODULES_DIR}")
    logging.debug(f"OUTPUT_DIR: {OUTPUT_DIR}")
    logging.debug(f"CONFIG_DIR: {CONFIG_DIR}")
    logging.debug(f"LOGS_DIR: {LOGS_DIR}")
    logging.debug(f"VALID_PROXIES_FILE: {VALID_PROXIES_FILE}")
    logging.debug(f"LOG_FILE_PATH: {LOG_FILE_PATH}")


REPORTS_PATH = r'/data/data/com.termux/files/home/reports'
