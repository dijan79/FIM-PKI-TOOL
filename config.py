"""
config.py
---------
Central configuration for the FIM-PKI Tool.
Author : Dijan Ghale
Project: File Integrity Monitoring Tool with PKI, GUI & Docker Support
"""
import os

APP_NAME = "FIM-PKI Sentinel"
APP_VERSION = "3.0.0"
AUTHOR = "Dijan Ghale"


BASE_DIR = os.path.dirname(os.path.abspath(__file__))

KEY_DIR = os.path.join(BASE_DIR, "keys")
CERT_DIR = os.path.join(BASE_DIR, "certs")
LOG_DIR = os.path.join(BASE_DIR, "logs")
CSV_DIR = os.path.join(BASE_DIR, "CSV_logs")
DATA_DIR = os.path.join(BASE_DIR, "data")

for _d in (KEY_DIR, CERT_DIR, LOG_DIR, CSV_DIR, DATA_DIR):
    os.makedirs(_d, exist_ok=True)

REVOKED_FILE = os.path.join(DATA_DIR, "revoked.json")
DB_FILE = os.path.join(DATA_DIR, "fim_storage.db")

LOG_KEY_FILE = os.path.join(DATA_DIR, "logkey.key")
ENCRYPTED_LOG_FILE = os.path.join(LOG_DIR, "monitor.enc")
STRUCTURED_LOG_FILE = os.path.join(LOG_DIR, "activity.jsonl")

NOTIFY_CFG_FILE = os.path.join(DATA_DIR, "notify_config.json")
NOTIFY_OUTBOX_FILE = os.path.join(LOG_DIR, "notifications.jsonl")
PRIVATE_KEY_PASSWORD = os.environ.get("FIM_KEY_PASSWORD", "ChangeMe123!").encode()
CERT_VALIDITY_DAYS = 365
PERIODIC_SCAN_INTERVAL = 30
