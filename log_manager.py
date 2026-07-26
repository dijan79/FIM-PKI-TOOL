"""
log_manager.py
---------------
Centralised logging for the FIM tool.

Two log streams are maintained:

1. A structured, human-readable JSON-Lines log (logs/activity.jsonl)
   suitable for ingestion into a SIEM / log analysis tool.

2. A tamper-evident, encrypted audit log (logs/monitor.enc) using a
   Fernet symmetric key (data/logkey.key). This is a separate,
   append-only audit trail kept independently of the structured log so
   that even if activity.jsonl were altered, the encrypted copy remains
   as corroborating evidence.

It also provides CSV export of the structured log for reporting
purposes, and a small alert queue used by the GUI to surface
real-time integrity alerts to the user.

Author: Dijan Ghale
"""

import os
import json
import csv
import queue
from datetime import datetime

from cryptography.fernet import Fernet

import config

# Severity levels used throughout the application
LEVEL_INFO = "INFO"
LEVEL_WARNING = "WARNING"
LEVEL_ALERT = "ALERT"


class LogManager:
    """Write structured + encrypted logs and expose them for the GUI."""

    def __init__(self):
        self.json_log_path = config.STRUCTURED_LOG_FILE
        self.enc_log_path = config.ENCRYPTED_LOG_FILE
        self.key_path = config.LOG_KEY_FILE
        self.csv_dir = config.CSV_DIR

        # Real-time alert queue (thread-safe) consumed by the GUI
        self.alert_queue = queue.Queue()

        self._ensure_key()

    # ------------------------------------------------------------------
    # Encryption key handling
    # ------------------------------------------------------------------
    def _ensure_key(self):
        if not os.path.exists(self.key_path):
            key = Fernet.generate_key()
            with open(self.key_path, "wb") as f:
                f.write(key)

    def _fernet(self):
        with open(self.key_path, "rb") as f:
            return Fernet(f.read())

    # ------------------------------------------------------------------
    # Writing logs
    # ------------------------------------------------------------------
    def log_event(self, level, event, filepath="", username="", message=""):
        """Record a structured event and, for warnings/alerts, queue a
        notification for the GUI."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": level,
            "event": event,
            "username": username,
            "filepath": filepath,
            "message": message,
        }

        # 1) Structured JSON-Lines log
        with open(self.json_log_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # 2) Encrypted audit log (single-line plaintext, then encrypted)
        plain = f"[{entry['timestamp']}] {level} | {event} | user={username} | path={filepath} | {message}"
        fernet = self._fernet()
        with open(self.enc_log_path, "ab") as f:
            f.write(fernet.encrypt(plain.encode()) + b"\n")

        # 3) Real-time alert queue for the GUI
        if level in (LEVEL_WARNING, LEVEL_ALERT):
            self.alert_queue.put(entry)

        return entry

    # ------------------------------------------------------------------
    # Reading logs
    # ------------------------------------------------------------------
    def read_structured_log(self, limit=500):
        """Return the most recent *limit* structured log entries."""
        if not os.path.exists(self.json_log_path):
            return []
        with open(self.json_log_path) as f:
            lines = f.readlines()
        entries = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return entries

    def read_encrypted_log(self):
        """Decrypt and return all entries from the encrypted audit log."""
        if not os.path.exists(self.enc_log_path):
            return []
        fernet = self._fernet()
        results = []
        with open(self.enc_log_path, "rb") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    results.append(fernet.decrypt(line).decode())
                except Exception:
                    results.append("[ERROR] Could not decrypt entry (key mismatch or corruption)")
        return results

    # ------------------------------------------------------------------
    # CSV export
    # ------------------------------------------------------------------
    def export_csv(self):
        os.makedirs(self.csv_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        filepath = os.path.join(self.csv_dir, f"fim_report_{timestamp}.csv")

        entries = self.read_structured_log(limit=10_000)
        with open(filepath, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "Level", "Event", "Username", "FilePath", "Message"])
            for e in entries:
                writer.writerow([
                    e.get("timestamp", ""),
                    e.get("level", ""),
                    e.get("event", ""),
                    e.get("username", ""),
                    e.get("filepath", ""),
                    e.get("message", ""),
                ])
        return filepath

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------
    def get_pending_alerts(self):
        """Drain and return all currently queued alerts (non-blocking)."""
        alerts = []
        while True:
            try:
                alerts.append(self.alert_queue.get_nowait())
            except queue.Empty:
                break
        return alerts
