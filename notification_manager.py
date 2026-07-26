"""
notification_manager.py
------------------------
Notification Center for integrity alerts.

Design rationale
-----------------
Real-world FIM/SIEM tools (Splunk, Wazuh, Tripwire) route alerts through
configurable notification channels — email, SMS, webhook, ticketing
system, etc. This module implements that same architecture: alerts are
formatted, queued, and dispatched to one or more channels based on a
user-editable configuration (data/notify_config.json).

For this coursework build, channels are SIMULATED rather than wired to
a live SMTP/Twilio account:
    * every "send" is fully formatted exactly as a real provider call
      would format it (subject, body, recipient, provider envelope)
    * it is timestamped and appended to an outbox log
      (logs/notifications.jsonl) as proof of dispatch
    * the GUI's Notification Center shows it as a real delivered message

This is intentionally honest: it does not claim to have sent a real
email or SMS over the network. Swapping in a live provider later is a
one-function change — see `_dispatch_email` / `_dispatch_sms` below,
where a real smtplib/Twilio call would replace the simulated write.

Author: Dijan Ghale
"""

import os
import json
import threading
from datetime import datetime

import config

_DEFAULTS = {
    "email_enabled": True,
    "email_address": "soc-team@example.com",
    "sms_enabled": True,
    "sms_number": "+977-98XXXXXXXX",
    "min_level": "WARNING",   # INFO < WARNING < ALERT
}

_LEVEL_ORDER = {"INFO": 0, "WARNING": 1, "ALERT": 2}


class NotificationManager:
    """Load/save notification preferences and dispatch (simulated) alerts."""

    def __init__(self):
        self.cfg_path = config.NOTIFY_CFG_FILE
        self.outbox_path = config.NOTIFY_OUTBOX_FILE
        self.cfg = self._load()

    # ------------------------------------------------------------------
    # Config persistence
    # ------------------------------------------------------------------
    def _load(self):
        if os.path.exists(self.cfg_path):
            try:
                with open(self.cfg_path) as f:
                    data = json.load(f)
                return {**_DEFAULTS, **data}
            except Exception:
                pass
        return dict(_DEFAULTS)

    def save(self, updates: dict):
        self.cfg.update(updates)
        with open(self.cfg_path, "w") as f:
            json.dump(self.cfg, f, indent=2)
        return self.cfg

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------
    def dispatch(self, level, event, filepath, username, message):
        """Fire configured channels asynchronously; return immediately."""
        if _LEVEL_ORDER.get(level, 0) < _LEVEL_ORDER.get(self.cfg["min_level"], 1):
            return

        threading.Thread(
            target=self._dispatch_worker,
            args=(level, event, filepath, username, message),
            daemon=True,
        ).start()

    def _dispatch_worker(self, level, event, filepath, username, message):
        if self.cfg.get("email_enabled"):
            self._dispatch_email(level, event, filepath, username, message)
        if self.cfg.get("sms_enabled"):
            self._dispatch_sms(level, event, filepath, username, message)

    # ------------------------------------------------------------------
    # Channel implementations (simulated — see module docstring)
    # ------------------------------------------------------------------
    def _dispatch_email(self, level, event, filepath, username, message):
        record = {
            "channel": "EMAIL",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "to": self.cfg.get("email_address", ""),
            "subject": f"[FIM-PKI Sentinel] {level}: {event}",
            "body": self._format_body(level, event, filepath, username, message),
            "status": "SIMULATED_SENT",
        }
        self._write_outbox(record)
        return record

    def _dispatch_sms(self, level, event, filepath, username, message):
        record = {
            "channel": "SMS",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "to": self.cfg.get("sms_number", ""),
            "body": f"[FIM-PKI] {level} | {event} | {os.path.basename(filepath) if filepath else '-'} | {message}"[:160],
            "status": "SIMULATED_SENT",
        }
        self._write_outbox(record)
        return record

    # ------------------------------------------------------------------
    def _write_outbox(self, record):
        with open(self.outbox_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    @staticmethod
    def _format_body(level, event, filepath, username, message):
        ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        return (
            f"Timestamp : {ts}\n"
            f"Severity  : {level}\n"
            f"Event     : {event}\n"
            f"User      : {username or '-'}\n"
            f"File      : {filepath or '-'}\n"
            f"Detail    : {message}\n\n"
            f"This alert was generated automatically by {config.APP_NAME}.\n"
            f"Review the Logs tab for the full audit trail."
        )

    # ------------------------------------------------------------------
    # Reading the outbox (for the GUI's Notification Center)
    # ------------------------------------------------------------------
    def read_outbox(self, limit=200):
        if not os.path.exists(self.outbox_path):
            return []
        with open(self.outbox_path) as f:
            lines = f.readlines()
        out = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    def send_test_notification(self):
        """Used by the 'Send Test Alert' button in Settings."""
        self.dispatch(
            "ALERT", "TEST_NOTIFICATION", "", "system",
            "This is a test notification triggered manually from Settings."
        )
