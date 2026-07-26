# FIM-PKI Sentinel — File Integrity Monitoring with PKI, Real-Time Alerting & Docker Support

**Author:** Dijan Ghale
**Version:** 3.0.0

A desktop security console for monitoring file integrity using a small
in-house **Public Key Infrastructure (PKI)**. Every monitored file is
hashed (SHA-256) and digitally signed with a user's RSA private key. A
real-time watcher continuously checks files against this signed baseline
and immediately raises alerts — on screen, in the audit log, and through
a simulated email/SMS Notification Center — the moment a file is
tampered with, deleted, or modified outside policy.

---

## ✨ Features

- **PKI Management** — issue and revoke per-user RSA-2048 key pairs and
  self-signed X.509 certificates directly from the console.
- **Signed Integrity Baseline** — register individual files or entire
  folders; each file's SHA-256 hash is digitally signed by the chosen
  user's private key and stored in a local SQLite database.
- **Real-Time Monitoring** — uses `watchdog` to watch folders for
  create/modify/delete/move events as they happen.
- **Real-Time Alerting** — any change that breaks a file's signed
  baseline (or deletion of a monitored file) immediately raises a
  desktop alert and is logged at `ALERT` severity.
- **Notification Center** — WARNING/ALERT events are dispatched to
  configurable email and SMS channels. *(For this coursework build,
  delivery is simulated and fully logged — see "About Notifications"
  below — rather than wired to a paid SMS provider or a personal email
  account.)*
- **Structured Logging** — every event is recorded as a JSON line
  (`logs/activity.jsonl`) with timestamp, severity, event type, user,
  file path, and message — ready for ingestion into log analysis tools.
- **Encrypted Audit Trail** — a second, Fernet-encrypted copy of the log
  (`logs/monitor.enc`) provides a tamper-evident audit record.
- **CSV Export** — generate compliance-ready CSV reports of all logged
  activity at the click of a button.
- **Security Dashboard** — live KPI cards, charts, and an event feed
  styled after real SOC tooling (Splunk/Wazuh-style dark console).
- **Periodic Background Scan** — independent of real-time monitoring,
  the app re-verifies every baselined file's signature every 30 seconds.
- **Dockerised** — ships with a `Dockerfile` and `docker-compose.yml`
  for consistent, reproducible deployment.
- **One-command setup scripts** — `setup.sh` (Linux/macOS) and
  `setup.bat` (Windows) handle the virtual environment, dependencies,
  and folder creation automatically.

---

## 🗂️ Project Structure

```
fim_tool/
├── fim_gui.py               # Main GUI application (entry point)
├── theme.py                  # Centralised dark-console design tokens
├── config.py                 # Central configuration & paths
├── pki_manager.py             # Certificate / key lifecycle management
├── signer.py                  # File hashing + digital signature logic
├── db_manager.py               # SQLite-backed integrity baseline storage
├── log_manager.py              # Structured + encrypted logging, CSV export
├── notification_manager.py     # Email/SMS notification center (simulated)
├── realtime_monitor.py         # Watchdog event handler / integrity checks
├── requirements.txt
├── setup.sh / setup.bat        # One-command environment setup
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .gitignore
├── keys/                       # Per-user encrypted private keys (generated)
├── certs/                      # Per-user X.509 certificates (generated)
├── data/                       # SQLite DB, revocation list, log key, notify config (generated)
├── logs/                       # activity.jsonl + monitor.enc + notifications.jsonl (generated)
└── CSV_logs/                   # Exported CSV reports (generated)
```

---

## 🖥️ Quick Start (Local)

### Linux / macOS
```bash
chmod +x setup.sh
./setup.sh
```

### Windows
Double-click `setup.bat`, or from Command Prompt:
```cmd
setup.bat
```

The script creates a virtual environment, installs dependencies, creates
the required folders, and offers to launch the app immediately.

### Manual setup
```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
python fim_gui.py
```

---

## 🔔 About Notifications

Real SMS delivery requires a paid provider (e.g. Twilio) and real email
delivery requires SMTP credentials tied to a personal/institutional
account — neither is appropriate to hard-code into a coursework
submission. Instead, the **Notification Center** demonstrates the full
real-world architecture:

- Alerts are formatted exactly as a live provider call would format them
  (subject, recipient, message body).
- Each dispatch is timestamped and written to `logs/notifications.jsonl`
  as proof of delivery, then shown in the Notification Center page.
- Channels, recipients, and the minimum severity that triggers a
  notification are all configurable from the **Settings** page.
- Swapping in a real provider later is a small, isolated change inside
  `notification_manager.py` (`_dispatch_email` / `_dispatch_sms`) —
  the rest of the application is provider-agnostic.

This is the same pattern production systems use (a notification
abstraction layer behind feature flags) — it's simply pointed at a log
instead of a live network call for this submission.

---

## 🔐 Security Notes

- Private keys are encrypted at rest using a passphrase, read from the
  `FIM_KEY_PASSWORD` environment variable (see `docker-compose.yml`).
  Change it before any real deployment.
- The encrypted audit log key (`data/logkey.key`) and all PKI material
  in `keys/` and `certs/` are excluded from version control via
  `.gitignore` — **do not commit them**.
- Revoking a user's certificate causes all future signature
  verifications for files they signed to fail, simulating real-world
  certificate revocation.

---

## 📋 Typical Demo Workflow

1. **PKI / Users** — issue a certificate for yourself (e.g. `dijan`).
2. **Baseline** — select your user, then add a file or folder to the
   signed integrity baseline.
3. **Live Monitor** — choose the same folder, select the active user,
   and click **Start Monitoring**.
4. Modify, delete, or tamper with a monitored file — an alert pops up
   immediately and is recorded in **Audit Logs** and **Notification
   Center**.
5. **Dashboard** — view live KPIs and charts update in real time.
6. **Audit Logs** — export a CSV report for submission/review.

---

## 🧰 Tech Stack

- **Python 3 / Tkinter** — GUI
- **cryptography** — RSA keys, X.509 certificates, digital signatures, Fernet encryption
- **watchdog** — real-time filesystem event monitoring
- **SQLite** — integrity baseline storage
- **matplotlib** — dashboard charts
- **Docker / Docker Compose** — containerised deployment
