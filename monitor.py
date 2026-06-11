import sqlite3
import os
import time
from datetime import datetime

class FileMonitor:
    def __init__(self, signer):
        self.signer = signer
        self.db = "storage.db"
        self.log_file = "monitor.log"
        self.setup_db()

    def setup_db(self):
        with sqlite3.connect(self.db) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS files (
                username TEXT, filepath TEXT PRIMARY KEY, filehash BLOB, signature BLOB
            )''')

    def log_event(self, message):
        timestamp = datetime.utcnow().isoformat()
        log_entry = f"[{timestamp}] {message}\n"
        with open(self.log_file, "a") as f:
            f.write(log_entry)

    def register_file(self, username, filepath):
        if not os.path.isfile(filepath):
            print("File does not exist.")
            return

        file_hash, signature = self.signer.sign_file(username, filepath)

        with sqlite3.connect(self.db) as conn:
            conn.execute("REPLACE INTO files VALUES (?, ?, ?, ?)",
                         (username, filepath, file_hash, signature))

        print(f"File {filepath} registered and integrity baseline set.")
        self.log_event(f"File registered: {filepath} by {username}")

    def start_monitoring(self):
        print("Starting continuous file integrity monitoring...")
        while True:
            with sqlite3.connect(self.db) as conn:
                cursor = conn.execute("SELECT username, filepath, signature FROM files")
                for username, filepath, signature in cursor:
                    if not os.path.isfile(filepath):
                        print(f"WARNING: File {filepath} missing!")
                        self.log_event(f"File missing: {filepath}")
                        continue
                    valid = self.signer.verify_signature(username, filepath, signature)
                    if valid:
                        print(f"OK: {filepath} integrity intact.")
                    else:
                        print(f"ALERT: {filepath} integrity compromised!")
                        self.log_event(f"Integrity alert: {filepath} compromised.")
            time.sleep(10)
