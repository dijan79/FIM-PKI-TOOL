"""
db_manager.py
-------------
SQLite-backed storage for the integrity "baseline" of monitored files
(the expected hash + signature recorded when a file is registered).

Author: Dijan Ghale
"""

import sqlite3
from datetime import datetime

import config


class DBManager:
    """Simple wrapper around the SQLite baseline database."""

    def __init__(self, db_path=None):
        self.db_path = db_path or config.DB_FILE
        self._setup()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _setup(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    filepath    TEXT PRIMARY KEY,
                    username    TEXT NOT NULL,
                    filehash    BLOB NOT NULL,
                    signature   BLOB NOT NULL,
                    registered_at TEXT NOT NULL,
                    last_status TEXT DEFAULT 'OK',
                    last_checked TEXT
                )
            """)

    # ------------------------------------------------------------------
    def add_file(self, username, filepath, file_hash, signature):
        with self._connect() as conn:
            conn.execute(
                "REPLACE INTO files (filepath, username, filehash, signature, "
                "registered_at, last_status, last_checked) VALUES (?, ?, ?, ?, ?, 'OK', ?)",
                (filepath, username, file_hash, signature,
                 datetime.utcnow().isoformat(), datetime.utcnow().isoformat()),
            )

    def remove_file(self, filepath):
        with self._connect() as conn:
            conn.execute("DELETE FROM files WHERE filepath = ?", (filepath,))

    def get_file(self, filepath):
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT filepath, username, filehash, signature, registered_at, "
                "last_status, last_checked FROM files WHERE filepath = ?",
                (filepath,),
            )
            return cur.fetchone()

    def list_files(self):
        with self._connect() as conn:
            cur = conn.execute(
                "SELECT filepath, username, registered_at, last_status, last_checked "
                "FROM files ORDER BY registered_at DESC"
            )
            return cur.fetchall()

    def update_status(self, filepath, status):
        with self._connect() as conn:
            conn.execute(
                "UPDATE files SET last_status = ?, last_checked = ? WHERE filepath = ?",
                (status, datetime.utcnow().isoformat(), filepath),
            )

    def all_filepaths(self):
        with self._connect() as conn:
            cur = conn.execute("SELECT filepath, username, filehash, signature FROM files")
            return cur.fetchall()

    def count_by_status(self):
        with self._connect() as conn:
            cur = conn.execute("SELECT last_status, COUNT(*) FROM files GROUP BY last_status")
            return dict(cur.fetchall())
