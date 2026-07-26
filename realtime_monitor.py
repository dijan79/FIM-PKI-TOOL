"""
realtime_monitor.py
--------------------
Real-time filesystem watcher built on `watchdog`. For every monitored
event it:

    * computes the new SHA-256 hash of the affected file
    * compares it against the signed baseline stored in the database
    * raises a structured ALERT if the file was changed/deleted without
      being re-baselined (i.e. a potential integrity violation)
    * logs every event (INFO / WARNING / ALERT) through LogManager
    * forwards WARNING/ALERT events to the NotificationManager so
      configured channels (email/SMS) are dispatched

Author: Dijan Ghale
"""

from watchdog.events import FileSystemEventHandler

from log_manager import LEVEL_INFO, LEVEL_WARNING, LEVEL_ALERT


class FIMEventHandler(FileSystemEventHandler):
    """Watchdog handler that performs live integrity verification."""

    def __init__(self, db_manager, signer, log_manager, notifier=None, active_user=None):
        super().__init__()
        self.db = db_manager
        self.signer = signer
        self.logger = log_manager
        self.notifier = notifier
        self.active_user = active_user  # username whose key is used for re-baselining

    # ------------------------------------------------------------------
    def _log(self, level, event, filepath, username, message):
        self.logger.log_event(level, event, filepath=filepath, username=username, message=message)
        if self.notifier is not None:
            self.notifier.dispatch(level, event, filepath, username, message)

    # ------------------------------------------------------------------
    def on_created(self, event):
        if event.is_directory:
            return
        path = event.src_path
        self._log(LEVEL_INFO, "FILE_CREATED", path, self.active_user or "",
                   "A new file was created in the monitored folder.")

    def on_modified(self, event):
        if event.is_directory:
            return
        path = event.src_path
        record = self.db.get_file(path)

        if record is None:
            self._log(LEVEL_INFO, "FILE_MODIFIED_UNTRACKED", path, self.active_user or "",
                       "An unmonitored file was modified.")
            return

        _, username, _file_hash, signature, *_ = record
        try:
            valid = self.signer.verify_signature(username, path, signature)
        except FileNotFoundError:
            valid = False

        if valid:
            self.db.update_status(path, "OK")
            self._log(LEVEL_INFO, "FILE_MODIFIED_VERIFIED", path, username,
                       "File changed but signature/hash still matches baseline.")
        else:
            self.db.update_status(path, "TAMPERED")
            self._log(LEVEL_ALERT, "INTEGRITY_VIOLATION", path, username,
                       "File content no longer matches the signed baseline! "
                       "Possible unauthorized modification.")

    def on_deleted(self, event):
        if event.is_directory:
            return
        path = event.src_path
        record = self.db.get_file(path)

        if record is None:
            self._log(LEVEL_INFO, "FILE_DELETED_UNTRACKED", path, self.active_user or "",
                       "An unmonitored file was deleted.")
            return

        _, username, *_ = record
        self.db.update_status(path, "MISSING")
        self._log(LEVEL_ALERT, "FILE_MISSING", path, username,
                   "A monitored file was deleted!")

    def on_moved(self, event):
        if event.is_directory:
            return
        self._log(LEVEL_WARNING, "FILE_MOVED", event.dest_path, self.active_user or "",
                   f"File moved/renamed from {event.src_path} to {event.dest_path}.")
