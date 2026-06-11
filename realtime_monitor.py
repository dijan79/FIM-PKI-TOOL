# realtime_monitor.py
from log_encryptor import encrypt_log
import time
import os
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

class RealtimeHandler(FileSystemEventHandler):
    def __init__(self, log_file="monitor.log"):
        self.log_file = log_file

    def log_event(self, action, path):
    	timestamp = datetime.utcnow().isoformat()
    	message = f"[{timestamp}] {action.upper()}: {path}"
    	print(message)
    	encrypt_log(message)  # <-- Save encrypted log


    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("deleted", event.src_path)

def start_realtime_monitor(path_to_watch="."):
    print(f"🔍 Watching directory: {path_to_watch}")
    event_handler = RealtimeHandler()
    observer = Observer()
    observer.schedule(event_handler, path=path_to_watch, recursive=True)
    observer.start()

    try:
        while True:
            time.sleep(1)  # Just keep the script alive
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    folder = input("📁 Enter the folder path to monitor: ").strip()
    if os.path.isdir(folder):
        start_realtime_monitor(folder)
    else:
        print("❌ Folder does not exist.")
