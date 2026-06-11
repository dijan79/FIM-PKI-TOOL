import csv
import os
from datetime import datetime
from cryptography.fernet import Fernet

KEY_FILE = "logkey.key"
ENC_FILE = "monitor.enc"
CSV_FOLDER = "CSV_logs"

def load_key():
    try:
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print("❌ Key file not found.")
        return None

def decrypt_logs():
    key = load_key()
    if not key:
        return []

    fernet = Fernet(key)
    logs = []

    try:
        with open(ENC_FILE, 'rb') as f:
            lines = f.readlines()
            for line in lines:
                try:
                    decrypted = fernet.decrypt(line.strip()).decode()
                    # Format: [timestamp] ACTION: path
                    if decrypted.startswith('['):
                        timestamp = decrypted.split(']')[0][1:]
                        rest = decrypted.split(']')[1].strip()
                        action, path = rest.split(':', 1)
                        logs.append([timestamp, action.strip(), path.strip()])
                except Exception as e:
                    print("❌ Failed to decrypt line:", e)
    except FileNotFoundError:
        print("❌ Encrypted log file not found.")

    return logs

def export_to_csv():
    os.makedirs(CSV_FOLDER, exist_ok=True)

    now = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"fim_logs_{now}.csv"
    filepath = os.path.join(CSV_FOLDER, filename)

    logs = decrypt_logs()
    if logs:
        with open(filepath, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "Action", "FilePath"])
            writer.writerows(logs)
        print(f"✅ Logs exported successfully to {filepath}")
    else:
        print("⚠️ No logs to export.")

if __name__ == "__main__":
    export_to_csv()
