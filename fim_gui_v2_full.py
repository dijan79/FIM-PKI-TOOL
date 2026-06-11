
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
from datetime import datetime
import csv
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
import json

CERT_DIR = "certs"
KEY_DIR = "keys"
REVOKED_FILE = "revoked.json"

os.makedirs(CERT_DIR, exist_ok=True)
os.makedirs(KEY_DIR, exist_ok=True)
if not os.path.exists(REVOKED_FILE):
    with open(REVOKED_FILE, "w") as f:
        json.dump([], f)

class GUIRealtimeHandler(FileSystemEventHandler):
    def __init__(self, output_box):
        self.output_box = output_box

    def on_created(self, event):
        self.log_event("✅ CREATED", event.src_path)

    def on_modified(self, event):
        self.log_event("🟨 MODIFIED", event.src_path)

    def on_deleted(self, event):
        self.log_event("❌ DELETED", event.src_path)

    def log_event(self, action, path):
        timestamp = datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
        message = f"{timestamp} {action}: {path}\n"
        self.output_box.insert(tk.END, message)
        self.output_box.see(tk.END)

class FIMGUIv2:
    def __init__(self, root):
        self.root = root
        self.root.title("FIM Tool - GUI V2 (Waaris Edition)")

        self.tab_control = ttk.Notebook(self.root)

        self.home_tab = ttk.Frame(self.tab_control)
        self.monitor_tab = ttk.Frame(self.tab_control)
        self.logs_tab = ttk.Frame(self.tab_control)
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.cert_tab = ttk.Frame(self.tab_control)
        self.settings_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.home_tab, text="🏠 Home")
        self.tab_control.add(self.monitor_tab, text="🖥️ Monitor")
        self.tab_control.add(self.logs_tab, text="📄 Logs")
        self.tab_control.add(self.dashboard_tab, text="📊 Dashboard")
        self.tab_control.add(self.cert_tab, text="👤 Users")
        self.tab_control.add(self.settings_tab, text="⚙️ Settings")

        self.tab_control.pack(expand=1, fill="both")

        self.build_home_tab()
        self.build_monitor_tab()
        self.build_logs_tab()
        self.build_dashboard_tab()
        self.build_cert_tab()
        self.build_settings_tab()

    def build_home_tab(self):
        label = tk.Label(self.home_tab, text="🔐 File Integrity Monitoring Tool", font=("Helvetica", 16, "bold"))
        label.pack(pady=20)

        desc = tk.Label(self.home_tab, text="Built with ❤️ by Mohammad Waaris Ali Khan", font=("Helvetica", 12))
        desc.pack(pady=5)

        note = tk.Label(self.home_tab, text="This tool monitors, logs, signs, and audits your file system in real time.", wraplength=600)
        note.pack(pady=10)

    def build_settings_tab(self):
        label = tk.Label(self.settings_tab, text="⚙️ Settings", font=("Helvetica", 14, "bold"))
        label.pack(pady=20)

        note = tk.Label(self.settings_tab, text="(Future updates will include alert configurations, themes, and user auth settings.)", wraplength=600)
        note.pack(pady=10)

    def build_monitor_tab(self):
        tk.Label(self.monitor_tab, text="Choose a folder to monitor:").pack(pady=10)

        self.folder_entry = tk.Entry(self.monitor_tab, width=60)
        self.folder_entry.pack(pady=5)

        tk.Button(self.monitor_tab, text="Browse", command=self.browse_folder).pack()

        tk.Button(self.monitor_tab, text="Start Monitoring", command=self.start_monitoring).pack(pady=10)

        self.monitor_output = tk.Text(self.monitor_tab, height=15, width=100, bg="black", fg="lime")
        self.monitor_output.pack(padx=10, pady=10)

    def build_logs_tab(self):
        self.logs_text = tk.Text(self.logs_tab, height=20, width=100, bg="white")
        self.logs_text.pack(padx=10, pady=10)

        tk.Button(self.logs_tab, text="💾 Save Logs to CSV", command=self.save_logs_to_csv).pack(pady=5)

    def build_dashboard_tab(self):
        self.dashboard_frame = tk.Frame(self.dashboard_tab)
        self.dashboard_frame.pack(fill=tk.BOTH, expand=True)

        tk.Button(self.dashboard_tab, text="🔄 Refresh Chart", command=self.refresh_chart).pack(pady=5)

    def build_cert_tab(self):
        frame = tk.Frame(self.cert_tab)
        frame.pack(padx=10, pady=10)

        tk.Label(frame, text="Enter New Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(frame, width=30)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)

        tk.Button(frame, text="➕ Generate Cert", command=self.generate_certificate).grid(row=0, column=2, padx=5)
        tk.Button(frame, text="📄 Show Certs", command=self.show_certificates).grid(row=1, column=0, pady=10)
        tk.Button(frame, text="🚫 Revoke Cert", command=self.revoke_certificate).grid(row=1, column=1, pady=10)

        self.output_box = tk.Text(self.cert_tab, height=15, width=100, bg="white")
        self.output_box.pack(padx=10, pady=5)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.folder_entry.delete(0, tk.END)
            self.folder_entry.insert(0, folder)

    def start_monitoring(self):
        folder = self.folder_entry.get()
        if not folder:
            messagebox.showwarning("Folder Required", "Please select a folder to monitor.")
            return
        threading.Thread(target=self.monitor_thread, args=(folder,), daemon=True).start()

    def monitor_thread(self, folder):
        try:
            handler = GUIRealtimeHandler(self.monitor_output)
            observer = Observer()
            observer.schedule(handler, path=folder, recursive=True)
            observer.start()
            self.monitor_output.insert(tk.END, f"✅ Real-time monitoring started on: {folder}\n")
            self.monitor_output.see(tk.END)
            while True:
                pass
        except Exception as e:
            self.monitor_output.insert(tk.END, f"❌ Error: {str(e)}\n")

    def save_logs_to_csv(self):
        logs = self.monitor_output.get("1.0", tk.END).strip().split("\n")
        if not logs:
            messagebox.showinfo("No Logs", "There are no logs to save.")
            return
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        folder_path = "./CSV_logs"
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, f"log_{timestamp}.csv")
        with open(file_path, "w", newline="") as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(["Timestamp", "Action", "File Path"])
            for log in logs:
                parts = log.split(" ", 2)
                if len(parts) == 3:
                    writer.writerow(parts)
        messagebox.showinfo("Saved", f"Logs saved to {file_path}")

    def refresh_chart(self):
        logs = self.monitor_output.get("1.0", tk.END).strip().split("\n")
        created = sum(1 for line in logs if "CREATED" in line)
        modified = sum(1 for line in logs if "MODIFIED" in line)
        deleted = sum(1 for line in logs if "DELETED" in line)

        for widget in self.dashboard_frame.winfo_children():
            widget.destroy()

        fig, ax = plt.subplots(figsize=(6, 4))
        actions = ['Created', 'Modified', 'Deleted']
        counts = [created, modified, deleted]
        ax.bar(actions, counts, color=['green', 'orange', 'red'])
        ax.set_title("File Activity Summary")
        ax.set_ylabel("Number of Events")

        canvas = FigureCanvasTkAgg(fig, master=self.dashboard_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def generate_certificate(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Input Error", "Please enter a username.")
            return
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        private_key_bytes = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(f"{KEY_DIR}/{username}_private.pem", "wb") as f:
            f.write(private_key_bytes)

        public_key = private_key.public_key()
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ])
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)            .public_key(public_key)            .serial_number(x509.random_serial_number())            .not_valid_before(datetime.utcnow())            .not_valid_after(datetime.utcnow().replace(year=datetime.utcnow().year + 1))            .sign(private_key, algorithm=hashes.SHA256())

        with open(f"{CERT_DIR}/{username}.pem", "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        self.output_box.insert(tk.END, f"✅ Certificate generated for: {username}\n")

    def show_certificates(self):
        certs = os.listdir(CERT_DIR)
        self.output_box.delete("1.0", tk.END)
        self.output_box.insert(tk.END, "📄 Issued Certificates:\n")
        for cert in certs:
            self.output_box.insert(tk.END, f"• {cert}\n")

    def revoke_certificate(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Input Error", "Enter username to revoke cert.")
            return
        revoked = []
        if os.path.exists(REVOKED_FILE):
            with open(REVOKED_FILE, "r") as f:
                revoked = json.load(f)
        if username not in revoked:
            revoked.append(username)
            with open(REVOKED_FILE, "w") as f:
                json.dump(revoked, f, indent=2)
            self.output_box.insert(tk.END, f"🚫 Certificate revoked for: {username}\n")
        else:
            self.output_box.insert(tk.END, f"⚠️ Already revoked: {username}\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = FIMGUIv2(root)
    root.mainloop()
