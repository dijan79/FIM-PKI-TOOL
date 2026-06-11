import os
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from realtime_monitor import RealtimeHandler
from watchdog.observers import Observer
from log_encryptor import decrypt_log

class FIMApp:
    def __init__(self, root):
        self.root = root
        self.root.title("File Integrity Monitor (FIM) - Secure Edition")
        self.root.geometry("700x500")
        self.root.resizable(False, False)

        self.path_var = tk.StringVar()

        # Folder select
        tk.Label(root, text="Choose Folder to Monitor:", font=("Helvetica", 12)).pack(pady=10)
        path_frame = tk.Frame(root)
        path_frame.pack()
        self.path_entry = tk.Entry(path_frame, textvariable=self.path_var, width=60)
        self.path_entry.pack(side=tk.LEFT, padx=5)
        tk.Button(path_frame, text="Browse", command=self.browse_folder).pack(side=tk.LEFT)

        # Start Monitor Button
        tk.Button(root, text="Start Monitoring", bg="#28a745", fg="white",
                  font=("Helvetica", 12), command=self.start_monitoring).pack(pady=10)

        # View Logs Button
        tk.Button(root, text="View Decrypted Logs", bg="#007bff", fg="white",
                  font=("Helvetica", 12), command=self.show_logs).pack(pady=5)

        # Output Log Console
        tk.Label(root, text="Live Monitor Logs:", font=("Helvetica", 12)).pack()
        self.console = scrolledtext.ScrolledText(root, height=15, width=85, state='disabled')
        self.console.pack(pady=5)

    def browse_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.path_var.set(folder)

    def start_monitoring(self):
        folder = self.path_var.get()
        if not os.path.isdir(folder):
            messagebox.showerror("Error", "Please select a valid folder.")
            return

        def monitor():
            handler = RealtimeHandler(signer=None, log_file="monitor.enc")  # signer=None for now
            observer = Observer()
            observer.schedule(handler, folder, recursive=True)
            observer.start()
            self.write_console(f"✅ Monitoring started for: {folder}")
            try:
                while True:
                    pass  # keep thread alive
            except KeyboardInterrupt:
                observer.stop()
            observer.join()

        threading.Thread(target=monitor, daemon=True).start()

    def show_logs(self):
        # Decrypt and display logs in popup
        log_window = tk.Toplevel(self.root)
        log_window.title("Decrypted Log Viewer")
        log_window.geometry("650x400")

        output = scrolledtext.ScrolledText(log_window, height=25, width=80)
        output.pack(pady=10)

        # Decrypt logs and insert
        key = open("logkey.key", 'rb').read()
        from cryptography.fernet import Fernet
        fernet = Fernet(key)
        try:
            with open("monitor.enc", 'rb') as f:
                for line in f:
                    try:
                        decrypted = fernet.decrypt(line.strip()).decode()
                        output.insert(tk.END, decrypted + "\n")
                    except Exception as e:
                        output.insert(tk.END, f"[ERROR] {str(e)}\n")
        except FileNotFoundError:
            output.insert(tk.END, "No encrypted logs found.")

    def write_console(self, message):
        self.console.configure(state='normal')
        self.console.insert(tk.END, message + "\n")
        self.console.configure(state='disabled')
        self.console.yview(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = FIMApp(root)
    root.mainloop()
