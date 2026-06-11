import threading
from watchdog.observers import Observer
from realtime_monitor import RealtimeHandler
import tkinter as tk

from tkinter import ttk, filedialog, messagebox, scrolledtext

from watchdog.events import FileSystemEventHandler
from datetime import datetime

class GUIRealtimeHandler(FileSystemEventHandler):
    def __init__(self, gui_output_box, log_file="monitor.enc"):
        self.output_box = gui_output_box
        self.log_file = log_file

    def log_event(self, action, path):
        timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        action_clean = action.lower()
        emoji = {"created": "✅", "modified": "⚠️", "deleted": "❌"}.get(action_clean, "📄")
        tag = f"tag_{action_clean}"
        message = f"[{timestamp}] {emoji} {action.upper()}: {path}"

        with open(self.log_file, "a") as f:
            f.write(message + "\\n")

        self.output_box.insert(tk.END, message + "\\n", tag)
        self.output_box.see(tk.END)




    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("modified", event.src_path)

    def on_created(self, event):
        if not event.is_directory:
            self.log_event("created", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory:
            self.log_event("deleted", event.src_path)


class FIMGUIv2:
    def __init__(self, root):
        self.root = root
        self.root.title("FIM Tool - GUI V2")
        self.root.geometry("900x600")
        self.root.resizable(False, False)

        # Setup style
        style = ttk.Style()
        style.configure('TNotebook.Tab', font=('Helvetica', 11, 'bold'))
        style.configure('TButton', font=('Helvetica', 10))
        style.configure('TLabel', font=('Helvetica', 10))

        # Create notebook (tab system)
        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill='both', expand=True)

        # Create all tab frames
        self.home_tab = ttk.Frame(self.tabs)
        self.monitor_tab = ttk.Frame(self.tabs)
        self.logs_tab = ttk.Frame(self.tabs)
        self.settings_tab = ttk.Frame(self.tabs)

        # Add tabs to notebook
        self.tabs.add(self.home_tab, text='🏠 Home')
        self.tabs.add(self.monitor_tab, text='🖥️ Monitor')
        self.tabs.add(self.logs_tab, text='📄 Logs')
        self.tabs.add(self.settings_tab, text='⚙️ Settings')

        # Populate each tab
        self.build_home_tab()
        self.build_monitor_tab()
        self.build_logs_tab()
        self.build_settings_tab()

    def build_home_tab(self):
        ttk.Label(self.home_tab, text="Welcome to File Integrity Monitoring (FIM) Tool",
                  font=("Helvetica", 16)).pack(pady=20)
        ttk.Label(self.home_tab, text="Built by Waaris 🔐", font=("Helvetica", 12)).pack(pady=10)

    def build_monitor_tab(self):
        label = tk.Label(self.monitor_tab, text="Choose a folder to monitor:")
        label.pack(pady=10)

        self.folder_entry = tk.Entry(self.monitor_tab, width=60)
        self.folder_entry.pack(pady=5)

        browse_btn = tk.Button(self.monitor_tab, text="Browse", command=self.browse_folder)
        browse_btn.pack(pady=5)

        monitor_btn = tk.Button(self.monitor_tab, text="Start Monitoring", command=self.start_monitoring)
        monitor_btn.pack(pady=10)

        self.monitor_output = scrolledtext.ScrolledText(self.monitor_tab, height=20, width=100)
        self.monitor_output.pack(pady=10)

        # ✅ Add color tag styles for each log type
        self.monitor_output.tag_config("tag_created", foreground="green")
        self.monitor_output.tag_config("tag_modified", foreground="orange")
        self.monitor_output.tag_config("tag_deleted", foreground="red")


	

    def build_logs_tab(self):
        ttk.Button(self.logs_tab, text="View Decrypted Logs", command=self.view_logs).pack(pady=10)
        self.log_output = scrolledtext.ScrolledText(self.logs_tab, height=20, width=100)
        self.log_output.pack(pady=10)

    def build_settings_tab(self):
        ttk.Label(self.settings_tab, text="Future settings will be here (alerts, themes, etc.)",
                  font=("Helvetica", 12)).pack(pady=20)

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


        thread = threading.Thread(target=monitor_thread, daemon=True)
        thread.start()



    def view_logs(self):
        try:
            with open("logkey.key", "rb") as f:
                key = f.read()
        except FileNotFoundError:
            self.log_output.insert(tk.END, "❌ Key file not found.\n")
            return

        try:
            with open("monitor.enc", "rb") as f:
                lines = f.readlines()
        except FileNotFoundError:
            self.log_output.insert(tk.END, "❌ Encrypted log file not found.\n")
            return

        fernet = Fernet(key)
        self.log_output.delete('1.0', tk.END)

        for line in lines:
            try:
                decrypted = fernet.decrypt(line.strip()).decode()
                self.log_output.insert(tk.END, f"{decrypted}\n")
            except Exception as e:
                self.log_output.insert(tk.END, f"[ERROR] Failed to decrypt line: {e}\n")


if __name__ == "__main__":
    root = tk.Tk()
    app = FIMGUIv2(root)
    root.mainloop()
