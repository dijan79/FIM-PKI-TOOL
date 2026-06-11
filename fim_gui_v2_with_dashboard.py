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

# GUI-Compatible Event Handler
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
        self.root.title("FIM Tool - GUI V2")

        self.tab_control = ttk.Notebook(self.root)

        self.home_tab = ttk.Frame(self.tab_control)
        self.monitor_tab = ttk.Frame(self.tab_control)
        self.logs_tab = ttk.Frame(self.tab_control)
        self.dashboard_tab = ttk.Frame(self.tab_control)
        self.settings_tab = ttk.Frame(self.tab_control)

        self.tab_control.add(self.home_tab, text="🏠 Home")
        self.tab_control.add(self.monitor_tab, text="🖥️ Monitor")
        self.tab_control.add(self.logs_tab, text="📄 Logs")
        self.tab_control.add(self.dashboard_tab, text="📊 Dashboard")
        self.tab_control.add(self.settings_tab, text="⚙️ Settings")

        self.tab_control.pack(expand=1, fill="both")

        self.build_monitor_tab()
        self.build_logs_tab()
        self.build_dashboard_tab()

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
        folder_path = "/home/md/Desktop/Coursework/latest/fim_pki_tool/CSV_logs"
        os.makedirs(folder_path, exist_ok=True)
        file_path = os.path.join(folder_path, f"log_{timestamp}.csv")

        try:
            with open(file_path, "w", newline="") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Timestamp", "Action", "File Path"])
                for log in logs:
                    parts = log.split(" ", 2)
                    if len(parts) == 3:
                        writer.writerow(parts)
            messagebox.showinfo("Saved", f"Logs saved to {file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Could not save CSV: {str(e)}")

    def refresh_chart(self):
        # Analyze current log from monitor_output
        logs = self.monitor_output.get("1.0", tk.END).strip().split("\n")
        created = sum(1 for line in logs if "CREATED" in line)
        modified = sum(1 for line in logs if "MODIFIED" in line)
        deleted = sum(1 for line in logs if "DELETED" in line)

        # Destroy previous chart
        for widget in self.dashboard_frame.winfo_children():
            widget.destroy()

        # Create chart
        fig, ax = plt.subplots(figsize=(6, 4))
        actions = ['Created', 'Modified', 'Deleted']
        counts = [created, modified, deleted]
        ax.bar(actions, counts, color=['green', 'orange', 'red'])
        ax.set_title("File Activity Summary")
        ax.set_ylabel("Number of Events")

        canvas = FigureCanvasTkAgg(fig, master=self.dashboard_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

if __name__ == "__main__":
    root = tk.Tk()
    app = FIMGUIv2(root)
    root.mainloop()
