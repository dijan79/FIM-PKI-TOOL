"""
fim_gui.py
==========
FIM-PKI Sentinel — File Integrity Monitoring Tool with PKI

A desktop security console, styled after real SOC/SIEM tooling, that
lets an operator:

    * Manage an in-house PKI (issue / revoke per-user certificates)
    * Register a signed integrity baseline for files and folders
    * Monitor folders in real time for unauthorized changes
    * Receive immediate on-screen alerts plus simulated email/SMS
      notifications (Notification Center)
    * Review structured + encrypted audit logs and export CSV reports
    * Watch live dashboard statistics and charts

Layout: fixed left sidebar for navigation + a status strip, with a
content area on the right that swaps between pages.

Author : Dijan Ghale
Version: 3.0.0
"""

import os
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from datetime import datetime

from watchdog.observers import Observer
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import config
import theme
from pki_manager import PKIManager
from signer import Signer
from db_manager import DBManager
from log_manager import LogManager, LEVEL_INFO, LEVEL_WARNING, LEVEL_ALERT
from notification_manager import NotificationManager
from realtime_monitor import FIMEventHandler


# =============================================================================
# Small reusable widgets
# =============================================================================
class StatCard(tk.Frame):
    """A single KPI card: big number, label, accent-colored top bar."""

    def __init__(self, parent, label, accent=theme.ACCENT, **kwargs):
        super().__init__(parent, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1, **kwargs)
        bar = tk.Frame(self, bg=accent, height=3)
        bar.pack(fill="x", side="top")

        inner = tk.Frame(self, bg=theme.BG_PANEL)
        inner.pack(fill="both", expand=True, padx=18, pady=14)

        self.value_var = tk.StringVar(value="0")
        tk.Label(inner, textvariable=self.value_var, font=theme.FONT_STAT_NUMBER,
                 bg=theme.BG_PANEL, fg=theme.TEXT_PRIMARY).pack(anchor="w")
        tk.Label(inner, text=label.upper(), font=theme.FONT_SMALL,
                 bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY).pack(anchor="w", pady=(2, 0))

    def set_value(self, value):
        self.value_var.set(str(value))


class SectionHeader(tk.Frame):
    """Page title + optional subtitle + optional right-aligned action area."""

    def __init__(self, parent, title, subtitle=None, **kwargs):
        super().__init__(parent, bg=theme.BG_VOID, **kwargs)
        left = tk.Frame(self, bg=theme.BG_VOID)
        left.pack(side="left", fill="x")
        tk.Label(left, text=title, font=theme.FONT_TITLE, bg=theme.BG_VOID,
                 fg=theme.TEXT_PRIMARY).pack(anchor="w")
        if subtitle:
            tk.Label(left, text=subtitle, font=theme.FONT_SUBTITLE, bg=theme.BG_VOID,
                     fg=theme.TEXT_SECONDARY).pack(anchor="w", pady=(2, 0))
        self.actions = tk.Frame(self, bg=theme.BG_VOID)
        self.actions.pack(side="right")


def styled_button(parent, text, command, kind="default"):
    """A flat, dark-themed button. kind: default | primary | danger"""
    palette = {
        "default": (theme.BG_PANEL_RAISED, theme.TEXT_PRIMARY, theme.BORDER),
        "primary": (theme.ACCENT, "#031018", theme.ACCENT),
        "danger": (theme.STATUS_ALERT, "#1a0505", theme.STATUS_ALERT),
    }
    bg, fg, border = palette.get(kind, palette["default"])
    btn = tk.Button(
        parent, text=text, command=command, bg=bg, fg=fg,
        activebackground=border, activeforeground=fg,
        font=theme.FONT_LABEL_BOLD, relief="flat", bd=0,
        padx=14, pady=7, cursor="hand2", highlightthickness=0,
    )
    return btn


# =============================================================================
# Main Application
# =============================================================================
class FIMApp:

    NAV_ITEMS = [
        ("dashboard", "📊", "Dashboard"),
        ("users", "🛂", "PKI / Users"),
        ("baseline", "🗂", "Baseline"),
        ("monitor", "🛰", "Live Monitor"),
        ("logs", "📜", "Audit Logs"),
        ("notifications", "🔔", "Notifications"),
        ("settings", "⚙", "Settings"),
        ("about", "ℹ", "About"),
    ]

    def __init__(self, root):
        self.root = root
        self.root.title(f"{config.APP_NAME} — {config.AUTHOR}")
        self.root.geometry("1280x780")
        self.root.minsize(1100, 680)
        self.root.configure(bg=theme.BG_VOID)

        # Core components -----------------------------------------------
        self.pki = PKIManager()
        self.signer = Signer(self.pki)
        self.db = DBManager()
        self.logger = LogManager()
        self.notifier = NotificationManager()

        self.observer = None
        self.monitoring_active = False
        self.scan_thread_running = False
        self.current_page = None

        self._configure_ttk_style()
        self._build_shell()
        self._build_pages()
        self.show_page("dashboard")

        self._start_periodic_scan()
        self.root.after(1000, self._poll_alerts)
        self.root.after(2000, self._refresh_clock)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # =========================================================================
    # ttk theme configuration (dark)
    # =========================================================================
    def _configure_ttk_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        style.configure("Treeview", background=theme.BG_PANEL, fieldbackground=theme.BG_PANEL,
                         foreground=theme.TEXT_PRIMARY, borderwidth=0, rowheight=26,
                         font=theme.FONT_BODY)
        style.configure("Treeview.Heading", background=theme.BG_PANEL_RAISED,
                         foreground=theme.TEXT_SECONDARY, font=theme.FONT_LABEL_BOLD,
                         borderwidth=0, relief="flat")
        style.map("Treeview", background=[("selected", theme.ACCENT_DIM)],
                  foreground=[("selected", theme.TEXT_PRIMARY)])
        style.map("Treeview.Heading", background=[("active", theme.BG_PANEL_RAISED)])

        style.configure("TCombobox", fieldbackground=theme.BG_INPUT, background=theme.BG_INPUT,
                         foreground=theme.TEXT_PRIMARY, arrowcolor=theme.TEXT_SECONDARY,
                         borderwidth=0)
        style.configure("TEntry", fieldbackground=theme.BG_INPUT, foreground=theme.TEXT_PRIMARY,
                         borderwidth=0, insertcolor=theme.TEXT_PRIMARY)
        style.configure("TCheckbutton", background=theme.BG_PANEL, foreground=theme.TEXT_PRIMARY,
                         font=theme.FONT_BODY)
        style.map("TCheckbutton", background=[("active", theme.BG_PANEL)])

        style.configure("Horizontal.TScrollbar", background=theme.BG_PANEL_RAISED,
                         troughcolor=theme.BG_VOID, borderwidth=0, arrowcolor=theme.TEXT_SECONDARY)
        style.configure("Vertical.TScrollbar", background=theme.BG_PANEL_RAISED,
                         troughcolor=theme.BG_VOID, borderwidth=0, arrowcolor=theme.TEXT_SECONDARY)

    # =========================================================================
    # Shell: sidebar + content area
    # =========================================================================
    def _build_shell(self):
        container = tk.Frame(self.root, bg=theme.BG_VOID)
        container.pack(fill="both", expand=True)

        # ---- Sidebar -----------------------------------------------------
        sidebar = tk.Frame(container, bg=theme.BG_PANEL_RAISED, width=230)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        brand = tk.Frame(sidebar, bg=theme.BG_PANEL_RAISED)
        brand.pack(fill="x", pady=(22, 26), padx=20)
        tk.Label(brand, text="🛡  SENTINEL", font=(theme.FONT_UI, 15, "bold"),
                 bg=theme.BG_PANEL_RAISED, fg=theme.TEXT_PRIMARY).pack(anchor="w")
        tk.Label(brand, text="FIM · PKI · AUDIT", font=(theme.FONT_MONO, 8),
                 bg=theme.BG_PANEL_RAISED, fg=theme.ACCENT).pack(anchor="w", pady=(2, 0))

        self.nav_buttons = {}
        nav_frame = tk.Frame(sidebar, bg=theme.BG_PANEL_RAISED)
        nav_frame.pack(fill="x")
        for key, icon, label in self.NAV_ITEMS:
            self._add_nav_button(nav_frame, key, icon, label)

        # ---- Sidebar bottom: live status strip ---------------------------
        status_frame = tk.Frame(sidebar, bg=theme.BG_PANEL)
        status_frame.pack(side="bottom", fill="x")

        self.threat_dot_var = tk.StringVar(value="●")
        threat_row = tk.Frame(status_frame, bg=theme.BG_PANEL)
        threat_row.pack(fill="x", padx=18, pady=(14, 4))
        self.threat_dot_label = tk.Label(threat_row, textvariable=self.threat_dot_var,
                                          font=(theme.FONT_UI, 12), bg=theme.BG_PANEL,
                                          fg=theme.STATUS_OK)
        self.threat_dot_label.pack(side="left")
        self.threat_text_var = tk.StringVar(value="System Secure")
        tk.Label(threat_row, textvariable=self.threat_text_var, font=theme.FONT_LABEL_BOLD,
                 bg=theme.BG_PANEL, fg=theme.TEXT_PRIMARY).pack(side="left", padx=(8, 0))

        self.monitor_status_var = tk.StringVar(value="Monitor: Idle")
        tk.Label(status_frame, textvariable=self.monitor_status_var, font=theme.FONT_SMALL,
                 bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY).pack(anchor="w", padx=18, pady=(0, 4))

        self.clock_var = tk.StringVar(value="")
        tk.Label(status_frame, textvariable=self.clock_var, font=theme.FONT_MONO_SMALL,
                 bg=theme.BG_PANEL, fg=theme.TEXT_MUTED).pack(anchor="w", padx=18, pady=(0, 14))

        # ---- Content area --------------------------------------------------
        self.content = tk.Frame(container, bg=theme.BG_VOID)
        self.content.pack(side="left", fill="both", expand=True)

        self.pages = {}

    def _add_nav_button(self, parent, key, icon, label):
        btn = tk.Button(
            parent, text=f"  {icon}   {label}", anchor="w", font=theme.FONT_NAV,
            bg=theme.BG_PANEL_RAISED, fg=theme.TEXT_SECONDARY, activebackground=theme.BG_PANEL,
            activeforeground=theme.TEXT_PRIMARY, relief="flat", bd=0, padx=8, pady=11,
            cursor="hand2", highlightthickness=0,
            command=lambda k=key: self.show_page(k),
        )
        btn.pack(fill="x")
        self.nav_buttons[key] = btn

    def show_page(self, key):
        for k, btn in self.nav_buttons.items():
            if k == key:
                btn.configure(bg=theme.BG_PANEL, fg=theme.ACCENT)
            else:
                btn.configure(bg=theme.BG_PANEL_RAISED, fg=theme.TEXT_SECONDARY)

        for k, frame in self.pages.items():
            frame.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        self.current_page = key

        if key == "dashboard":
            self.refresh_dashboard()
        elif key == "users":
            self.refresh_user_list()
        elif key == "baseline":
            self.refresh_baseline_list()
            self.refresh_baseline_user_dropdown()
        elif key == "monitor":
            self.refresh_monitor_user_dropdown()
        elif key == "logs":
            self.refresh_structured_log()
        elif key == "notifications":
            self.refresh_notification_outbox()

    def _refresh_clock(self):
        self.clock_var.set(datetime.now().strftime("%Y-%m-%d  %H:%M:%S"))
        self.root.after(1000, self._refresh_clock)

    def _page_container(self, key):
        frame = tk.Frame(self.content, bg=theme.BG_VOID)
        self.pages[key] = frame
        return frame

    def _scroll_body(self, parent, padx=32, pady=26):
        """Standard padded body wrapper for a page."""
        body = tk.Frame(parent, bg=theme.BG_VOID)
        body.pack(fill="both", expand=True, padx=padx, pady=pady)
        return body

    # =========================================================================
    def _build_pages(self):
        self._build_dashboard_page()
        self._build_users_page()
        self._build_baseline_page()
        self._build_monitor_page()
        self._build_logs_page()
        self._build_notifications_page()
        self._build_settings_page()
        self._build_about_page()

    # =========================================================================
    # DASHBOARD
    # =========================================================================
    def _build_dashboard_page(self):
        frame = self._page_container("dashboard")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "Security Dashboard",
                                "Real-time overview of integrity status and system activity")
        header.pack(fill="x")
        styled_button(header.actions, "Refresh", self.refresh_dashboard, "default").pack(side="right")

        # Stat cards row
        cards_row = tk.Frame(body, bg=theme.BG_VOID)
        cards_row.pack(fill="x", pady=(22, 18))
        self.card_files = StatCard(cards_row, "Files Monitored", theme.ACCENT)
        self.card_users = StatCard(cards_row, "Active Certificates", theme.STATUS_OK)
        self.card_alerts = StatCard(cards_row, "Alerts (24h)", theme.STATUS_ALERT)
        self.card_tampered = StatCard(cards_row, "Tampered Files", theme.STATUS_WARNING)
        for c in (self.card_files, self.card_users, self.card_alerts, self.card_tampered):
            c.pack(side="left", fill="both", expand=True, padx=8)
        cards_row.pack_configure(padx=0)

        # Charts + live feed row
        lower = tk.Frame(body, bg=theme.BG_VOID)
        lower.pack(fill="both", expand=True)

        chart_panel = tk.Frame(lower, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                                highlightthickness=1)
        chart_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        tk.Label(chart_panel, text="ACTIVITY OVERVIEW", font=theme.FONT_LABEL_BOLD,
                 bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(14, 6))
        self.dashboard_chart_frame = tk.Frame(chart_panel, bg=theme.BG_PANEL)
        self.dashboard_chart_frame.pack(fill="both", expand=True, padx=10, pady=(0, 12))

        feed_panel = tk.Frame(lower, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                               highlightthickness=1, width=360)
        feed_panel.pack(side="left", fill="y")
        feed_panel.pack_propagate(False)
        tk.Label(feed_panel, text="RECENT EVENTS", font=theme.FONT_LABEL_BOLD,
                 bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY).pack(anchor="w", padx=16, pady=(14, 6))
        self.dashboard_feed = scrolledtext.ScrolledText(
            feed_panel, bg=theme.BG_PANEL, fg=theme.TEXT_PRIMARY, font=theme.FONT_MONO_SMALL,
            relief="flat", bd=0, wrap="word", height=20,
        )
        self.dashboard_feed.pack(fill="both", expand=True, padx=10, pady=(0, 12))
        for level, color in theme.LEVEL_COLORS.items():
            self.dashboard_feed.tag_config(level, foreground=color)
        self.dashboard_feed.configure(state="disabled")

    def refresh_dashboard(self):
        status_counts = self.db.count_by_status()
        active_users = sum(1 for _u, s, _e in self.pki.list_users() if s == "ACTIVE")
        total_files = sum(status_counts.values())
        tampered = status_counts.get("TAMPERED", 0) + status_counts.get("MISSING", 0)

        entries = self.logger.read_structured_log(limit=5000)
        alert_count = sum(1 for e in entries if e.get("level") == LEVEL_ALERT)

        self.card_files.set_value(total_files)
        self.card_users.set_value(active_users)
        self.card_alerts.set_value(alert_count)
        self.card_tampered.set_value(tampered)

        self._update_threat_indicator(alert_count, tampered)
        self._render_dashboard_charts(entries, status_counts)
        self._render_dashboard_feed(entries)

    def _update_threat_indicator(self, alert_count, tampered):
        if tampered > 0 or alert_count > 0:
            self.threat_dot_label.configure(fg=theme.STATUS_ALERT)
            self.threat_text_var.set("Integrity Issues Detected")
        else:
            self.threat_dot_label.configure(fg=theme.STATUS_OK)
            self.threat_text_var.set("System Secure")

    def _render_dashboard_charts(self, entries, status_counts):
        for widget in self.dashboard_chart_frame.winfo_children():
            widget.destroy()

        counts = {"INFO": 0, "WARNING": 0, "ALERT": 0}
        for e in entries:
            lvl = e.get("level", "INFO")
            counts[lvl] = counts.get(lvl, 0) + 1

        fig, axes = plt.subplots(1, 2, figsize=(8.6, 3.6), facecolor=theme.BG_PANEL)
        for ax in axes:
            ax.set_facecolor(theme.BG_PANEL)
            ax.tick_params(colors=theme.TEXT_SECONDARY, labelsize=8)
            for spine in ax.spines.values():
                spine.set_color(theme.BORDER)

        axes[0].bar(counts.keys(), counts.values(),
                    color=[theme.STATUS_INFO, theme.STATUS_WARNING, theme.STATUS_ALERT])
        axes[0].set_title("Events by Severity", color=theme.TEXT_PRIMARY, fontsize=10)

        labels = [k for k, v in status_counts.items() if v > 0] or ["No data"]
        values = [v for v in status_counts.values() if v > 0] or [1]
        color_map = {**theme.FILE_STATUS_COLORS, "No data": theme.STATUS_NEUTRAL}
        pie_colors = [color_map.get(l, theme.STATUS_NEUTRAL) for l in labels]
        wedges, texts, autotexts = axes[1].pie(
            values, labels=labels, autopct="%1.0f%%", colors=pie_colors,
            textprops={"color": theme.TEXT_PRIMARY, "fontsize": 8},
        )
        axes[1].set_title("Baseline File Status", color=theme.TEXT_PRIMARY, fontsize=10)

        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, master=self.dashboard_chart_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        plt.close(fig)

    def _render_dashboard_feed(self, entries):
        self.dashboard_feed.configure(state="normal")
        self.dashboard_feed.delete("1.0", tk.END)
        for e in list(reversed(entries))[:60]:
            ts = e.get("timestamp", "")[11:19]
            line = f"[{ts}] {e.get('level','INFO'):7s} {e.get('event','')} — {e.get('filepath','') or e.get('message','')}\n"
            self.dashboard_feed.insert(tk.END, line, e.get("level", "INFO"))
        self.dashboard_feed.configure(state="disabled")

    # =========================================================================
    # USERS / PKI PAGE
    # =========================================================================
    def _build_users_page(self):
        frame = self._page_container("users")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "PKI / Certificate Authority",
                                "Issue and revoke per-user RSA key pairs and X.509 certificates")
        header.pack(fill="x")

        panel = tk.Frame(body, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(22, 0))

        toolbar = tk.Frame(panel, bg=theme.BG_PANEL)
        toolbar.pack(fill="x", padx=18, pady=16)

        tk.Label(toolbar, text="USERNAME", font=theme.FONT_SMALL, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.username_entry = ttk.Entry(toolbar, width=28, style="TEntry")
        self.username_entry.grid(row=1, column=0, sticky="w", padx=(0, 8))

        styled_button(toolbar, "➕  Issue Certificate", self.generate_certificate, "primary").grid(
            row=1, column=1, padx=4)
        styled_button(toolbar, "🚫  Revoke Certificate", self.revoke_certificate, "danger").grid(
            row=1, column=2, padx=4)
        styled_button(toolbar, "↻  Refresh", self.refresh_user_list, "default").grid(
            row=1, column=3, padx=4)

        columns = ("username", "status", "expires")
        self.user_tree = ttk.Treeview(panel, columns=columns, show="headings", height=16)
        self.user_tree.heading("username", text="Username")
        self.user_tree.heading("status", text="Certificate Status")
        self.user_tree.heading("expires", text="Expires")
        self.user_tree.column("username", width=300)
        self.user_tree.column("status", width=160, anchor="center")
        self.user_tree.column("expires", width=160, anchor="center")
        self.user_tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))

        for status, color in theme.CERT_STATUS_COLORS.items():
            self.user_tree.tag_configure(status, foreground=color)

        self.refresh_user_list()

    def generate_certificate(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Input Required", "Please enter a username.")
            return
        try:
            self.pki.register_user(username)
            self.logger.log_event(LEVEL_INFO, "USER_REGISTERED", username=username,
                                   message="New PKI certificate issued.")
            messagebox.showinfo("Certificate Issued", f"Certificate successfully issued for '{username}'.")
            self.refresh_user_list()
            self.refresh_baseline_user_dropdown()
            self.refresh_monitor_user_dropdown()
        except FileExistsError as e:
            messagebox.showerror("Error", str(e))
        except Exception as e:
            messagebox.showerror("Error", f"Could not issue certificate: {e}")

    def revoke_certificate(self):
        username = self.username_entry.get().strip()
        if not username:
            messagebox.showwarning("Input Required", "Please enter a username to revoke.")
            return
        if not self.pki.user_exists(username):
            messagebox.showerror("Error", f"No certificate found for '{username}'.")
            return
        if not messagebox.askyesno("Confirm Revocation",
                                    f"Revoke the certificate for '{username}'?\n"
                                    "Files signed by this user will fail integrity checks afterwards."):
            return
        changed = self.pki.revoke_certificate(username)
        if changed:
            self.logger.log_event(LEVEL_WARNING, "USER_REVOKED", username=username,
                                   message="Certificate revoked by administrator.")
            self.notifier.dispatch(LEVEL_WARNING, "USER_REVOKED", "", username,
                                    "Certificate revoked by administrator.")
            messagebox.showinfo("Revoked", f"Certificate for '{username}' has been revoked.")
        else:
            messagebox.showinfo("Already Revoked", f"'{username}' was already revoked.")
        self.refresh_user_list()

    def refresh_user_list(self):
        for row in self.user_tree.get_children():
            self.user_tree.delete(row)
        for username, status, expires in self.pki.list_users():
            self.user_tree.insert("", "end", values=(username, status, expires), tags=(status,))

    # =========================================================================
    # BASELINE PAGE
    # =========================================================================
    def _build_baseline_page(self):
        frame = self._page_container("baseline")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "Integrity Baseline",
                                "Register files and folders; each is hashed (SHA-256) and digitally signed")
        header.pack(fill="x")

        panel = tk.Frame(body, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(22, 0))

        toolbar = tk.Frame(panel, bg=theme.BG_PANEL)
        toolbar.pack(fill="x", padx=18, pady=16)

        tk.Label(toolbar, text="SIGNING USER", font=theme.FONT_SMALL, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.baseline_user_var = tk.StringVar()
        self.baseline_user_combo = ttk.Combobox(toolbar, textvariable=self.baseline_user_var,
                                                  state="readonly", width=22)
        self.baseline_user_combo.grid(row=1, column=0, sticky="w", padx=(0, 8))

        styled_button(toolbar, "📄  Add File", self.add_baseline_file, "primary").grid(row=1, column=1, padx=4)
        styled_button(toolbar, "📁  Add Folder", self.add_baseline_folder, "default").grid(row=1, column=2, padx=4)
        styled_button(toolbar, "✅  Re-Verify All", self.verify_all_baseline, "default").grid(row=1, column=3, padx=4)
        styled_button(toolbar, "🗑  Remove Selected", self.remove_baseline_file, "danger").grid(row=1, column=4, padx=4)

        columns = ("filepath", "username", "status", "last_checked")
        self.baseline_tree = ttk.Treeview(panel, columns=columns, show="headings", height=16)
        self.baseline_tree.heading("filepath", text="File Path")
        self.baseline_tree.heading("username", text="Registered By")
        self.baseline_tree.heading("status", text="Status")
        self.baseline_tree.heading("last_checked", text="Last Checked (UTC)")
        self.baseline_tree.column("filepath", width=440)
        self.baseline_tree.column("username", width=130, anchor="center")
        self.baseline_tree.column("status", width=110, anchor="center")
        self.baseline_tree.column("last_checked", width=190, anchor="center")
        self.baseline_tree.pack(fill="both", expand=True, padx=18, pady=(0, 18))

        for status, color in theme.FILE_STATUS_COLORS.items():
            self.baseline_tree.tag_configure(status, foreground=color)

        self.refresh_baseline_user_dropdown()
        self.refresh_baseline_list()

    def refresh_baseline_user_dropdown(self):
        users = [u for u, status, _ in self.pki.list_users() if status == "ACTIVE"]
        self.baseline_user_combo["values"] = users
        if users and not self.baseline_user_var.get():
            self.baseline_user_var.set(users[0])

    def _register_single_file(self, username, filepath):
        try:
            file_hash, signature = self.signer.sign_file(username, filepath)
            self.db.add_file(username, filepath, file_hash, signature)
            self.logger.log_event(LEVEL_INFO, "FILE_BASELINED", filepath=filepath, username=username,
                                   message="File added to the signed integrity baseline.")
            return True
        except Exception as e:
            self.logger.log_event(LEVEL_WARNING, "BASELINE_ERROR", filepath=filepath, username=username,
                                   message=f"Failed to baseline file: {e}")
            return False

    def add_baseline_file(self):
        username = self.baseline_user_var.get()
        if not username:
            messagebox.showwarning("No User Selected", "Please issue/select a signing user first (PKI / Users page).")
            return
        filepath = filedialog.askopenfilename(title="Select file to add to baseline")
        if not filepath:
            return
        if self._register_single_file(username, filepath):
            messagebox.showinfo("Baseline Updated", f"File registered:\n{filepath}")
            self.refresh_baseline_list()

    def add_baseline_folder(self):
        username = self.baseline_user_var.get()
        if not username:
            messagebox.showwarning("No User Selected", "Please issue/select a signing user first (PKI / Users page).")
            return
        folder = filedialog.askdirectory(title="Select folder to baseline")
        if not folder:
            return

        count, failed = 0, 0
        for root_dir, _dirs, files in os.walk(folder):
            for fname in files:
                fpath = os.path.join(root_dir, fname)
                if self._register_single_file(username, fpath):
                    count += 1
                else:
                    failed += 1

        messagebox.showinfo("Baseline Updated", f"Registered {count} file(s).\nFailed: {failed}")
        self.refresh_baseline_list()

    def remove_baseline_file(self):
        selected = self.baseline_tree.selection()
        if not selected:
            messagebox.showwarning("No Selection", "Select a file in the table first.")
            return
        for item in selected:
            filepath = self.baseline_tree.item(item)["values"][0]
            self.db.remove_file(filepath)
            self.logger.log_event(LEVEL_INFO, "FILE_REMOVED_FROM_BASELINE", filepath=filepath,
                                   message="File removed from integrity baseline.")
        self.refresh_baseline_list()

    def verify_all_baseline(self):
        threading.Thread(target=self._verify_all_baseline_worker, daemon=True).start()

    def _verify_all_baseline_worker(self):
        records = self.db.all_filepaths()
        for filepath, username, _file_hash, signature in records:
            if not os.path.isfile(filepath):
                self.db.update_status(filepath, "MISSING")
                self.logger.log_event(LEVEL_ALERT, "FILE_MISSING", filepath=filepath, username=username,
                                       message="Monitored file is missing during scheduled scan.")
                self.notifier.dispatch(LEVEL_ALERT, "FILE_MISSING", filepath, username,
                                        "Monitored file is missing during scheduled scan.")
                continue
            valid = self.signer.verify_signature(username, filepath, signature)
            if valid:
                self.db.update_status(filepath, "OK")
            else:
                self.db.update_status(filepath, "TAMPERED")
                self.logger.log_event(LEVEL_ALERT, "INTEGRITY_VIOLATION", filepath=filepath, username=username,
                                       message="Scheduled scan detected a baseline mismatch.")
                self.notifier.dispatch(LEVEL_ALERT, "INTEGRITY_VIOLATION", filepath, username,
                                        "Scheduled scan detected a baseline mismatch.")
        self.root.after(0, self.refresh_baseline_list)
        self.root.after(0, self.refresh_dashboard)

    def refresh_baseline_list(self):
        for row in self.baseline_tree.get_children():
            self.baseline_tree.delete(row)
        for filepath, username, _registered_at, status, last_checked in self.db.list_files():
            last_checked = (last_checked or "")[:19].replace("T", " ")
            self.baseline_tree.insert("", "end", values=(filepath, username, status, last_checked),
                                       tags=(status,))

    # =========================================================================
    # MONITOR PAGE
    # =========================================================================
    def _build_monitor_page(self):
        frame = self._page_container("monitor")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "Live Monitor",
                                "Real-time filesystem watch with instant integrity verification")
        header.pack(fill="x")

        panel = tk.Frame(body, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(22, 0))

        toolbar = tk.Frame(panel, bg=theme.BG_PANEL)
        toolbar.pack(fill="x", padx=18, pady=16)

        tk.Label(toolbar, text="FOLDER", font=theme.FONT_SMALL, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY).grid(row=0, column=0, sticky="w")
        self.monitor_folder_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self.monitor_folder_var, width=48).grid(
            row=1, column=0, sticky="w", padx=(0, 6))
        styled_button(toolbar, "Browse", self.browse_monitor_folder, "default").grid(row=1, column=1, padx=4)

        tk.Label(toolbar, text="ACTIVE USER", font=theme.FONT_SMALL, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY).grid(row=0, column=2, sticky="w", padx=(20, 0))
        self.monitor_user_var = tk.StringVar()
        self.monitor_user_combo = ttk.Combobox(toolbar, textvariable=self.monitor_user_var,
                                                state="readonly", width=20)
        self.monitor_user_combo.grid(row=1, column=2, sticky="w", padx=(20, 6))

        self.start_btn = styled_button(toolbar, "▶  Start Monitoring", self.start_monitoring, "primary")
        self.start_btn.grid(row=1, column=3, padx=4)
        self.stop_btn = styled_button(toolbar, "■  Stop Monitoring", self.stop_monitoring, "danger")
        self.stop_btn.grid(row=1, column=4, padx=4)
        self.stop_btn.configure(state="disabled")

        status_row = tk.Frame(panel, bg=theme.BG_PANEL)
        status_row.pack(fill="x", padx=18, pady=(0, 8))
        self.monitor_state_dot = tk.Label(status_row, text="●", font=(theme.FONT_UI, 12),
                                           bg=theme.BG_PANEL, fg=theme.TEXT_MUTED)
        self.monitor_state_dot.pack(side="left")
        self.monitor_state_var = tk.StringVar(value="Idle — no folder is being watched")
        tk.Label(status_row, textvariable=self.monitor_state_var, font=theme.FONT_LABEL_BOLD,
                 bg=theme.BG_PANEL, fg=theme.TEXT_PRIMARY).pack(side="left", padx=(8, 0))

        self.monitor_output = scrolledtext.ScrolledText(
            panel, bg=theme.BG_VOID, fg=theme.TEXT_PRIMARY, font=theme.FONT_MONO_BODY,
            relief="flat", bd=0, insertbackground=theme.TEXT_PRIMARY,
        )
        self.monitor_output.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        for level, color in theme.LEVEL_COLORS.items():
            self.monitor_output.tag_config(level, foreground=color)

        self.refresh_monitor_user_dropdown()

    def refresh_monitor_user_dropdown(self):
        users = [u for u, status, _ in self.pki.list_users() if status == "ACTIVE"]
        self.monitor_user_combo["values"] = users
        if users and not self.monitor_user_var.get():
            self.monitor_user_var.set(users[0])

    def browse_monitor_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.monitor_folder_var.set(folder)

    def start_monitoring(self):
        folder = self.monitor_folder_var.get().strip()
        if not folder or not os.path.isdir(folder):
            messagebox.showwarning("Invalid Folder", "Please choose a valid folder to monitor.")
            return
        if self.monitoring_active:
            messagebox.showinfo("Already Running", "Monitoring is already active.")
            return

        username = self.monitor_user_var.get() or None

        handler = FIMEventHandler(self.db, self.signer, self.logger, notifier=self.notifier,
                                   active_user=username)
        self.observer = Observer()
        self.observer.schedule(handler, path=folder, recursive=True)
        self.observer.start()

        self.monitoring_active = True
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.monitor_state_dot.configure(fg=theme.STATUS_OK)
        self.monitor_state_var.set(f"Monitoring: {folder}")
        self.monitor_status_var.set("Monitor: Active")
        self._append_monitor_line(LEVEL_INFO, f"Real-time monitoring started on: {folder}")
        self.logger.log_event(LEVEL_INFO, "MONITOR_STARTED", filepath=folder, username=username or "",
                               message="Real-time folder monitoring started.")

    def stop_monitoring(self):
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
            self.observer = None
        self.monitoring_active = False
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.monitor_state_dot.configure(fg=theme.TEXT_MUTED)
        self.monitor_state_var.set("Idle — no folder is being watched")
        self.monitor_status_var.set("Monitor: Idle")
        self._append_monitor_line(LEVEL_INFO, "Real-time monitoring stopped.")
        self.logger.log_event(LEVEL_INFO, "MONITOR_STOPPED", message="Real-time folder monitoring stopped.")

    def _append_monitor_line(self, level, text):
        timestamp = datetime.now().strftime("%H:%M:%S")
        icon = {"INFO": "ℹ", "WARNING": "⚠", "ALERT": "🚨"}.get(level, "•")
        self.monitor_output.insert(tk.END, f"[{timestamp}] {icon}  {text}\n", level)
        self.monitor_output.see(tk.END)

    # =========================================================================
    # LOGS PAGE
    # =========================================================================
    def _build_logs_page(self):
        frame = self._page_container("logs")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "Audit Logs",
                                "Structured event log (JSON-Lines) + encrypted tamper-evident audit trail")
        header.pack(fill="x")
        styled_button(header.actions, "🔐  View Encrypted Log", self.view_encrypted_log, "default").pack(
            side="right", padx=4)
        styled_button(header.actions, "💾  Export CSV Report", self.export_csv_report, "primary").pack(
            side="right", padx=4)
        styled_button(header.actions, "↻  Refresh", self.refresh_structured_log, "default").pack(
            side="right", padx=4)

        panel = tk.Frame(body, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(22, 0))

        columns = ("timestamp", "level", "event", "username", "filepath", "message")
        self.log_tree = ttk.Treeview(panel, columns=columns, show="headings", height=22)
        widths = {"timestamp": 165, "level": 75, "event": 190, "username": 100, "filepath": 260, "message": 320}
        headings = {"timestamp": "Timestamp (UTC)", "level": "Level", "event": "Event",
                     "username": "User", "filepath": "Path", "message": "Message"}
        for col in columns:
            self.log_tree.heading(col, text=headings[col])
            self.log_tree.column(col, width=widths[col], anchor="w")
        self.log_tree.pack(fill="both", expand=True, padx=18, pady=18)

        for level, color in theme.LEVEL_COLORS.items():
            self.log_tree.tag_configure(level, foreground=color)

        self.refresh_structured_log()

    def refresh_structured_log(self):
        for row in self.log_tree.get_children():
            self.log_tree.delete(row)
        for entry in reversed(self.logger.read_structured_log()):
            ts = entry.get("timestamp", "")[:19].replace("T", " ")
            self.log_tree.insert("", "end", values=(
                ts, entry.get("level", ""), entry.get("event", ""),
                entry.get("username", ""), entry.get("filepath", ""), entry.get("message", "")
            ), tags=(entry.get("level", "INFO"),))

    def view_encrypted_log(self):
        win = tk.Toplevel(self.root)
        win.title("Decrypted Audit Log — monitor.enc")
        win.geometry("800x480")
        win.configure(bg=theme.BG_VOID)
        text = scrolledtext.ScrolledText(win, font=theme.FONT_MONO_SMALL, bg=theme.BG_VOID,
                                          fg=theme.TEXT_PRIMARY, relief="flat", bd=0)
        text.pack(fill="both", expand=True, padx=14, pady=14)

        entries = self.logger.read_encrypted_log()
        if not entries:
            text.insert(tk.END, "No encrypted audit log entries found yet.\n")
        for line in entries:
            text.insert(tk.END, line + "\n")

    def export_csv_report(self):
        try:
            path = self.logger.export_csv()
            messagebox.showinfo("Export Complete", f"Report exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export Failed", str(e))

    # =========================================================================
    # NOTIFICATIONS PAGE (Notification Center)
    # =========================================================================
    def _build_notifications_page(self):
        frame = self._page_container("notifications")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "Notification Center",
                                "Delivery log for email and SMS alerts dispatched on WARNING / ALERT events")
        header.pack(fill="x")
        styled_button(header.actions, "✉  Send Test Alert", self.send_test_notification, "primary").pack(
            side="right", padx=4)
        styled_button(header.actions, "↻  Refresh", self.refresh_notification_outbox, "default").pack(
            side="right", padx=4)

        note = tk.Label(
            body,
            text="Demo mode: messages below are fully formatted and logged exactly as a live SMTP/SMS "
                 "provider call would send them, but no real network delivery occurs. Configure recipients "
                 "in Settings.",
            font=theme.FONT_SMALL, bg=theme.BG_VOID, fg=theme.TEXT_MUTED, wraplength=900, justify="left",
        )
        note.pack(fill="x", pady=(10, 0), anchor="w")

        panel = tk.Frame(body, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(16, 0))

        columns = ("timestamp", "channel", "to", "content", "status")
        self.notify_tree = ttk.Treeview(panel, columns=columns, show="headings", height=22)
        widths = {"timestamp": 165, "channel": 80, "to": 200, "content": 470, "status": 130}
        headings = {"timestamp": "Timestamp (UTC)", "channel": "Channel", "to": "Recipient",
                     "content": "Subject / Message", "status": "Status"}
        for col in columns:
            self.notify_tree.heading(col, text=headings[col])
            self.notify_tree.column(col, width=widths[col], anchor="w")
        self.notify_tree.pack(fill="both", expand=True, padx=18, pady=18)
        self.notify_tree.tag_configure("EMAIL", foreground=theme.STATUS_INFO)
        self.notify_tree.tag_configure("SMS", foreground=theme.ACCENT)

        self.refresh_notification_outbox()

    def refresh_notification_outbox(self):
        for row in self.notify_tree.get_children():
            self.notify_tree.delete(row)
        for record in reversed(self.notifier.read_outbox()):
            ts = record.get("timestamp", "")[:19].replace("T", " ")
            content = record.get("subject") or record.get("body", "")
            self.notify_tree.insert("", "end", values=(
                ts, record.get("channel", ""), record.get("to", ""), content, record.get("status", "")
            ), tags=(record.get("channel", ""),))

    def send_test_notification(self):
        self.notifier.send_test_notification()
        self.root.after(400, self.refresh_notification_outbox)
        messagebox.showinfo("Test Alert Dispatched",
                             "A test notification was queued on all enabled channels.\n"
                             "Check the table below for the delivery record.")

    # =========================================================================
    # SETTINGS PAGE
    # =========================================================================
    def _build_settings_page(self):
        frame = self._page_container("settings")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "Settings",
                                "Configure notification channels and alert thresholds")
        header.pack(fill="x")

        panel = tk.Frame(body, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(22, 0))

        inner = tk.Frame(panel, bg=theme.BG_PANEL)
        inner.pack(fill="x", padx=24, pady=24, anchor="n")

        cfg = self.notifier.cfg

        # Email
        tk.Label(inner, text="EMAIL ALERTS", font=theme.FONT_LABEL_BOLD, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY).grid(row=0, column=0, sticky="w", pady=(0, 6))
        self.email_enabled_var = tk.BooleanVar(value=cfg.get("email_enabled", True))
        ttk.Checkbutton(inner, text="Enable email notifications", variable=self.email_enabled_var
                         ).grid(row=1, column=0, columnspan=2, sticky="w")

        tk.Label(inner, text="Recipient address", font=theme.FONT_SMALL, bg=theme.BG_PANEL,
                 fg=theme.TEXT_MUTED).grid(row=2, column=0, sticky="w", pady=(10, 2))
        self.email_addr_var = tk.StringVar(value=cfg.get("email_address", ""))
        ttk.Entry(inner, textvariable=self.email_addr_var, width=40).grid(row=3, column=0, sticky="w")

        # SMS
        tk.Label(inner, text="SMS ALERTS", font=theme.FONT_LABEL_BOLD, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY).grid(row=0, column=1, sticky="w", padx=(60, 0), pady=(0, 6))
        self.sms_enabled_var = tk.BooleanVar(value=cfg.get("sms_enabled", True))
        ttk.Checkbutton(inner, text="Enable SMS notifications", variable=self.sms_enabled_var
                         ).grid(row=1, column=1, sticky="w", padx=(60, 0))

        tk.Label(inner, text="Recipient phone number", font=theme.FONT_SMALL, bg=theme.BG_PANEL,
                 fg=theme.TEXT_MUTED).grid(row=2, column=1, sticky="w", padx=(60, 0), pady=(10, 2))
        self.sms_number_var = tk.StringVar(value=cfg.get("sms_number", ""))
        ttk.Entry(inner, textvariable=self.sms_number_var, width=30).grid(row=3, column=1, sticky="w", padx=(60, 0))

        # Minimum severity
        tk.Label(inner, text="MINIMUM SEVERITY TO NOTIFY", font=theme.FONT_LABEL_BOLD, bg=theme.BG_PANEL,
                 fg=theme.TEXT_SECONDARY).grid(row=4, column=0, sticky="w", pady=(26, 6))
        self.min_level_var = tk.StringVar(value=cfg.get("min_level", "WARNING"))
        level_combo = ttk.Combobox(inner, textvariable=self.min_level_var, state="readonly",
                                    values=["INFO", "WARNING", "ALERT"], width=18)
        level_combo.grid(row=5, column=0, sticky="w")

        btn_row = tk.Frame(inner, bg=theme.BG_PANEL)
        btn_row.grid(row=6, column=0, columnspan=2, sticky="w", pady=(30, 0))
        styled_button(btn_row, "💾  Save Settings", self.save_notification_settings, "primary").pack(
            side="left", padx=(0, 8))
        styled_button(btn_row, "✉  Send Test Alert", self.send_test_notification, "default").pack(side="left")

        divider = tk.Frame(panel, bg=theme.BORDER, height=1)
        divider.pack(fill="x", padx=24, pady=(20, 0))

        info = tk.Label(
            panel,
            text="Note: this build simulates notification delivery (see Notification Center) rather than "
                 "sending live email/SMS, so no real credentials are required for the coursework demo.",
            font=theme.FONT_SMALL, bg=theme.BG_PANEL, fg=theme.TEXT_MUTED, wraplength=820, justify="left",
        )
        info.pack(anchor="w", padx=24, pady=16)

    def save_notification_settings(self):
        self.notifier.save({
            "email_enabled": self.email_enabled_var.get(),
            "email_address": self.email_addr_var.get().strip(),
            "sms_enabled": self.sms_enabled_var.get(),
            "sms_number": self.sms_number_var.get().strip(),
            "min_level": self.min_level_var.get(),
        })
        messagebox.showinfo("Settings Saved", "Notification preferences have been updated.")

    # =========================================================================
    # ABOUT PAGE
    # =========================================================================
    def _build_about_page(self):
        frame = self._page_container("about")
        body = self._scroll_body(frame)

        header = SectionHeader(body, "About")
        header.pack(fill="x")

        panel = tk.Frame(body, bg=theme.BG_PANEL, highlightbackground=theme.BORDER,
                          highlightthickness=1)
        panel.pack(fill="both", expand=True, pady=(22, 0))

        inner = tk.Frame(panel, bg=theme.BG_PANEL)
        inner.pack(fill="both", expand=True, padx=28, pady=28)

        tk.Label(inner, text=f"{config.APP_NAME}", font=(theme.FONT_UI, 18, "bold"),
                 bg=theme.BG_PANEL, fg=theme.TEXT_PRIMARY).pack(anchor="w")
        tk.Label(inner, text=f"Version {config.APP_VERSION}", font=theme.FONT_SUBTITLE,
                 bg=theme.BG_PANEL, fg=theme.ACCENT).pack(anchor="w", pady=(2, 0))
        tk.Label(inner, text=f"Developed by {config.AUTHOR}", font=theme.FONT_SUBTITLE,
                 bg=theme.BG_PANEL, fg=theme.TEXT_SECONDARY).pack(anchor="w", pady=(2, 18))

        bullets = [
            "Public Key Infrastructure — RSA-2048 keys + self-signed X.509 certificates per user",
            "Digital signatures (RSA/PKCS1v15 + SHA-256) bind each file to its signing identity",
            "Real-time filesystem monitoring via the watchdog library",
            "Structured JSON-Lines logging plus a Fernet-encrypted, tamper-evident audit trail",
            "Simulated email/SMS Notification Center with a configurable delivery threshold",
            "Live dashboard (matplotlib) for event severity and baseline status",
            "Containerised deployment via Docker / Docker Compose",
        ]
        for b in bullets:
            row = tk.Frame(inner, bg=theme.BG_PANEL)
            row.pack(anchor="w", pady=3, fill="x")
            tk.Label(row, text="▸", font=theme.FONT_BODY, bg=theme.BG_PANEL, fg=theme.ACCENT).pack(side="left")
            tk.Label(row, text=" " + b, font=theme.FONT_BODY, bg=theme.BG_PANEL,
                     fg=theme.TEXT_PRIMARY, wraplength=820, justify="left").pack(side="left")

        tk.Label(
            inner,
            text="Coursework / demonstration build. Review private-key passphrase handling and enable a "
                 "live SMTP/SMS provider before any production deployment.",
            font=theme.FONT_SMALL, bg=theme.BG_PANEL, fg=theme.TEXT_MUTED, wraplength=820,
            justify="left",
        ).pack(anchor="w", pady=(20, 0))

    # =========================================================================
    # Background tasks
    # =========================================================================
    def _start_periodic_scan(self):
        if self.scan_thread_running:
            return
        self.scan_thread_running = True

        def loop():
            while self.scan_thread_running:
                time.sleep(config.PERIODIC_SCAN_INTERVAL)
                try:
                    self._verify_all_baseline_worker()
                except Exception as e:
                    self.logger.log_event(LEVEL_WARNING, "SCAN_ERROR", message=str(e))

        threading.Thread(target=loop, daemon=True).start()

    def _poll_alerts(self):
        for entry in self.logger.get_pending_alerts():
            level = entry.get("level", "INFO")
            if self.current_page == "monitor":
                self._append_monitor_line(level, f"{entry.get('event')}: {entry.get('filepath')} - {entry.get('message')}")
            if level == LEVEL_ALERT:
                self.root.bell()
                messagebox.showwarning(
                    "🚨 Integrity Alert",
                    f"{entry.get('event')}\n\nFile: {entry.get('filepath')}\n"
                    f"User: {entry.get('username')}\n\n{entry.get('message')}"
                )
            if self.current_page == "dashboard":
                self.refresh_dashboard()
            if self.current_page == "baseline":
                self.refresh_baseline_list()
            if self.current_page == "logs":
                self.refresh_structured_log()
            if self.current_page == "notifications":
                self.refresh_notification_outbox()
        self.root.after(1000, self._poll_alerts)

    def _on_close(self):
        self.scan_thread_running = False
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=3)
        self.root.destroy()


# =============================================================================
if __name__ == "__main__":
    root = tk.Tk()
    app = FIMApp(root)
    root.mainloop()
