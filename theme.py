"""
theme.py
--------
Centralised visual design tokens for the FIM-PKI Sentinel GUI.

Design direction: a dark, security-operations-center (SOC) console —
the same visual register as tools like Splunk, Wazuh, and CrowdStrike
Falcon. One signature accent (signal cyan) is used sparingly against a
near-black ground; status colors (green/amber/red) are reserved
strictly for OK/WARNING/ALERT semantics so they stay meaningful instead
of decorative.

Author: Dijan Ghale
"""

# ---------------------------------------------------------------------------
# Palette
# ---------------------------------------------------------------------------
BG_VOID = "#0a0e14"        # outermost background
BG_PANEL = "#10151d"       # panel / card background
BG_PANEL_RAISED = "#161c27"  # raised panel (sidebar, headers)
BG_INPUT = "#0d1219"

BORDER = "#222a36"
BORDER_SUBTLE = "#1a2029"

TEXT_PRIMARY = "#e6edf3"
TEXT_SECONDARY = "#8b96a5"
TEXT_MUTED = "#5b6573"

ACCENT = "#00d4ff"          # signal cyan — the one signature color
ACCENT_DIM = "#0a4d5c"

STATUS_OK = "#3fb950"
STATUS_WARNING = "#d29922"
STATUS_ALERT = "#f85149"
STATUS_INFO = "#58a6ff"
STATUS_NEUTRAL = "#5b6573"

# ---------------------------------------------------------------------------
# Typography
# ---------------------------------------------------------------------------
FONT_UI = "Segoe UI"
FONT_MONO = "Consolas"

FONT_TITLE = (FONT_UI, 20, "bold")
FONT_SUBTITLE = (FONT_UI, 11)
FONT_SECTION = (FONT_UI, 13, "bold")
FONT_LABEL = (FONT_UI, 10)
FONT_LABEL_BOLD = (FONT_UI, 10, "bold")
FONT_BODY = (FONT_UI, 10)
FONT_SMALL = (FONT_UI, 9)
FONT_NAV = (FONT_UI, 11)
FONT_STAT_NUMBER = (FONT_UI, 26, "bold")
FONT_MONO_BODY = (FONT_MONO, 10)
FONT_MONO_SMALL = (FONT_MONO, 9)

# ---------------------------------------------------------------------------
# Status color lookup helpers
# ---------------------------------------------------------------------------
LEVEL_COLORS = {
    "INFO": STATUS_INFO,
    "WARNING": STATUS_WARNING,
    "ALERT": STATUS_ALERT,
}

FILE_STATUS_COLORS = {
    "OK": STATUS_OK,
    "TAMPERED": STATUS_ALERT,
    "MISSING": STATUS_WARNING,
}

CERT_STATUS_COLORS = {
    "ACTIVE": STATUS_OK,
    "REVOKED": STATUS_ALERT,
}
