"""
user_client.py  —  End-user Security Alert Client
RogueAP Detection System v2.0

Two alert sources:
  1. Polls alert_server.py every 2 s — picks up admin Approve/Block/Quarantine instantly
  2. Monitors this device's connected Wi-Fi every 4 s — alerts the moment you join any network

v2.1 fix: popups used to fire immediately for every alert the server returned, so a
single scan of N nearby APs meant N modal windows appearing on top of each other at
once. Two fixes:
  - Popup QUEUE: only one popup is ever on screen; others wait their turn and the
    popup shows "+N more waiting".
  - Cooldown DEDUP: the same (ssid, bssid, status) won't pop up again for
    ALERT_COOLDOWN_S seconds — it's still logged to history, just not re-alerted.
"""

import customtkinter as ctk
import requests
import threading
import time
import os
import socket
import psycopg2
from datetime import datetime
import tkinter as tk

try:
    import pywifi
    from pywifi import const as wconst
    WIFI_OK = True
except Exception:
    WIFI_OK = False

# ── appearance ────────────────────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── config ────────────────────────────────────────────────────────────────────
ALERT_SERVER     = "http://127.0.0.1:5000"
POLL_MS          = 2000     # poll server every 2 s
WIFI_CHECK_S     = 4        # check connected network every 4 s

# Same (ssid, bssid, status) won't trigger a new popup again within this window.
# Still logged to history — just not re-shown as a modal. Tune to taste.
ALERT_COOLDOWN_S = 300      # 5 minutes

# Safe networks are logged to history but don't interrupt with a popup at all —
# they aren't actionable. Set to False if you want popups for SAFE too.
SUPPRESS_SAFE_POPUPS = True

# Identifies this device to the admin dashboard when it reports a connection
# event. Override by setting the CLIENT_NAME environment variable.
CLIENT_NAME = os.environ.get("CLIENT_NAME", socket.gethostname())

# ── palette  (ALL 6-digit hex — tkinter does not support 8-digit alpha hex) ──
BG        = "#0d1117"
BG_CARD   = "#161b22"
BG_ROW    = "#1c2128"
BORDER    = "#30363d"
TEXT      = "#e6edf3"
TEXT_SEC  = "#8b949e"
TEXT_MUT  = "#6e7681"
GREEN     = "#22c55e"
RED       = "#ef4444"
ORANGE    = "#f59e0b"
BLUE      = "#58a6ff"

# popup background colours — solid, no alpha
SAFE_BG   = "#052e16"
DANGER_BG = "#2d0a0a"
WARN_BG   = "#2d1d00"
SAFE_GRID = "#0a3d1f"
DANGER_GRID = "#3d1010"
WARN_GRID   = "#3d2600"

# ── optional DB (local SSID/BSSID lookup) ────────────────────────────────────
try:
    _db = psycopg2.connect(
        host     = os.environ.get("DB_HOST",     "localhost"),
        database = os.environ.get("DB_NAME",     "RogueAPDetection"),
        user     = os.environ.get("DB_USER",     "postgres"),
        password = os.environ.get("DB_PASSWORD", "admin123"),
    )
    _db.autocommit = True
    _dbc  = _db.cursor()
    DB_OK = True
except Exception:
    DB_OK = False
    _dbc  = None

def db_lookup(bssid):
    """Return (status, threat_level, encryption) for a BSSID, or None."""
    if not _dbc:
        return None
    try:
        _dbc.execute("""
            SELECT status, threat_level, encryption_type
            FROM access_points
            WHERE LOWER(TRIM(bssid)) = %s
        """, (bssid.lower().strip().rstrip(":"),))
        row = _dbc.fetchone()
        return row
    except Exception:
        return None

# ── main window ───────────────────────────────────────────────────────────────
root = ctk.CTk()
root.title("Wireless Security Alerts")
root.geometry("580x680")
root.configure(fg_color=BG)
root.resizable(False, True)

# position top-right of screen
root.update_idletasks()
sw = root.winfo_screenwidth()
root.geometry(f"580x680+{sw - 600}+{30}")

# ── header ────────────────────────────────────────────────────────────────────
hdr = ctk.CTkFrame(root, fg_color=BG_CARD, height=58, corner_radius=0,
                   border_width=1, border_color=BORDER)
hdr.pack(fill="x")
hdr.pack_propagate(False)

ctk.CTkLabel(hdr, text="📡  Wireless Security Alerts",
             font=("Inter", 16, "bold"), text_color=TEXT).pack(side="left", padx=18, pady=14)

badge_lbl = ctk.CTkLabel(hdr, text="0 alerts",
                          font=("Inter", 11), text_color=TEXT_SEC)
badge_lbl.pack(side="right", padx=8)

conn_dot = ctk.CTkLabel(hdr, text="● Connecting...",
                         font=("Inter", 11), text_color=ORANGE)
conn_dot.pack(side="right", padx=4)

# ── connected network bar ─────────────────────────────────────────────────────
net_bar = ctk.CTkFrame(root, fg_color=BG_ROW, height=36, corner_radius=0)
net_bar.pack(fill="x")
net_bar.pack_propagate(False)

net_icon = ctk.CTkLabel(net_bar, text="📶", font=("Arial", 14))
net_icon.pack(side="left", padx=(12, 4), pady=8)

net_lbl = ctk.CTkLabel(net_bar, text="Checking connected network...",
                        font=("Inter", 11), text_color=TEXT_SEC)
net_lbl.pack(side="left", pady=8)

net_status_dot = ctk.CTkLabel(net_bar, text="●", font=("Arial", 10),
                               text_color=TEXT_SEC)
net_status_dot.pack(side="right", padx=12)

# ── queue status bar (new) 
queue_bar = ctk.CTkFrame(root, fg_color="transparent", height=0)
queue_lbl = ctk.CTkLabel(root, text="", font=("Inter", 10, "bold"),
                          text_color=ORANGE)
# packed on demand in _update_queue_label()

# ── history list 
hist_hdr = ctk.CTkFrame(root, fg_color="transparent")
hist_hdr.pack(fill="x", padx=14, pady=(10, 2))
ctk.CTkLabel(hist_hdr, text="Alert History",
             font=("Inter", 13, "bold"), text_color=TEXT).pack(side="left")
clear_btn = ctk.CTkButton(hist_hdr, text="Clear", font=("Inter", 10),
                           fg_color=BG_CARD, hover_color=BG_ROW,
                           text_color=TEXT_SEC, height=24, width=56,
                           border_width=1, border_color=BORDER)
clear_btn.pack(side="right")

history_frame = ctk.CTkScrollableFrame(root, fg_color=BG_CARD, corner_radius=8)
history_frame.pack(fill="both", expand=True, padx=12, pady=(0, 4))

def clear_history():
    for w in history_frame.winfo_children():
        w.destroy()
    alert_count[0] = 0
    badge_lbl.configure(text="0 alerts")

clear_btn.configure(command=clear_history)

# ── status bar 
sbar = ctk.CTkFrame(root, fg_color=BG_CARD, height=26, corner_radius=0,
                    border_width=1, border_color=BORDER)
sbar.pack(fill="x", side="bottom")
sbar.pack_propagate(False)

status_lbl = ctk.CTkLabel(sbar, text="Waiting for alerts...",
                           font=("Inter", 10), text_color=TEXT_SEC)
status_lbl.pack(side="left", padx=12, pady=4)

db_dot = ctk.CTkLabel(sbar,
                       text="● DB connected" if DB_OK else "● DB offline",
                       font=("Inter", 10),
                       text_color=GREEN if DB_OK else RED)
db_dot.pack(side="right", padx=12, pady=4)

alert_count = [0]

# ── popup queue state (new) 
popup_queue   = []          # list[alert dict] waiting to be shown
active_popup  = {"win": None}

def _update_queue_label():
    n = len(popup_queue)
    if n > 0:
        queue_lbl.configure(text=f"⏳  {n} more alert{'s' if n != 1 else ''} waiting")
        if not queue_lbl.winfo_ismapped():
            queue_lbl.pack(fill="x", padx=14, pady=(4, 0))
    else:
        if queue_lbl.winfo_ismapped():
            queue_lbl.pack_forget()

def _popup_closed():
    """Called whenever the active popup is dismissed or auto-closes."""
    active_popup["win"] = None
    root.after(200, _show_next_popup)

def _show_next_popup():
    if active_popup["win"] is not None:
        return
    if not popup_queue:
        _update_queue_label()
        return
    alert = popup_queue.pop(0)
    _update_queue_label()
    win = _build_popup(alert)
    active_popup["win"] = win

def enqueue_popup(alert):
    popup_queue.append(alert)
    _update_queue_label()
    _show_next_popup()

# ── popup window
def _build_popup(alert):
    atype = alert.get("type", "warning")

    if atype == "safe":
        bg_col    = SAFE_BG
        grid_col  = SAFE_GRID
        border_c  = GREEN
        icon_c    = GREEN
        icon_txt  = "✓"
        btn_color = GREEN
        btn_text_color = "#000000"
    elif atype == "danger":
        bg_col    = DANGER_BG
        grid_col  = DANGER_GRID
        border_c  = RED
        icon_c    = RED
        icon_txt  = "⚠"
        btn_color = RED
        btn_text_color = TEXT
    else:
        bg_col    = WARN_BG
        grid_col  = WARN_GRID
        border_c  = ORANGE
        icon_c    = ORANGE
        icon_txt  = "⚠"
        btn_color = ORANGE
        btn_text_color = "#000000"

    pop = ctk.CTkToplevel(root)
    pop.title("Network Security Alert")
    pop.geometry("460x370")
    pop.configure(fg_color=bg_col)
    pop.resizable(False, False)
    pop.attributes("-topmost", True)
    pop.lift()
    pop.focus_force()

    # position bottom-right
    pop.update_idletasks()
    sw2 = pop.winfo_screenwidth()
    sh2 = pop.winfo_screenheight()
    pop.geometry(f"460x370+{sw2 - 478}+{sh2 - 420}")

    _closed = {"done": False}
    def close_popup():
        if _closed["done"]:
            return
        _closed["done"] = True
        if pop.winfo_exists():
            pop.destroy()
        _popup_closed()

    # if the user clicks the window's native close [x], treat it the same way
    pop.protocol("WM_DELETE_WINDOW", close_popup)

    # coloured top strip
    strip = tk.Frame(pop, bg=border_c, height=5)
    strip.pack(fill="x")

    body = ctk.CTkFrame(pop, fg_color="transparent")
    body.pack(fill="both", expand=True, padx=20, pady=12)

    # icon + title row
    top_row = ctk.CTkFrame(body, fg_color="transparent")
    top_row.pack(fill="x", pady=(0, 10))

    ctk.CTkLabel(top_row, text=icon_txt,
                 font=("Arial", 36), text_color=icon_c).pack(side="left")

    title_col = ctk.CTkFrame(top_row, fg_color="transparent")
    title_col.pack(side="left", padx=12)

    ctk.CTkLabel(title_col, text=alert.get("title", "Security Alert"),
                 font=("Inter", 16, "bold"), text_color=icon_c,
                 anchor="w").pack(anchor="w")
    ctk.CTkLabel(title_col, text=alert.get("timestamp", ""),
                 font=("Inter", 10), text_color=TEXT_SEC,
                 anchor="w").pack(anchor="w")

    # details grid — solid bg only, no alpha
    grid_f = ctk.CTkFrame(body, fg_color=grid_col, corner_radius=8)
    grid_f.pack(fill="x", pady=(0, 10))

    fields = [
        ("Network (SSID)",  alert.get("ssid",       "—")),
        ("MAC Address",     alert.get("bssid",      "—")),
        ("Status",          alert.get("status",     "—")),
        ("Threat Level",    alert.get("threat",     "—")),
        ("Encryption",      alert.get("encryption", "—")),
        ("Signal Strength", f"{alert.get('signal', '—')} dBm"),
    ]
    for label, val in fields:
        row = ctk.CTkFrame(grid_f, fg_color="transparent")
        row.pack(fill="x", padx=12, pady=2)
        ctk.CTkLabel(row, text=f"{label}:", font=("Inter", 11),
                     text_color=TEXT_SEC, width=135, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=str(val), font=("Inter", 11, "bold"),
                     text_color=TEXT, anchor="w").pack(side="left")

    # message
    ctk.CTkLabel(body, text=alert.get("message", ""),
                 font=("Inter", 11), text_color=TEXT_SEC,
                 wraplength=415, justify="left", anchor="w").pack(fill="x", pady=(0, 12))

    # queue indicator, if more are waiting
    if popup_queue:
        n = len(popup_queue)
        ctk.CTkLabel(body, text=f"+{n} more alert{'s' if n != 1 else ''} waiting",
                     font=("Inter", 10), text_color=TEXT_MUT).pack(anchor="w", pady=(0, 6))

    # dismiss button
    ctk.CTkButton(body, text="Dismiss",
                  font=("Inter", 12, "bold"),
                  fg_color=btn_color,
                  hover_color=btn_color,
                  text_color=btn_text_color,
                  height=34, corner_radius=6,
                  command=close_popup).pack(fill="x")

    # safe alerts auto-close after 8 s;warning stay until dismissed
    if atype == "safe":
        pop.after(8000, close_popup)

    return pop

# ── history entry 
def add_history(alert):
    atype = alert.get("type", "warning")
    dot   = GREEN if atype == "safe" else (RED if atype == "danger" else ORANGE)

    row = ctk.CTkFrame(history_frame, fg_color=BG_ROW, corner_radius=6,
                       border_width=1, border_color=BORDER)
    row.pack(fill="x", padx=4, pady=3)

    left = ctk.CTkFrame(row, fg_color="transparent")
    left.pack(side="left", padx=10, pady=6, fill="x", expand=True)

    top = ctk.CTkFrame(left, fg_color="transparent")
    top.pack(fill="x")
    ctk.CTkLabel(top, text="●", text_color=dot,
                 font=("Arial", 12)).pack(side="left")
    ctk.CTkLabel(top, text=f"  {alert.get('title', 'Alert')}",
                 font=("Inter", 11, "bold"), text_color=TEXT).pack(side="left")

    ctk.CTkLabel(left,
                 text=(f"SSID: {alert.get('ssid','—')}   "
                       f"Status: {alert.get('status','—')}   "
                       f"Threat: {alert.get('threat','—')}"),
                 font=("Inter", 10), text_color=TEXT_SEC,
                 anchor="w").pack(fill="x", pady=(1, 0))

    ctk.CTkLabel(row, text=alert.get("timestamp", ""),
                 font=("Inter", 10), text_color=TEXT_MUT).pack(side="right", padx=10)

# ── build alert 
def make_alert(ssid, bssid, status, threat, encryption, signal="—"):
    ts = datetime.now().strftime("%H:%M:%S")
    s  = (status or "").upper()

    if s == "SAFE":
        atype   = "safe"
        title   = "✓  Safe Network"
        message = (f"This network is verified and authorised by your administrator.\n"
                   f"Encryption: {encryption}  —  You may connect safely.")
    elif s in ("SUSPICIOUS", "ROGUE", "BLOCKED"):
        atype   = "danger"
        title   = "⚠  Rogue Access Point Detected"
        message = ("DO NOT CONNECT to this network.\n"
                   "This access point is not authorised and may intercept your data.")
    else:
        atype   = "warning"
        title   = "⚠  Unverified Network"
        message = ("This network has not been verified by your administrator.\n"
                   "Proceed with caution or avoid connecting until it is reviewed.")

    return {
        "type": atype, "title": title,
        "ssid": ssid,  "bssid": bssid,
        "status": s,   "threat": (threat or "—").upper(),
        "encryption": encryption, "signal": signal,
        "message": message, "timestamp": ts,
    }

def report_to_admin(ssid, bssid, status, threat, encryption, signal="—"):
    """Tell the admin dashboard this device just connected to an AP.
    Fire-and-forget on a background thread — never blocks the UI, and a
    down/unreachable server just fails silently here (the local popup
    already happened via deliver())."""
    def _post():
        try:
            requests.post(f"{ALERT_SERVER}/client_connected", json={
                "client_name": CLIENT_NAME,
                "ssid": ssid, "bssid": bssid, "status": status,
                "threat_level": threat, "encryption": encryption,
                "signal": signal,
            }, timeout=2)
        except Exception:
            pass
    threading.Thread(target=_post, daemon=True).start()

# ── dedup / cooldown (new) 
_last_shown = {}   # (ssid, bssid, status) 

def _cooldown_key(alert):
    return (alert.get("ssid", ""), alert.get("bssid", ""), alert.get("status", ""))

def _on_cooldown(alert):
    key = _cooldown_key(alert)
    last = _last_shown.get(key)
    return last is not None and (time.time() - last) < ALERT_COOLDOWN_S

def _mark_shown(alert):
    _last_shown[_cooldown_key(alert)] = time.time()

def deliver(alert):
    """History always gets the event. Popup only if not on cooldown
    (and not a suppressed SAFE alert), and always goes through the queue
    so at most one popup is ever visible at once."""
    def _do():
        alert_count[0] += 1
        n = alert_count[0]
        badge_lbl.configure(text=f"{n} alert{'s' if n != 1 else ''}")
        status_lbl.configure(
            text=f"Last: {alert.get('title','?')} — {alert.get('ssid','?')} "
                 f"at {alert.get('timestamp','')}")
        add_history(alert)

        if alert.get("type") == "safe" and SUPPRESS_SAFE_POPUPS:
            return
        if _on_cooldown(alert):
            return

        _mark_shown(alert)
        enqueue_popup(alert)

    root.after(0, _do)

# ── thread 1: poll alert server for admin-pushed alerts
def poll_server():
    while True:
        try:
            resp   = requests.get(f"{ALERT_SERVER}/get_alerts", timeout=2)
            alerts = resp.json()
            root.after(0, lambda: conn_dot.configure(
                text="● Server connected", text_color=GREEN))
            for a in alerts:
                deliver(a)
        except requests.exceptions.ConnectionError:
            root.after(0, lambda: conn_dot.configure(
                text="● Server offline", text_color=RED))
        except Exception as e:
            root.after(0, lambda: conn_dot.configure(
                text="● Error", text_color=ORANGE))
            print(f"Poll error: {e}")
        time.sleep(POLL_MS / 1000)

# ── thread 2: watch which network this device is connected to ─
def monitor_connection():
    last_bssid = [None]

    while True:
        try:
            if not WIFI_OK:
                time.sleep(WIFI_CHECK_S)
                continue

            wifi  = pywifi.PyWiFi()
            iface = wifi.interfaces()[0]

            connected_ssid  = None
            connected_bssid = None

            # pywifi status 4 == connected
            if iface.status() == wconst.IFACE_CONNECTED:
                # Scan to get current AP details
                iface.scan()
                time.sleep(1)
                results = iface.scan_results()

                # The strongest matching signal is the one we're on
                if results:
                    best = sorted(results, key=lambda r: r.signal, reverse=True)[0]
                    connected_ssid  = best.ssid.strip()
                    connected_bssid = best.bssid.lower().strip().rstrip(":")

            if connected_bssid and connected_bssid != last_bssid[0]:
                last_bssid[0] = connected_bssid

                # Update network bar
                root.after(0, lambda s=connected_ssid, b=connected_bssid: [
                    net_lbl.configure(text=f"{s}  ({b})", text_color=TEXT),
                    net_status_dot.configure(text="●", text_color=GREEN),
                ])

                # Look up status in DB
                row = db_lookup(connected_bssid)
                if row:
                    status, threat, enc = row
                    alert = make_alert(connected_ssid, connected_bssid,
                                       status, threat, enc or "—")
                else:
                    # Not in DB — unknown network
                    status, threat, enc = "WARNING", "MEDIUM", "Unknown"
                    alert = make_alert(connected_ssid, connected_bssid,
                                       status, threat, enc)
                    alert["message"] = (
                        "You connected to a network not yet in the admin database.\n"
                        "Status will be assigned on the next admin scan."
                    )

                deliver(alert)
                report_to_admin(connected_ssid, connected_bssid, status, threat, enc)

            elif not connected_bssid:
                if last_bssid[0] is not None:
                    last_bssid[0] = None
                    root.after(0, lambda: [
                        net_lbl.configure(
                            text="Not connected to any Wi-Fi network",
                            text_color=TEXT_SEC),
                        net_status_dot.configure(text="●", text_color=TEXT_SEC),
                    ])

        except Exception as e:
            print(f"Connection monitor error: {e}")

        time.sleep(WIFI_CHECK_S)

# ── start 
threading.Thread(target=poll_server,        daemon=True).start()

if WIFI_OK:
    threading.Thread(target=monitor_connection, daemon=True).start()
    net_lbl.configure(text="Starting network monitor...", text_color=TEXT_SEC)
else:
    net_lbl.configure(
        text="Wi-Fi monitor unavailable — run:  pip install comtypes pywin32",
        text_color=ORANGE)
    net_status_dot.configure(text="●", text_color=ORANGE)

root.mainloop()
