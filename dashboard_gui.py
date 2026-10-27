
import customtkinter as ctk
from tkinter import ttk, messagebox, filedialog
import psycopg2
import pywifi
import time
import requests
import threading
import queue
import os
import csv
from datetime import datetime, timedelta
import tkinter as tk
from collections import defaultdict, deque

# Scapy - used for 802.11 frame-level monitoring that PyWiFi cannot do:

try:
    from scapy.all import sniff, Dot11, Dot11Beacon, Dot11Deauth, Dot11Elt, IP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ── palette 
BG_DEEP    = "#0d1117"
BG_CARD    = "#161b22"
BG_SIDEBAR = "#0d1117"
BG_ROW_ALT = "#1c2128"
BORDER     = "#30363d"
TEXT_PRI   = "#e6edf3"
TEXT_SEC   = "#8b949e"
TEXT_MUTED = "#6e7681"
RED        = "#da3633"
ORANGE     = "#e3b341"
GREEN      = "#3fb950"
BLUE       = "#58a6ff"
PURPLE     = "#bc8cff"

# ── logged-in user (injected by login.py via env vars) 
LOGGED_USER     = os.environ.get("LOGGED_IN_USER",     "admin")
LOGGED_FULLNAME = os.environ.get("LOGGED_IN_FULLNAME", "Administrator")
LOGGED_ROLE     = os.environ.get("LOGGED_IN_ROLE",     "admin")


# NETWORK CLASSIFICATION LISTS
# TRUSTED_APS   — your authorised AP(s). SSID -> exact MAC.
#                 These are SAFE. Any same-SSID / different-MAC is an evil twin.
TRUSTED_APS = {
    "Safaricom_B320_8F84": "f8:54:f6:ae:42:e6",
}

IGNORED_SSIDS = set([
    # paste neighbour / school SSIDs here, one per line, e.g.:
    # "Neighbour_WiFi",
    # "SchoolNetwork",
])

IGNORED_BSSIDS = set([
    # "aa:bb:cc:dd:ee:ff",
])

# Admin-locked BSSIDs — scans never overwrite these
ADMIN_LOCKED = set()

# ── database ─
try:
    conn = psycopg2.connect(
        host     = os.environ.get("DB_HOST",     "localhost"),
        database = os.environ.get("DB_NAME",     "RogueAPDetection"),
        user     = os.environ.get("DB_USER",     "postgres"),
        password = os.environ.get("DB_PASSWORD", "admin123"),
    )
    conn.autocommit = False
    cursor = conn.cursor()
    DB_CONNECTED = True
except Exception as e:
    print(f"DB: {e}")
    DB_CONNECTED = False
    conn = None
    cursor = None

def db_exec(sql, params=()):
    if not cursor:
        return None
    try:
        cursor.execute(sql, params)
        conn.commit()
        try:    return cursor.fetchall()
        except: return []
    except Exception as e:
        try:    conn.rollback()
        except: pass
        print(f"DB error: {e}")
        return None

def ensure_ignored_column():
    db_exec("""
        ALTER TABLE access_points
        ADD COLUMN IF NOT EXISTS ignored_reason VARCHAR(100) DEFAULT NULL
    """)
    db_exec("""
        ALTER TABLE access_points
        ADD COLUMN IF NOT EXISTS channel INTEGER DEFAULT NULL
    """)

def ensure_traffic_table():
    """Rolling traffic-volume samples used for anomaly detection - separate
    from access_points since this tracks the connected network as a whole,
    not any single AP."""
    db_exec("""
        CREATE TABLE IF NOT EXISTS traffic_samples (
            id               SERIAL PRIMARY KEY,
            sample_time      TIMESTAMP DEFAULT NOW(),
            packet_count     INTEGER,
            connection_count INTEGER,
            byte_count       BIGINT,
            is_anomaly       BOOLEAN DEFAULT FALSE
        )
    """)

def load_locked():
    rows = db_exec("""
        SELECT bssid FROM access_points
        WHERE admin_decision IN ('APPROVED','BLOCKED','QUARANTINED')
    """) or []
    for (b,) in rows:
        ADMIN_LOCKED.add(b.lower().strip())

def load_ignored_from_db():
    rows = db_exec("""
        SELECT DISTINCT ssid FROM access_points
        WHERE ignored_reason IS NOT NULL
    """) or []
    for (s,) in rows:
        if s:
            IGNORED_SSIDS.add(s)

# ── classification 
def classify(ssid, bssid, encryption):
    """
    Returns (status, threat_level, ignored_reason).
    ignored_reason is None for real threats/available networks, a string for
    ignored networks.

    Categories:
      IGNORED     - explicitly out of scope (neighbour/school/etc.)
      SAFE        - exact match to a trusted AP (SSID + BSSID)
      SUSPICIOUS  - real rogue signal: same SSID as a trusted AP but a
                    different BSSID (evil twin / MAC spoofing)
      WARNING     - open/unencrypted network with no trusted relationship
      AVAILABLE   - any other encrypted network nearby with no relationship
                    to a trusted AP. This is NOT evidence of an attack -
                    it's just another network in range, unreviewed. Only
                    escalates to SUSPICIOUS/WARNING if it actually shows a
                    rogue signal above.
    """
    bssid_clean = bssid.strip().lower().rstrip(":")
    ssid_clean  = ssid.strip()

    # 1. Explicitly ignored - not our network, not a threat
    if ssid_clean in IGNORED_SSIDS:
        return "IGNORED", "NONE", "Not in monitoring zone"
    if bssid_clean in IGNORED_BSSIDS:
        return "IGNORED", "NONE", "Manually ignored device"

    # 2. Exact trusted match - SAFE
    trusted_bssid = TRUSTED_APS.get(ssid_clean, "").lower()
    if trusted_bssid and trusted_bssid == bssid_clean:
        return "SAFE", "LOW", None

    # 3. Known SSID but wrong MAC - evil twin / rogue. Real threat.
    if ssid_clean in TRUSTED_APS:
        return "SUSPICIOUS", "HIGH", None

    # 4. Open network with no trusted relationship - real threat
    if encryption == "OPEN":
        return "WARNING", "MEDIUM", None

    # 5. Any other encrypted network - just another AP in range that isn't
    #    ours and shows no rogue signal. Surface it as AVAILABLE for admin
    #    review rather than lumping it in with genuine SUSPICIOUS threats.
    return "AVAILABLE", "LOW", None


# SCAPY - 802.11 FRAME-LEVEL MONITORING
#      that exist, not attacks happening in real time.
#

MONITOR_IFACE     = os.environ.get("MONITOR_IFACE", "wlan0mon")
DEAUTH_WINDOW_S   = 10   # look at deauth frames within this rolling window
DEAUTH_THRESHOLD  = 10   # ...and flag a flood if more than this many land on one BSSID


DEAUTH_PCAP_REPLAY = os.environ.get("DEAUTH_PCAP_REPLAY", None)

_deauth_hits = defaultdict(lambda: deque())   # bssid -> deque[timestamp]
_scapy_status = {"active": False, "note": "Not started"}

def _get_ssid_from_beacon(pkt):
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 0:  # SSID element
                ssid = elt.info.decode(errors="ignore").strip()
                return ssid
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return ""

def _get_channel_from_beacon(pkt):
    try:
        elt = pkt.getlayer(Dot11Elt)
        while elt:
            if elt.ID == 3 and len(elt.info) >= 1:  # DS Parameter Set = channel
                return elt.info[0]
            elt = elt.payload.getlayer(Dot11Elt)
    except Exception:
        pass
    return None

def _handle_beacon(pkt):
    bssid = pkt.addr2
    if not bssid:
        return
    bssid = bssid.lower().strip()
    channel = _get_channel_from_beacon(pkt)
    if channel is None:
        return
    
    db_exec("UPDATE access_points SET channel=%s WHERE LOWER(TRIM(bssid))=%s",
            (int(channel), bssid))

def _handle_deauth(pkt):
    # addr1 = destination (client being kicked), addr2 = source (usually the AP
    # or an attacker spoofing it) - the BSSID under attack is addr2/addr3.
    bssid = (pkt.addr2 or pkt.addr3 or "").lower().strip()
    if not bssid:
        return
    now = time.time()
    hits = _deauth_hits[bssid]
    hits.append(now)
    while hits and now - hits[0] > DEAUTH_WINDOW_S:
        hits.popleft()

    if len(hits) >= DEAUTH_THRESHOLD:
        hits.clear()  # reset so we don't re-fire every single packet
        if bssid in ADMIN_LOCKED:
            ui_call(lambda b=bssid: add_activity(
                f"Deauth flood on locked AP {b} - admin decision kept", PURPLE))
            return

        rows = db_exec("SELECT ssid FROM access_points WHERE LOWER(TRIM(bssid))=%s", (bssid,)) or []
        ssid = rows[0][0] if rows else bssid

        db_exec("""
            UPDATE access_points
            SET status='SUSPICIOUS', threat_level='HIGH', admin_decision='PENDING'
            WHERE LOWER(TRIM(bssid))=%s
        """, (bssid,))
        db_exec("INSERT INTO alerts (alert_type, alert_message) VALUES (%s,%s)",
                ("SUSPICIOUS", f"Deauthentication flood detected targeting {ssid} ({bssid}) - possible active attack"))

        def _notify(s=ssid, b=bssid):
            add_activity(f"DEAUTH FLOOD: {s} ({b}) - possible active attack", RED)
            load_data()
        ui_call(_notify)
        push_alert(ssid, bssid, "SUSPICIOUS", "HIGH", "-", "-")

def _process_packet(pkt):
    try:
        if pkt.haslayer(Dot11Deauth):
            _handle_deauth(pkt)
        elif pkt.haslayer(Dot11Beacon):
            _handle_beacon(pkt)
    except Exception:
        pass

def start_scapy_sniffer():
    """Runs on a background thread. Never blocks the UI, never crashes the
    app if monitor mode isn't set up - just logs why and stays inactive.

    If DEAUTH_PCAP_REPLAY is set, replays a saved capture file through the
    same detection code instead of live-capturing - useful for demonstrating
    deauth-flood detection on hardware that doesn't support monitor mode."""
    if not SCAPY_OK:
        _scapy_status["note"] = "scapy not installed"
        ui_call(lambda: add_activity("Scapy not installed - deauth/channel detection disabled", TEXT_MUTED))
        return

    if DEAUTH_PCAP_REPLAY:
        try:
            _scapy_status["active"] = True
            _scapy_status["note"] = f"Replaying {os.path.basename(DEAUTH_PCAP_REPLAY)} (demo mode)"
            ui_call(lambda: add_activity(
                f"DEMO MODE: replaying {os.path.basename(DEAUTH_PCAP_REPLAY)} through live detection code", PURPLE))
            sniff(offline=DEAUTH_PCAP_REPLAY, prn=_process_packet, store=False)
            ui_call(lambda: add_activity("Pcap replay finished", TEXT_MUTED))
        except Exception as e:
            _scapy_status["active"] = False
            _scapy_status["note"] = f"Replay failed: {str(e)[:60]}"
            ui_call(lambda: add_activity(f"Pcap replay failed ({str(e)[:50]})", RED))
        return

    try:
        _scapy_status["active"] = True
        _scapy_status["note"] = f"Sniffing on {MONITOR_IFACE}"
        ui_call(lambda: add_activity(f"Scapy monitor-mode sniffer started on {MONITOR_IFACE}", BLUE))
        sniff(iface=MONITOR_IFACE, prn=_process_packet, store=False)
    except Exception as e:
        _scapy_status["active"] = False
        _scapy_status["note"] = f"Unavailable: {str(e)[:60]}"
        ui_call(lambda: add_activity(
            f"Scapy sniffer unavailable ({str(e)[:50]}) - PyWiFi scanning still active", ORANGE))

# SCAPY - TRAFFIC VOLUME / CONNECTION-COUNT MONITORING
TRAFFIC_IFACE               = os.environ.get("TRAFFIC_IFACE", None)  # None = scapy default
TRAFFIC_SAMPLE_INTERVAL_S   = 5     # length of each measurement window
TRAFFIC_BASELINE_WINDOW     = 24    # how many past windows form the baseline (2 min at 5s)
TRAFFIC_MIN_BASELINE_SAMPLES= 5     # need at least this many samples before judging anomalies
TRAFFIC_STDDEV_MULTIPLIER   = 2.5   # how many std-devs above baseline counts as a spike
TRAFFIC_MIN_PACKETS_FLOOR   = 50    # ignore anomaly logic below this - avoids false alarms on a quiet network

_traffic_lock     = threading.Lock()
_traffic_counters = {"packets": 0, "connections": set(), "bytes": 0}
_traffic_history  = deque(maxlen=TRAFFIC_BASELINE_WINDOW)
_traffic_status   = {"active": False, "note": "Not started"}
_traffic_chart_data = deque(maxlen=60)   # recent (packets, is_anomaly) pairs, for the UI chart

def _traffic_packet_handler(pkt):
    """Called for every sniffed packet. Kept minimal - just tallies counts,
    the actual analysis happens once per window in traffic_sample_loop()."""
    try:
        with _traffic_lock:
            _traffic_counters["packets"] += 1
            _traffic_counters["bytes"] += len(pkt)
            if pkt.haslayer(IP):
                ip = pkt[IP]
                sport = getattr(pkt, "sport", 0) or 0
                dport = getattr(pkt, "dport", 0) or 0
                key = (ip.src, ip.dst, sport, dport)
                _traffic_counters["connections"].add(key)
    except Exception:
        pass

def traffic_sample_loop():
    """Runs forever on its own thread: every TRAFFIC_SAMPLE_INTERVAL_S
    seconds, snapshot+reset the counters, compare against the rolling
    baseline, and record/alert if this window is anomalous."""
    import statistics
    while True:
        time.sleep(TRAFFIC_SAMPLE_INTERVAL_S)
        with _traffic_lock:
            packets     = _traffic_counters["packets"]
            connections = len(_traffic_counters["connections"])
            byte_count  = _traffic_counters["bytes"]
            _traffic_counters["packets"]     = 0
            _traffic_counters["connections"] = set()
            _traffic_counters["bytes"]       = 0

        is_anomaly = False
        note = ""
        if len(_traffic_history) >= TRAFFIC_MIN_BASELINE_SAMPLES:
            pkt_values = [h["packets"] for h in _traffic_history]
            mean  = statistics.mean(pkt_values)
            stdev = statistics.pstdev(pkt_values) if len(pkt_values) > 1 else 0
            threshold = mean + TRAFFIC_STDDEV_MULTIPLIER * stdev
            if packets >= TRAFFIC_MIN_PACKETS_FLOOR and packets > threshold:
                is_anomaly = True
                note = f"baseline ~{mean:.0f} pkts/{TRAFFIC_SAMPLE_INTERVAL_S}s, this window {packets}"

        _traffic_history.append({"packets": packets, "connections": connections})
        _traffic_chart_data.append((packets, is_anomaly))

        db_exec("""
            INSERT INTO traffic_samples (packet_count, connection_count, byte_count, is_anomaly)
            VALUES (%s,%s,%s,%s)
        """, (packets, connections, byte_count, is_anomaly))

        ui_call(lambda p=packets, c=connections, a=is_anomaly: _update_traffic_ui(p, c, a))

        if is_anomaly:
            db_exec("INSERT INTO alerts (alert_type, alert_message) VALUES (%s,%s)",
                    ("WARNING", f"Unusual traffic volume detected: {packets} packets, "
                                f"{connections} connections in {TRAFFIC_SAMPLE_INTERVAL_S}s ({note})"))
            ui_call(lambda p=packets, c=connections: add_activity(
                f"Traffic spike: {p} pkts / {c} connections in {TRAFFIC_SAMPLE_INTERVAL_S}s", ORANGE))

def start_traffic_monitor():
    """Runs on a background thread. Needs Npcap (Windows) or root (Linux) to
    open a capture handle - falls back cleanly if that's not available, same
    pattern as the 802.11 module above."""
    if not SCAPY_OK:
        _traffic_status["note"] = "scapy not installed"
        return
    try:
        _traffic_status["active"] = True
        _traffic_status["note"] = "Monitoring active connection"
        ui_call(lambda: add_activity("Traffic volume monitor started", BLUE))
        threading.Thread(target=traffic_sample_loop, daemon=True).start()
        sniff(iface=TRAFFIC_IFACE, prn=_traffic_packet_handler, store=False)
    except Exception as e:
        _traffic_status["active"] = False
        _traffic_status["note"] = f"Unavailable: {str(e)[:60]}"
        ui_call(lambda: add_activity(
            f"Traffic monitor unavailable ({str(e)[:50]}) - needs Npcap + Administrator on Windows", ORANGE))

# ── root window ───────────────────────────────────────────────────────────────
root = ctk.CTk()
root.title("RogueAP Detection System v2.0")
root.geometry("1600x940")
root.configure(fg_color=BG_DEEP)
root.minsize(1280, 800)


_ui_queue = queue.Queue()

def ui_call(fn):
    """Background threads call this instead of ui_call(fn)."""
    _ui_queue.put(fn)

def _drain_ui_queue():
    while True:
        try:
            fn = _ui_queue.get_nowait()
        except queue.Empty:
            break
        try:
            fn()
        except Exception as e:
            print(f"UI queue callback error: {e}")
    root.after(50, _drain_ui_queue)

# ── helpers
def make_label(parent, text, size=12, weight="normal",
               color=TEXT_PRI, anchor="w", **kwargs):
    return ctk.CTkLabel(parent, text=text, font=("Inter", size, weight),
                        text_color=color, anchor=anchor, **kwargs)

def make_card(parent, **kwargs):
    return ctk.CTkFrame(parent, fg_color=BG_CARD, corner_radius=8,
                        border_width=1, border_color=BORDER, **kwargs)

def push_alert(ssid, bssid, status, threat_level, encryption, signal="-"):
    s = (status or "").upper()
    if s == "SAFE":
        atype, title = "safe",   "Safe Network"
        message = f"This network is verified and authorised.\nEncryption: {encryption}"
        color, border = "#14532d", "#22c55e"
    elif s in ("SUSPICIOUS","ROGUE","BLOCKED"):
        atype, title = "danger", "Rogue Access Point"
        message = "DO NOT CONNECT - this network is not authorised.\nYour data may be intercepted."
        color, border = "#7f1d1d", "#ef4444"
    else:
        atype, title = "warning","Suspicious Network"
        message = "This network has not been verified.\nProceed with caution."
        color, border = "#78350f", "#f59e0b"

    def _post():
        try:
            requests.post("http://127.0.0.1:5000/send_alert", json={
                "ssid": ssid, "bssid": bssid, "status": status,
                "threat_level": threat_level, "encryption": encryption,
                "signal": signal, "type": atype, "title": title,
                "message": message, "color": color, "border": border,
            }, timeout=2)
        except: pass
    threading.Thread(target=_post, daemon=True).start()

# CLIENT-CONNECTION POPUPS
#
# When any client device (user_client.py) connects to an AP, it reports the
# event to alert_server.py's /client_connected endpoint. This dashboard polls
# /client_events and shows a popup here same one-popup-at-a-time queue
# pattern used on the client side, so a burst of client connections doesn't
# flood the admin's screen either.

ALERT_SERVER = "http://127.0.0.1:5000"

client_popup_queue  = []
active_client_popup = {"win": None}

def _client_queue_label_text():
    n = len(client_popup_queue)
    return f"+{n} more client alert{'s' if n != 1 else ''} waiting" if n else ""

def _client_popup_closed():
    active_client_popup["win"] = None
    root.after(200, _show_next_client_popup)

def _show_next_client_popup():
    if active_client_popup["win"] is not None:
        return
    if not client_popup_queue:
        return
    event = client_popup_queue.pop(0)
    win = _build_client_popup(event)
    active_client_popup["win"] = win

def enqueue_client_popup(event):
    client_popup_queue.append(event)
    _show_next_client_popup()

def _build_client_popup(event):
    atype = event.get("type", "warning")
    if atype == "safe":
        bg_col, border_c, icon_txt = "#052e16", GREEN, "OK"
    elif atype == "danger":
        bg_col, border_c, icon_txt = "#2d0a0a", RED, "!"
    else:
        bg_col, border_c, icon_txt = "#2d1d00", ORANGE, "!"

    pop = ctk.CTkToplevel(root)
    pop.title("Client Connection Alert")
    pop.geometry("440x340")
    pop.configure(fg_color=bg_col)
    pop.resizable(False, False)
    pop.attributes("-topmost", True)
    pop.lift(); pop.focus_force()

    pop.update_idletasks()
    sw = pop.winfo_screenwidth(); sh = pop.winfo_screenheight()
    pop.geometry(f"440x340+{sw - 460}+{sh - 400}")

    _closed = {"done": False}
    def close_popup():
        if _closed["done"]: return
        _closed["done"] = True
        if pop.winfo_exists(): pop.destroy()
        _client_popup_closed()
    pop.protocol("WM_DELETE_WINDOW", close_popup)

    strip = tk.Frame(pop, bg=border_c, height=5); strip.pack(fill="x")
    body = ctk.CTkFrame(pop, fg_color="transparent")
    body.pack(fill="both", expand=True, padx=20, pady=14)

    top_row = ctk.CTkFrame(body, fg_color="transparent"); top_row.pack(fill="x", pady=(0,8))
    ctk.CTkLabel(top_row, text=icon_txt, font=("Arial", 20, "bold"),
                 text_color=border_c, width=36).pack(side="left")
    title_col = ctk.CTkFrame(top_row, fg_color="transparent"); title_col.pack(side="left", padx=8)
    ctk.CTkLabel(title_col, text=event.get("title","Client Alert"), font=("Inter",15,"bold"),
                 text_color=border_c, anchor="w").pack(anchor="w")
    ctk.CTkLabel(title_col, text=event.get("timestamp",""), font=("Inter",10),
                 text_color=TEXT_SEC, anchor="w").pack(anchor="w")

    grid_f = ctk.CTkFrame(body, fg_color=BG_ROW_ALT, corner_radius=8)
    grid_f.pack(fill="x", pady=(0,10))
    fields = [
        ("Client Device", event.get("client_name","-")),
        ("Network (SSID)", event.get("ssid","-")),
        ("MAC Address",    event.get("bssid","-")),
        ("Status",         event.get("status","-")),
        ("Threat Level",   event.get("threat","-")),
    ]
    for label, val in fields:
        row = ctk.CTkFrame(grid_f, fg_color="transparent"); row.pack(fill="x", padx=12, pady=2)
        ctk.CTkLabel(row, text=f"{label}:", font=("Inter",11), text_color=TEXT_SEC,
                     width=115, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=str(val), font=("Inter",11,"bold"),
                     text_color=TEXT_PRI, anchor="w").pack(side="left")

    ctk.CTkLabel(body, text=event.get("message",""), font=("Inter",11), text_color=TEXT_SEC,
                 wraplength=395, justify="left", anchor="w").pack(fill="x", pady=(0,10))

    if client_popup_queue:
        ctk.CTkLabel(body, text=_client_queue_label_text(), font=("Inter",10),
                     text_color=TEXT_MUTED).pack(anchor="w", pady=(0,6))

    ctk.CTkButton(body, text="Acknowledge", font=("Inter",12,"bold"),
                  fg_color=border_c, hover_color=border_c,
                  text_color="#000000" if atype!="danger" else TEXT_PRI,
                  height=34, corner_radius=6, command=close_popup).pack(fill="x")

    if atype == "safe":
        pop.after(8000, close_popup)

    return pop

def poll_client_events():
    """Background thread: polls alert_server.py for client-connection events
    and enqueues an admin popup + activity-log entry for each one."""
    while True:
        try:
            resp = requests.get(f"{ALERT_SERVER}/client_events", timeout=2)
            events = resp.json()
            for ev in events:
                def _handle(e=ev):
                    color = GREEN if e.get("type")=="safe" else (RED if e.get("type")=="danger" else ORANGE)
                    add_activity(
                        f"{e.get('client_name','Client')} -> {e.get('status','-')} "
                        f"({e.get('ssid','-')})", color)
                    enqueue_client_popup(e)
                ui_call(_handle)
        except Exception:
            pass
        time.sleep(2.5)



def show_all_rogue_aps():
    win = ctk.CTkToplevel(root)
    win.title("All Rogue APs"); win.geometry("900x560")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win, "All Rogue / Suspicious Access Points",
               size=16, weight="bold").pack(padx=20, pady=(16,8))
    cols = ("SSID","BSSID","Status","Threat","Encryption","Admin Decision")
    tree = ttk.Treeview(win, columns=cols, show="headings",
                        style="Dark.Treeview", height=16)
    for col in cols:
        tree.heading(col, text=col); tree.column(col, width=140, anchor="center")
    tree.pack(fill="both", expand=True, padx=16, pady=8)
    tree.tag_configure("high",   background="#2d1b1b", foreground=TEXT_PRI)
    tree.tag_configure("medium", background="#2d2210", foreground=TEXT_PRI)
    rows = db_exec("""
        SELECT ssid,bssid,status,threat_level,encryption_type,admin_decision
        FROM access_points WHERE status NOT IN ('SAFE','IGNORED','AVAILABLE')
        ORDER BY CASE threat_level WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END
    """) or []
    for r in rows:
        tag = "high" if r[3]=="HIGH" else "medium"
        tree.insert("","end", values=r, tags=(tag,))
    ctk.CTkButton(win, text="Close", command=win.destroy,
                  fg_color=BG_CARD, hover_color=BG_ROW_ALT, height=34).pack(pady=8)

def show_all_alerts():
    win = ctk.CTkToplevel(root)
    win.title("All Alerts"); win.geometry("860x520")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win, "Full Alert Log", size=16, weight="bold").pack(padx=20, pady=(16,8))
    cols = ("ID","Type","Message","Time")
    tree = ttk.Treeview(win, columns=cols, show="headings",
                        style="Dark.Treeview", height=16)
    for col, w in zip(cols,[50,110,520,120]):
        tree.heading(col, text=col); tree.column(col, width=w, anchor="center")
    tree.pack(fill="both", expand=True, padx=16, pady=8)
    rows = db_exec("""
        SELECT alert_id,alert_type,alert_message,created_at
        FROM alerts ORDER BY alert_id DESC LIMIT 200
    """) or []
    for r in rows:
        ts = r[3].strftime("%Y-%m-%d %H:%M:%S") if r[3] else "-"
        tree.insert("","end", values=(r[0],r[1],r[2],ts))
    ctk.CTkButton(win, text="Close", command=win.destroy,
                  fg_color=BG_CARD, hover_color=BG_ROW_ALT, height=34).pack(pady=8)

def show_sensors():
    win = ctk.CTkToplevel(root)
    win.title("Sensor Status"); win.geometry("500x360")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win, "Sensor Status", size=16, weight="bold").pack(padx=20, pady=(16,8))
    grid = ctk.CTkFrame(win, fg_color=BG_CARD, corner_radius=8)
    grid.pack(fill="both", expand=True, padx=16, pady=8)
    sensors = ([("o",GREEN,"Online")]*18)+([("o",TEXT_MUTED,"Offline")]*2)
    for i,(dot,color,label) in enumerate(sensors):
        r,c = divmod(i,5)
        f = ctk.CTkFrame(grid, fg_color="transparent")
        f.grid(row=r,column=c,padx=12,pady=10)
        ctk.CTkLabel(f,text=dot,text_color=color,font=("Arial",18)).pack()
        make_label(f,f"S-{i+1:02d}",size=9,color=TEXT_SEC,anchor="center").pack()
    ctk.CTkButton(win,text="Close",command=win.destroy,
                  fg_color=BG_CARD,hover_color=BG_ROW_ALT,height=34).pack(pady=8)

def show_full_report():
    win = ctk.CTkToplevel(root)
    win.title("Full Network Report"); win.geometry("1000x600")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win,"Full Network Report",size=16,weight="bold").pack(padx=20,pady=(16,8))
    cols = ("SSID","BSSID","Signal","Encryption","Status","Threat","Decision","Ignored?")
    tree = ttk.Treeview(win,columns=cols,show="headings",
                        style="Dark.Treeview",height=18)
    for col,w in zip(cols,[160,160,70,100,100,90,110,120]):
        tree.heading(col,text=col); tree.column(col,width=w,anchor="center")
    tree.pack(fill="both",expand=True,padx=16,pady=8)
    tree.tag_configure("safe",    background="#0d2818",foreground=TEXT_PRI)
    tree.tag_configure("warning", background="#2d2210",foreground=TEXT_PRI)
    tree.tag_configure("danger",  background="#2d1b1b",foreground=TEXT_PRI)
    tree.tag_configure("ignored", background="#1a1a2e",foreground=TEXT_MUTED)
    tree.tag_configure("available", background="#0d1b2d",foreground=TEXT_PRI)
    rows = db_exec("""
        SELECT ssid,bssid,signal_strength,encryption_type,
               status,threat_level,admin_decision,ignored_reason
        FROM access_points ORDER BY ssid
    """) or []
    for r in rows:
        s=(r[4] or "").upper()
        if s=="SAFE":           tag="safe"
        elif s=="IGNORED":      tag="ignored"
        elif s=="AVAILABLE":    tag="available"
        elif s=="WARNING":      tag="warning"
        else:                   tag="danger"
        tree.insert("","end",values=r,tags=(tag,))
    ctk.CTkButton(win,text="Close",command=win.destroy,
                  fg_color=BG_CARD,hover_color=BG_ROW_ALT,height=34).pack(pady=8)

def show_wireless_details():
    win = ctk.CTkToplevel(root)
    win.title("Wireless Environment"); win.geometry("540x420")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win,"Wireless Environment Details",size=16,weight="bold").pack(padx=20,pady=(16,8))
    rows = db_exec("""
        SELECT
            COUNT(*) FILTER (WHERE status='SAFE')         AS authorized,
            COUNT(*) FILTER (WHERE status NOT IN ('SAFE','IGNORED','AVAILABLE')) AS rogue,
            COUNT(*) FILTER (WHERE status='AVAILABLE')    AS available,
            COUNT(*) FILTER (WHERE status='IGNORED')      AS ignored,
            COUNT(*)                                       AS total,
            COUNT(*) FILTER (WHERE encryption_type='OPEN') AS open_nets,
            COUNT(*) FILTER (WHERE threat_level='HIGH')   AS high_threat
        FROM access_points
    """) or [[0,0,0,0,0,0,0]]
    r = rows[0]
    card = make_card(win); card.pack(fill="x",padx=20,pady=8)
    for label,val in [
        ("Authorized (Safe) APs", r[0]),
        ("Rogue / Suspicious APs",r[1]),
        ("Available (Unreviewed) APs", r[2]),
        ("Ignored (other zones)", r[3]),
        ("Total Networks Scanned",r[4]),
        ("Open (no encryption) APs",r[5]),
        ("High-Threat APs",       r[6]),
    ]:
        row = ctk.CTkFrame(card,fg_color="transparent")
        row.pack(fill="x",padx=16,pady=6)
        make_label(row,label,size=12,color=TEXT_SEC).pack(side="left")
        make_label(row,str(val),size=13,weight="bold",color=TEXT_PRI).pack(side="right")
    ctk.CTkButton(win,text="Close",command=win.destroy,
                  fg_color=BG_CARD,hover_color=BG_ROW_ALT,height=34).pack(pady=12)

def show_full_logs():    show_all_alerts()
def show_all_access_points(): show_full_report()

def show_notifications():
    win = ctk.CTkToplevel(root)
    win.title("Notifications"); win.geometry("640x420")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win,"Active Notifications",size=16,weight="bold").pack(padx=20,pady=(16,8))
    scroll = ctk.CTkScrollableFrame(win,fg_color=BG_CARD,corner_radius=8)
    scroll.pack(fill="both",expand=True,padx=16,pady=8)
    rows = db_exec("""
        SELECT alert_type,alert_message,created_at
        FROM alerts ORDER BY alert_id DESC LIMIT 50
    """) or []
    for atype,amsg,ats in rows:
        atype=(atype or "").upper()
        dot=GREEN if atype in("SAFE","APPROVED") else \
            (RED if atype in("SUSPICIOUS","BLOCKED","ROGUE") else ORANGE)
        row=ctk.CTkFrame(scroll,fg_color=BG_ROW_ALT,corner_radius=6)
        row.pack(fill="x",pady=3,padx=4)
        inner=ctk.CTkFrame(row,fg_color="transparent")
        inner.pack(fill="x",padx=10,pady=6)
        ctk.CTkLabel(inner,text="o",text_color=dot,font=("Arial",12)).pack(side="left")
        make_label(inner,f"  [{atype}]  {amsg}",size=11,color=TEXT_PRI).pack(side="left")
        ts=ats.strftime("%H:%M:%S") if ats else ""
        make_label(inner,ts,size=10,color=TEXT_MUTED).pack(side="right")
    ctk.CTkButton(win,text="Close",command=win.destroy,
                  fg_color=BG_CARD,hover_color=BG_ROW_ALT,height=34).pack(pady=8)

def show_time_filter():
    win = ctk.CTkToplevel(root)
    win.title("Time Filter"); win.geometry("340x260")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win,"Select Time Range",size=14,weight="bold").pack(padx=20,pady=(16,8))
    options=["Last 1 Hour","Last 6 Hours","Last 24 Hours","Last 7 Days","All Time"]
    var=ctk.StringVar(value="Last 24 Hours")
    for opt in options:
        ctk.CTkRadioButton(win,text=opt,variable=var,value=opt,
                           font=("Inter",12),text_color=TEXT_PRI).pack(anchor="w",padx=30,pady=4)
    ctk.CTkButton(win,text="Apply",
                  command=lambda:[time_btn.configure(text=f"{var.get()}  v"),win.destroy()],
                  fg_color=BLUE,hover_color="#3b82f6",height=36).pack(pady=12)

# ── manage networks ────────────────────────────────────────────────────────────
def show_manage_networks():
    win = ctk.CTkToplevel(root)
    win.title("Manage Networks - Set Ignored / Trusted")
    win.geometry("1000x620")
    win.configure(fg_color=BG_DEEP)
    win.attributes("-topmost", True)

    make_label(win, "Manage Networks", size=16, weight="bold").pack(padx=20, pady=(16,4))
    make_label(win,
               "Select any network that does NOT belong to your monitoring zone "
               "and click 'Mark as Ignored'. It will no longer be flagged as rogue.",
               size=11, color=TEXT_SEC).pack(padx=20, pady=(0,8))

    cols = ("SSID","BSSID","Signal","Encryption","Status","Threat","Ignored Reason")
    tree = ttk.Treeview(win, columns=cols, show="headings",
                        style="Dark.Treeview", height=16)
    for col, w in zip(cols, [180,170,70,110,100,90,200]):
        tree.heading(col, text=col); tree.column(col, width=w, anchor="center")
    tree.pack(fill="both", expand=True, padx=16, pady=4)
    tree.tag_configure("safe",    background="#0d2818", foreground=TEXT_PRI)
    tree.tag_configure("danger",  background="#2d1b1b", foreground=TEXT_PRI)
    tree.tag_configure("warning", background="#2d2210", foreground=TEXT_PRI)
    tree.tag_configure("ignored", background="#1a1a2e", foreground=TEXT_MUTED)
    tree.tag_configure("available", background="#0d1b2d", foreground=TEXT_PRI)

    def refresh_tree():
        for r in tree.get_children(): tree.delete(r)
        rows = db_exec("""
            SELECT ssid,bssid,signal_strength,encryption_type,
                   status,threat_level,ignored_reason
            FROM access_points ORDER BY ssid
        """) or []
        for r in rows:
            s=(r[4] or "").upper()
            if s=="SAFE":         tag="safe"
            elif s=="IGNORED":    tag="ignored"
            elif s=="AVAILABLE":  tag="available"
            elif s=="WARNING":    tag="warning"
            else:                 tag="danger"
            tree.insert("","end", values=(
                r[0],r[1],r[2] or "-",r[3] or "-",
                r[4] or "-",r[5] or "-",r[6] or "-"
            ), tags=(tag,))

    refresh_tree()

    btn_row = ctk.CTkFrame(win, fg_color="transparent")
    btn_row.pack(fill="x", padx=16, pady=8)

    reason_var = ctk.StringVar(value="Neighbour / Other Zone")
    ctk.CTkLabel(btn_row, text="Reason:", font=("Inter",11),
                 text_color=TEXT_SEC).pack(side="left")
    reason_menu = ctk.CTkOptionMenu(btn_row,
                                     values=["Neighbour / Other Zone",
                                             "School / Work Network",
                                             "Public Hotspot (not mine)",
                                             "Known Device (printer/TV)",
                                             "Other - not in scope"],
                                     variable=reason_var,
                                     font=("Inter",11), width=240)
    reason_menu.pack(side="left", padx=8)

    def mark_ignored():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("No Selection","Select a network first."); return
        vals = tree.item(sel[0])["values"]
        ssid, bssid = str(vals[0]), str(vals[1])
        reason = reason_var.get()
        db_exec("""
            UPDATE access_points
            SET status='IGNORED', threat_level='NONE',
                admin_decision='IGNORED', ignored_reason=%s
            WHERE bssid=%s
        """, (reason, bssid))
        db_exec("INSERT INTO alerts (alert_type, alert_message) VALUES (%s,%s)",
                ("IGNORED", f"Admin ignored {ssid} ({bssid}): {reason}"))
        IGNORED_SSIDS.add(ssid.strip())
        ADMIN_LOCKED.add(bssid.lower().strip())
        add_activity(f"Ignored: {ssid} - {reason}", TEXT_MUTED)
        refresh_tree()
        load_data()

    def mark_trusted():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("No Selection","Select a network first."); return
        vals = tree.item(sel[0])["values"]
        ssid, bssid = str(vals[0]), str(vals[1])
        TRUSTED_APS[ssid.strip()] = bssid.lower().strip()
        db_exec("""
            UPDATE access_points
            SET status='SAFE', threat_level='LOW',
                admin_decision='APPROVED', ignored_reason=NULL
            WHERE bssid=%s
        """, (bssid,))
        db_exec("INSERT INTO alerts (alert_type, alert_message) VALUES (%s,%s)",
                ("APPROVED", f"Admin added {ssid} to trusted list"))
        ADMIN_LOCKED.add(bssid.lower().strip())
        add_activity(f"Added to trusted: {ssid}", GREEN)
        refresh_tree()
        load_data()

    def unmark():
        sel = tree.selection()
        if not sel:
            messagebox.showwarning("No Selection","Select a network first."); return
        vals = tree.item(sel[0])["values"]
        ssid, bssid = str(vals[0]), str(vals[1])
        IGNORED_SSIDS.discard(ssid.strip())
        ADMIN_LOCKED.discard(bssid.lower().strip())
        db_exec("""
            UPDATE access_points
            SET status='PENDING', threat_level='HIGH',
                admin_decision='PENDING', ignored_reason=NULL
            WHERE bssid=%s
        """, (bssid,))
        add_activity(f"Reset to PENDING: {ssid}", BLUE)
        refresh_tree()
        load_data()

    for text, cmd, fc, hc in [
        ("Mark as Ignored",   mark_ignored, "#1e3a5f",  "#2563eb"),
        ("Add to Trusted",     mark_trusted, "#166534",  "#15803d"),
        ("Reset / Unmark",     unmark,       "#4a1942",  "#7c3aed"),
    ]:
        ctk.CTkButton(btn_row, text=text, command=cmd,
                      font=("Inter",11,"bold"),
                      fg_color=fc, hover_color=hc,
                      height=34, width=150, corner_radius=6).pack(side="left", padx=4)

    ctk.CTkButton(btn_row, text="Close", command=win.destroy,
                  fg_color=BG_CARD, hover_color=BG_ROW_ALT,
                  height=34, width=80).pack(side="right")

def show_admin_menu():
    win = ctk.CTkToplevel(root)
    win.title("Admin"); win.geometry("300x320")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost", True)
    make_label(win,f"{LOGGED_USER}",size=15,weight="bold").pack(padx=20,pady=(16,2))
    make_label(win,LOGGED_FULLNAME,size=11,color=TEXT_SEC).pack(padx=20)
    role_color=PURPLE if LOGGED_ROLE=="superadmin" else BLUE
    make_label(win,f"Role: {LOGGED_ROLE}",size=10,color=role_color).pack(padx=20,pady=(0,4))
    ctk.CTkFrame(win,height=1,fg_color=BORDER).pack(fill="x",padx=16,pady=10)
    for label,cmd in [
        ("View Full Report",   show_full_report),
        ("View Notifications", show_notifications),
        ("Change Password",    change_password_dialog),
    ]:
        ctk.CTkButton(win,text=label,font=("Inter",12),
                      fg_color=BG_CARD,hover_color=BG_ROW_ALT,
                      text_color=TEXT_PRI,height=36,
                      command=lambda c=cmd,w=win:(w.destroy(),c())
                      ).pack(fill="x",padx=16,pady=3)
    ctk.CTkFrame(win,height=1,fg_color=BORDER).pack(fill="x",padx=16,pady=8)
    ctk.CTkButton(win,text="Logout",font=("Inter",12,"bold"),
                  fg_color="#7f1d1d",hover_color="#dc2626",
                  text_color=TEXT_PRI,height=36,
                  command=lambda:(win.destroy(),logout())
                  ).pack(fill="x",padx=16,pady=(0,4))
    ctk.CTkButton(win,text="Close",command=win.destroy,
                  fg_color="transparent",hover_color=BG_ROW_ALT,
                  text_color=TEXT_SEC,height=28).pack(pady=4)

def change_password_dialog():
    import hashlib as _hl
    win = ctk.CTkToplevel(root)
    win.title("Change Password"); win.geometry("400x410")
    win.configure(fg_color=BG_DEEP); win.attributes("-topmost",True); win.resizable(False,False)
    make_label(win,"Change Password",size=15,weight="bold").pack(padx=24,pady=(20,4))
    make_label(win,f"Account: {LOGGED_USER}",size=11,color=TEXT_SEC).pack(padx=24)
    ctk.CTkFrame(win,height=1,fg_color=BORDER).pack(fill="x",padx=16,pady=12)
    inner=ctk.CTkFrame(win,fg_color="transparent"); inner.pack(fill="x",padx=24)
    err_lbl=ctk.CTkLabel(win,text="",font=("Inter",11),text_color=RED,wraplength=340)
    ok_lbl =ctk.CTkLabel(win,text="",font=("Inter",11),text_color=GREEN,wraplength=340)
    entries={}
    for label,key in [("Current Password","current"),("New Password","new"),("Confirm New Password","confirm")]:
        ctk.CTkLabel(inner,text=label,font=("Inter",11),text_color=TEXT_SEC,anchor="w").pack(fill="x",pady=(8,2))
        e=ctk.CTkEntry(inner,font=("Inter",12),height=38,fg_color="#21262d",
                       border_color=BORDER,text_color=TEXT_PRI,show="*",corner_radius=6)
        e.pack(fill="x"); entries[key]=e
    def _save():
        cur=entries["current"].get(); new_pw=entries["new"].get(); conf=entries["confirm"].get()
        err_lbl.pack_forget(); ok_lbl.pack_forget()
        if not cur or not new_pw or not conf:
            err_lbl.configure(text="All fields required."); err_lbl.pack(pady=4); return
        if new_pw!=conf:
            err_lbl.configure(text="Passwords do not match."); err_lbl.pack(pady=4); return
        if len(new_pw)<8:
            err_lbl.configure(text="Minimum 8 characters."); err_lbl.pack(pady=4); return
        rows=db_exec("SELECT password_hash FROM admin_users WHERE username=%s",(LOGGED_USER,)) or []
        if not rows or rows[0][0]!=_hl.sha256(cur.encode()).hexdigest():
            err_lbl.configure(text="Current password incorrect."); err_lbl.pack(pady=4); return
        db_exec("UPDATE admin_users SET password_hash=%s WHERE username=%s",
                (_hl.sha256(new_pw.encode()).hexdigest(),LOGGED_USER))
        ok_lbl.configure(text="Password changed!"); ok_lbl.pack(pady=4)
        add_activity("Password changed",GREEN); win.after(1500,win.destroy)
    ctk.CTkButton(inner,text="Save New Password",font=("Inter",12,"bold"),
                  fg_color=BLUE,hover_color="#3b82f6",height=38,corner_radius=6,
                  command=_save).pack(fill="x",pady=(16,0))

def logout():
    if not messagebox.askyesno("Logout",f"Log out, {LOGGED_USER}?"): return
    db_exec("INSERT INTO alerts (alert_type, alert_message) VALUES (%s,%s)",
            ("LOGOUT",f"{LOGGED_USER} logged out at {datetime.now().strftime('%H:%M:%S')}"))
    root.destroy()
    import subprocess,sys
    subprocess.Popen([sys.executable,
                      os.path.join(os.path.dirname(os.path.abspath(__file__)),"login.py")],
                     env=os.environ.copy())

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
sidebar=ctk.CTkFrame(root,width=230,fg_color=BG_SIDEBAR,corner_radius=0)
sidebar.pack(side="left",fill="y"); sidebar.pack_propagate(False)

logo_f=ctk.CTkFrame(sidebar,fg_color="transparent"); logo_f.pack(fill="x",padx=20,pady=(24,8))
ctk.CTkLabel(logo_f,text="[R]",font=("Arial",22,"bold"),text_color=BLUE).pack(side="left")
lt=ctk.CTkFrame(logo_f,fg_color="transparent"); lt.pack(side="left",padx=8)
make_label(lt,"RogueAP",size=15,weight="bold").pack(anchor="w")
make_label(lt,"Detection System",size=10,color=TEXT_SEC).pack(anchor="w")

ctk.CTkFrame(sidebar,height=1,fg_color=BORDER).pack(fill="x",padx=12,pady=12)

nav_items=[
    ("Dashboard",        True,  None),
    ("Alerts",           False, show_all_alerts),
    ("Rogue APs",        False, show_all_rogue_aps),
    ("Clients",          False, show_all_access_points),
    ("Sensors",          False, show_sensors),
    ("Reports",          False, show_full_report),
    ("Wireless Environ.",False, show_wireless_details),
    ("Manage Networks",  False, show_manage_networks),
    ("Settings",         False, None),
    ("System",           False, show_full_logs),
    ("Integrations",     False, None),
]

def nav_click(label,btns):
    for b,lbl in btns:
        b.configure(fg_color="#1f2937" if lbl==label else "transparent",
                    text_color=TEXT_PRI if lbl==label else TEXT_SEC)

nav_btns=[]
for label,active,cmd in nav_items:
    b=ctk.CTkButton(sidebar,text=f"  {label}",anchor="w",font=("Inter",13),
                    fg_color="#1f2937" if active else "transparent",
                    text_color=TEXT_PRI if active else TEXT_SEC,
                    hover_color="#1f2937",height=40,corner_radius=6)
    b.pack(fill="x",padx=10,pady=2); nav_btns.append((b,label))

for (b,lbl),(_,__,cmd) in zip(nav_btns,nav_items):
    def _nav(l=lbl,c=cmd): nav_click(l,nav_btns); c() if c else None
    b.configure(command=_nav)

ctk.CTkFrame(sidebar,fg_color="transparent").pack(fill="both",expand=True)
sb_bottom=ctk.CTkFrame(sidebar,fg_color=BG_CARD,corner_radius=8)
sb_bottom.pack(fill="x",padx=12,pady=10)
sr=ctk.CTkFrame(sb_bottom,fg_color="transparent"); sr.pack(fill="x",padx=12,pady=8)
ctk.CTkLabel(sr,text="o",text_color=GREEN,font=("Arial",14)).pack(side="left")
sc=ctk.CTkFrame(sr,fg_color="transparent"); sc.pack(side="left",padx=6)
make_label(sc,"System Status",size=12,weight="bold").pack(anchor="w")
make_label(sc,"All systems operational",size=10,color=TEXT_SEC).pack(anchor="w")
ctk.CTkFrame(sidebar,height=1,fg_color=BORDER).pack(fill="x",padx=12)
ar=ctk.CTkFrame(sidebar,fg_color="transparent"); ar.pack(fill="x",padx=12,pady=12)
ac=ctk.CTkFrame(ar,fg_color="transparent"); ac.pack(side="left",padx=8)
make_label(ac,LOGGED_USER,size=12,weight="bold").pack(anchor="w")
make_label(ac,LOGGED_FULLNAME,size=10,color=TEXT_SEC).pack(anchor="w")

# ─────────────────────────────────────────────────────────────────────────────
# MAIN AREA
# ─────────────────────────────────────────────────────────────────────────────
main=ctk.CTkFrame(root,fg_color=BG_DEEP,corner_radius=0)
main.pack(side="right",fill="both",expand=True)

topbar=ctk.CTkFrame(main,fg_color=BG_CARD,height=56,corner_radius=0,
                    border_width=1,border_color=BORDER)
topbar.pack(fill="x"); topbar.pack_propagate(False)
tb_left=ctk.CTkFrame(topbar,fg_color="transparent"); tb_left.pack(side="left",padx=24,pady=8)
make_label(tb_left,"Dashboard",size=18,weight="bold").pack(anchor="w")
make_label(tb_left,"Overview of wireless security",size=11,color=TEXT_SEC).pack(anchor="w")
tb_right=ctk.CTkFrame(topbar,fg_color="transparent"); tb_right.pack(side="right",padx=20)

time_btn=ctk.CTkButton(tb_right,text="Last 24 Hours  v",font=("Inter",11),
                        fg_color=BG_CARD,border_width=1,border_color=BORDER,
                        text_color=TEXT_PRI,hover_color=BG_ROW_ALT,height=32,width=165,
                        command=show_time_filter)
time_btn.pack(side="left",padx=6)

scan_top_btn=ctk.CTkButton(tb_right,text="Scan",font=("Inter",12,"bold"),
                            fg_color=BG_CARD,border_width=1,border_color=BORDER,
                            text_color=TEXT_PRI,hover_color=BG_ROW_ALT,height=32,width=60)
scan_top_btn.pack(side="left",padx=4)

notif_btn=ctk.CTkButton(tb_right,text="Alerts 0",font=("Inter",11),
                         fg_color=BG_CARD,border_width=1,border_color=BORDER,
                         text_color=ORANGE,hover_color=BG_ROW_ALT,height=32,width=70,
                         command=show_notifications)
notif_btn.pack(side="left",padx=4)

admin_btn=ctk.CTkButton(tb_right,text=f"{LOGGED_USER} v",font=("Inter",11),
                         fg_color=BG_CARD,border_width=1,border_color=BORDER,
                         text_color=TEXT_PRI,hover_color=BG_ROW_ALT,height=32,width=120,
                         command=show_admin_menu)
admin_btn.pack(side="left",padx=4)

scroll_frame=ctk.CTkScrollableFrame(main,fg_color=BG_DEEP,scrollbar_button_color=BORDER)
scroll_frame.pack(fill="both",expand=True)
content=scroll_frame

# ── stat cards 
stats_row=ctk.CTkFrame(content,fg_color="transparent")
stats_row.pack(fill="x",padx=20,pady=(16,8))
stat_defs=[
    ("ROGUE APS DETECTED","-",RED),
    ("AVAILABLE NETWORKS","-",BLUE),
    ("ACTIVE ALERTS","-",ORANGE),
    ("IGNORED NETWORKS","-",TEXT_MUTED),
    ("CLIENTS AT RISK","-",RED),
    ("TOTAL NETWORKS SCANNED","-",BLUE),
]
stat_labels={}; stat_sublbls={}
for title,val,col in stat_defs:
    card=make_card(stats_row); card.pack(side="left",fill="both",expand=True,padx=(0,8))
    inner=ctk.CTkFrame(card,fg_color="transparent"); inner.pack(fill="x",padx=16,pady=14)
    make_label(inner,title,size=10,color=TEXT_SEC).pack(anchor="w")
    vl=make_label(inner,val,size=28,weight="bold",color=col)
    vl.pack(anchor="w",pady=(4,2)); stat_labels[title]=vl
    sl=make_label(inner,"",size=10,color=TEXT_SEC); sl.pack(anchor="w"); stat_sublbls[title]=sl

# ── row 2: rogue table + donut + alerts ──────────────────────────────────────
row2=ctk.CTkFrame(content,fg_color="transparent"); row2.pack(fill="x",padx=20,pady=8)

rogue_card=make_card(row2); rogue_card.pack(side="left",fill="both",expand=True,padx=(0,8))
rh=ctk.CTkFrame(rogue_card,fg_color="transparent"); rh.pack(fill="x",padx=16,pady=(14,4))
make_label(rh,"Top Rogue APs",size=13,weight="bold").pack(side="left")
ctk.CTkButton(rh,text="View all rogue APs ->",font=("Inter",10),
              fg_color="transparent",text_color=BLUE,hover_color=BG_ROW_ALT,
              height=24,command=show_all_rogue_aps).pack(side="right")

style=ttk.Style(); style.theme_use("clam")
style.configure("Dark.Treeview",background=BG_CARD,foreground=TEXT_PRI,
    fieldbackground=BG_CARD,borderwidth=0,rowheight=32,font=("Inter",11))
style.configure("Dark.Treeview.Heading",background=BG_ROW_ALT,foreground=TEXT_SEC,
    borderwidth=0,font=("Inter",10,"bold"))
style.map("Dark.Treeview",background=[("selected","#1f2937")])

rogue_cols=("SSID","BSSID","Channel","Risk Level","Last Seen")
rogue_tree=ttk.Treeview(rogue_card,columns=rogue_cols,show="headings",
                         style="Dark.Treeview",height=6)
for col in rogue_cols:
    rogue_tree.heading(col,text=col)
    rogue_tree.column(col,width=190 if col in("SSID","BSSID") else 90,anchor="center")
rogue_tree.pack(fill="x",padx=12,pady=(0,12))
rogue_tree.tag_configure("high",  background="#2d1b1b",foreground=TEXT_PRI)
rogue_tree.tag_configure("medium",background="#2d2210",foreground=TEXT_PRI)

# donut
donut_card=make_card(row2); donut_card.pack(side="left",fill="y",padx=(0,8))
donut_card.configure(width=250)
make_label(donut_card,"Rogue APs by Risk Level",size=12,weight="bold",
           anchor="center").pack(pady=(14,4),padx=12)
donut_canvas=tk.Canvas(donut_card,width=210,height=160,bg=BG_CARD,highlightthickness=0)
donut_canvas.pack(pady=4)
legend_frame=ctk.CTkFrame(donut_card,fg_color="transparent"); legend_frame.pack(pady=(0,14),padx=20)
legend_labels={}
for color,label in[(RED,"High"),(ORANGE,"Medium"),(GREEN,"Low")]:
    r=ctk.CTkFrame(legend_frame,fg_color="transparent"); r.pack(fill="x",pady=2)
    ctk.CTkLabel(r,text="o",text_color=color,font=("Arial",14)).pack(side="left")
    lbl=make_label(r,f" {label} (0)",size=11,color=TEXT_SEC); lbl.pack(side="left")
    legend_labels[label]=lbl

def draw_donut(high=0,medium=0,low=0):
    donut_canvas.delete("all")
    total=high+medium+low; cx,cy,r_out,r_in=105,80,68,42
    if total==0:
        donut_canvas.create_arc(cx-r_out,cy-r_out,cx+r_out,cy+r_out,
            start=0,extent=359.9,fill=BG_ROW_ALT,outline=BG_CARD,width=2,style="pieslice")
    else:
        start=-90.0
        for count,color in[(high,RED),(medium,ORANGE),(low,GREEN)]:
            if count==0: continue
            extent=(count/total)*360
            donut_canvas.create_arc(cx-r_out,cy-r_out,cx+r_out,cy+r_out,
                start=start,extent=extent,fill=color,outline=BG_CARD,width=2,style="pieslice")
            start+=extent
    donut_canvas.create_oval(cx-r_in,cy-r_in,cx+r_in,cy+r_in,fill=BG_CARD,outline=BG_CARD)
    donut_canvas.create_text(cx,cy-10,text=str(total),fill=TEXT_PRI,font=("Inter",22,"bold"))
    donut_canvas.create_text(cx,cy+12,text="Total",fill=TEXT_SEC,font=("Inter",10))
    legend_labels["High"].configure(text=f" High ({high})")
    legend_labels["Medium"].configure(text=f" Medium ({medium})")
    legend_labels["Low"].configure(text=f" Low ({low})")

draw_donut()

# alerts timeline
alerts_card=make_card(row2); alerts_card.pack(side="left",fill="both",expand=True)
ah=ctk.CTkFrame(alerts_card,fg_color="transparent"); ah.pack(fill="x",padx=16,pady=(14,4))
make_label(ah,"Alerts Timeline",size=13,weight="bold").pack(side="left")
alerts_tl_frame=ctk.CTkFrame(alerts_card,fg_color="transparent")
alerts_tl_frame.pack(fill="both",expand=True,padx=12,pady=(0,4))

def refresh_timeline(items):
    for w in alerts_tl_frame.winfo_children(): w.destroy()
    for color,title,detail,when in items[:6]:
        row=ctk.CTkFrame(alerts_tl_frame,fg_color="transparent"); row.pack(fill="x",pady=5)
        ctk.CTkLabel(row,text="o",text_color=color,font=("Arial",14),width=16).pack(side="left",anchor="n",pady=2)
        txt=ctk.CTkFrame(row,fg_color="transparent"); txt.pack(side="left",padx=8,fill="x",expand=True)
        make_label(txt,title,size=11,weight="bold").pack(anchor="w")
        make_label(txt,detail,size=10,color=TEXT_SEC).pack(anchor="w")
        make_label(row,when,size=10,color=TEXT_MUTED).pack(side="right",anchor="n")
    vr=ctk.CTkFrame(alerts_card,fg_color="transparent"); vr.pack(fill="x",padx=12,pady=(0,10))
    ctk.CTkButton(vr,text="View all alerts ->",font=("Inter",10),
                  fg_color="transparent",text_color=BLUE,
                  hover_color=BG_ROW_ALT,height=24,command=show_all_alerts).pack(side="right")

refresh_timeline([])

# ── row 3: sensors + locations + env ─────────────────────────────────────────
row3=ctk.CTkFrame(content,fg_color="transparent"); row3.pack(fill="x",padx=20,pady=8)

sensors_card=make_card(row3); sensors_card.pack(side="left",fill="both",expand=True,padx=(0,8))
make_label(sensors_card,"Sensors Status",size=13,weight="bold").pack(anchor="w",padx=16,pady=(14,8))
sensors_dot_frame=ctk.CTkFrame(sensors_card,fg_color="transparent")
sensors_dot_frame.pack(fill="x",padx=16,pady=(0,4))
def render_sensor_dots(online=18,total=20):
    for w in sensors_dot_frame.winfo_children(): w.destroy()
    colors=([GREEN]*online)+([TEXT_MUTED]*(total-online))
    row_w=None
    for i,color in enumerate(colors):
        if i%10==0: row_w=ctk.CTkFrame(sensors_dot_frame,fg_color="transparent"); row_w.pack(anchor="w")
        ctk.CTkLabel(row_w,text="o",text_color=color,font=("Arial",18),width=22).pack(side="left")
render_sensor_dots()
ctk.CTkButton(sensors_card,text="View sensors ->",font=("Inter",10),
              fg_color="transparent",text_color=BLUE,hover_color=BG_ROW_ALT,
              height=28,command=show_sensors).pack(fill="x",padx=12,pady=(4,12))

loc_card=make_card(row3); loc_card.pack(side="left",fill="both",expand=True,padx=(0,8))
make_label(loc_card,"Top Flagged Networks",size=13,weight="bold").pack(anchor="w",padx=16,pady=(14,8))
loc_frame=ctk.CTkFrame(loc_card,fg_color="transparent"); loc_frame.pack(fill="x",padx=16,pady=(0,8))
def update_locations(data):
    for w in loc_frame.winfo_children(): w.destroy()
    if not data:
        make_label(loc_frame,"No flagged networks.",size=11,color=TEXT_MUTED).pack(anchor="w"); return
    max_count=max(c for _,c in data) or 1
    for i,(name,count) in enumerate(data[:5]):
        r=ctk.CTkFrame(loc_frame,fg_color="transparent"); r.pack(fill="x",pady=5)
        make_label(r,f"{i+1}. {name}",size=11).pack(side="left")
        bg=ctk.CTkFrame(r,height=8,corner_radius=4,fg_color=BG_ROW_ALT)
        bg.pack(side="left",fill="x",expand=True,padx=10)
        ctk.CTkFrame(bg,height=8,corner_radius=4,fg_color=BLUE
                     ).place(relx=0,rely=0,relwidth=count/max_count,relheight=1)
        make_label(r,str(count),size=11,color=TEXT_SEC).pack(side="right")
update_locations([])
ctk.CTkButton(loc_card,text="View full report ->",font=("Inter",10),
              fg_color="transparent",text_color=BLUE,hover_color=BG_ROW_ALT,
              height=28,command=show_full_report).pack(fill="x",padx=12,pady=(4,12))

env_card=make_card(row3); env_card.pack(side="left",fill="y"); env_card.configure(width=250)
make_label(env_card,"Wireless Environment",size=13,weight="bold").pack(anchor="w",padx=16,pady=(14,10))
env_row_frame=ctk.CTkFrame(env_card,fg_color="transparent"); env_row_frame.pack(fill="x",padx=12,pady=4)
env_labels={}
for label,key in[("Authorized APs","auth"),("Total Scanned","clients"),("Ignored","ignored")]:
    col=ctk.CTkFrame(env_row_frame,fg_color="transparent"); col.pack(side="left",expand=True,fill="x",padx=4)
    lbl=make_label(col,"-",size=18,weight="bold",color=TEXT_PRI,anchor="center"); lbl.pack(); env_labels[key]=lbl
    make_label(col,label,size=9,color=TEXT_SEC,anchor="center").pack()
ctk.CTkButton(env_card,text="View details ->",font=("Inter",10),
              fg_color="transparent",text_color=BLUE,hover_color=BG_ROW_ALT,
              height=28,command=show_wireless_details).pack(pady=(8,12))

# ── row 4: live access + activity ────────────────────────────────────────────
row4=ctk.CTkFrame(content,fg_color="transparent"); row4.pack(fill="x",padx=20,pady=(8,20))

live_card=make_card(row4); live_card.pack(side="left",fill="both",expand=True,padx=(0,8))
live_hdr=ctk.CTkFrame(live_card,fg_color="transparent"); live_hdr.pack(fill="x",padx=16,pady=(14,4))
make_label(live_hdr,"Live Access Status",size=13,weight="bold").pack(side="left")
scanning_label=make_label(live_hdr,"Ready",size=10,color=TEXT_SEC); scanning_label.pack(side="right")

live_cols=("","SSID","BSSID","Channel","Signal (dBm)","Encryption","Status","Risk","Admin Decision")
live_tree=ttk.Treeview(live_card,columns=live_cols,show="headings",style="Dark.Treeview",height=7)
for col,w in zip(live_cols,[28,155,160,65,95,100,95,80,115]):
    live_tree.heading(col,text=col); live_tree.column(col,width=w,anchor="center",minwidth=w)
live_tree.pack(fill="x",padx=12,pady=(0,4))
live_tree.tag_configure("safe",    background="#0d2818")
live_tree.tag_configure("warning", background="#2d2210")
live_tree.tag_configure("danger",  background="#2d1b1b")
live_tree.tag_configure("ignored", background="#1a1a2e")
live_tree.tag_configure("available", background="#0d1b2d")

live_actions=ctk.CTkFrame(live_card,fg_color="transparent"); live_actions.pack(fill="x",padx=12,pady=(4,12))

def get_selected():
    sel=live_tree.selection()
    if not sel:
        messagebox.showwarning("No Selection","Select an access point first."); return None
    return live_tree.item(sel[0])["values"]

def approve_ap():
    vals=get_selected()
    if not vals: return
    ssid,bssid,decision=vals[1],vals[2],vals[8]
    if decision=="APPROVED":
        messagebox.showinfo("Already Approved",f"{ssid} is already approved."); return
    enc=vals[5] if vals[5] else "-"; sig=vals[4] if vals[4] else "-"
    db_exec("UPDATE access_points SET status='SAFE',threat_level='LOW',admin_decision='APPROVED',ignored_reason=NULL WHERE bssid=%s",(bssid,))
    db_exec("INSERT INTO alerts (alert_type,alert_message) VALUES (%s,%s)",("APPROVED",f"Admin approved {ssid} ({bssid})"))
    ADMIN_LOCKED.add(bssid.lower().strip())
    push_alert(ssid,bssid,"SAFE","LOW",enc,sig)
    add_activity(f"Approved (locked): {ssid}",GREEN)
    load_data()
    messagebox.showinfo("Approved",f"{ssid} approved as SAFE.\n\nFuture scans will not change this.")

def block_ap():
    vals=get_selected()
    if not vals: return
    ssid,bssid=vals[1],vals[2]
    if not messagebox.askyesno("Confirm Block",f"Block {ssid}?\nMarks it HIGH threat and locks it."): return
    enc=vals[5] if vals[5] else "-"; sig=vals[4] if vals[4] else "-"
    db_exec("UPDATE access_points SET status='SUSPICIOUS',threat_level='HIGH',admin_decision='BLOCKED',ignored_reason=NULL WHERE bssid=%s",(bssid,))
    db_exec("INSERT INTO alerts (alert_type,alert_message) VALUES (%s,%s)",("BLOCKED",f"Admin blocked {ssid} ({bssid})"))
    ADMIN_LOCKED.add(bssid.lower().strip())
    push_alert(ssid,bssid,"SUSPICIOUS","HIGH",enc,sig)
    add_activity(f"Blocked (locked): {ssid}",RED)
    load_data()
    messagebox.showwarning("Blocked",f"{ssid} blocked.\n\nFuture scans will not change this.")

def quarantine_ap():
    vals=get_selected()
    if not vals: return
    ssid,bssid=vals[1],vals[2]
    enc=vals[5] if vals[5] else "-"; sig=vals[4] if vals[4] else "-"
    db_exec("UPDATE access_points SET status='WARNING',threat_level='MEDIUM',admin_decision='QUARANTINED',ignored_reason=NULL WHERE bssid=%s",(bssid,))
    db_exec("INSERT INTO alerts (alert_type,alert_message) VALUES (%s,%s)",("QUARANTINED",f"Admin quarantined {ssid} ({bssid})"))
    ADMIN_LOCKED.add(bssid.lower().strip())
    push_alert(ssid,bssid,"WARNING","MEDIUM",enc,sig)
    add_activity(f"Quarantined (locked): {ssid}",ORANGE)
    load_data()
    messagebox.showwarning("Quarantined",f"{ssid} quarantined.")

def ignore_ap():
    vals=get_selected()
    if not vals: return
    ssid,bssid=vals[1],vals[2]
    if not messagebox.askyesno("Ignore Network",
        f"Mark '{ssid}' as IGNORED?\n\n"
        f"Use this for neighbour/school networks that are not your concern.\n"
        f"They will be recorded but never flagged as rogue."): return
    db_exec("UPDATE access_points SET status='IGNORED',threat_level='NONE',admin_decision='IGNORED',ignored_reason='Not in monitoring zone' WHERE bssid=%s",(bssid,))
    db_exec("INSERT INTO alerts (alert_type,alert_message) VALUES (%s,%s)",("IGNORED",f"Admin ignored {ssid} ({bssid})"))
    IGNORED_SSIDS.add(ssid.strip())
    ADMIN_LOCKED.add(bssid.lower().strip())
    add_activity(f"Ignored: {ssid}",TEXT_MUTED)
    load_data()
    messagebox.showinfo("Ignored",f"'{ssid}' will no longer be flagged as rogue.\n\nTo manage this, go to Manage Networks in the sidebar.")

def unlock_ap():
    vals=get_selected()
    if not vals: return
    ssid,bssid=vals[1],vals[2]
    bk=bssid.lower().strip()
    if bk not in ADMIN_LOCKED:
        messagebox.showinfo("Not Locked",f"{ssid} has no admin lock."); return
    if not messagebox.askyesno("Unlock",f"Remove admin lock from {ssid}?\nNext scan will re-classify it."): return
    ADMIN_LOCKED.discard(bk); IGNORED_SSIDS.discard(ssid.strip())
    db_exec("UPDATE access_points SET admin_decision='PENDING',ignored_reason=NULL WHERE bssid=%s",(bssid,))
    add_activity(f"Unlocked: {ssid}",BLUE); load_data()
    messagebox.showinfo("Unlocked",f"{ssid} unlocked. Next scan will re-classify it.")

for text,cmd,fc,hc in[
    ("Approve",    approve_ap,   "#166534","#15803d"),
    ("Block",      block_ap,     "#7f1d1d","#dc2626"),
    ("Quarantine", quarantine_ap,"#78350f","#d97706"),
    ("Ignore",    ignore_ap,    "#1e3a5f","#2563eb"),
    ("Unlock",    unlock_ap,    "#4a1942","#7c3aed"),
]:
    ctk.CTkButton(live_actions,text=text,command=cmd,font=("Inter",11,"bold"),
                  fg_color=fc,hover_color=hc,height=34,width=100,corner_radius=6).pack(side="left",padx=(0,5))

ctk.CTkButton(live_actions,text="Manage Networks ->",font=("Inter",10),
              fg_color="transparent",text_color=BLUE,hover_color=BG_ROW_ALT,
              height=34,command=show_manage_networks).pack(side="right")

# activity
activity_card=make_card(row4); activity_card.pack(side="left",fill="both")
activity_card.configure(width=310)
make_label(activity_card,"System Activity",size=13,weight="bold").pack(anchor="w",padx=16,pady=(14,8))
act_frame=ctk.CTkFrame(activity_card,fg_color="transparent"); act_frame.pack(fill="both",expand=True,padx=12)
activity_items=[]
def add_activity(msg,color=GREEN,ts=None):
    ts=ts or datetime.now().strftime("%H:%M:%S")
    activity_items.insert(0,(color,msg,ts))
    if len(activity_items)>30: activity_items.pop()
    _render_activity()
def _render_activity():
    for w in act_frame.winfo_children(): w.destroy()
    for color,msg,ts in activity_items[:12]:
        r=ctk.CTkFrame(act_frame,fg_color="transparent"); r.pack(fill="x",pady=2)
        ctk.CTkLabel(r,text="o",text_color=color,font=("Arial",10),width=14).pack(side="left")
        make_label(r,msg,size=10,color=TEXT_SEC).pack(side="left",padx=4)
        make_label(r,ts,size=10,color=TEXT_MUTED).pack(side="right")
add_activity("Dashboard started",GREEN)
ctk.CTkButton(activity_card,text="View full logs ->",font=("Inter",10),
              fg_color="transparent",text_color=BLUE,hover_color=BG_ROW_ALT,
              height=28,command=show_full_logs).pack(pady=(4,12))

# ── row 5: traffic & suspicious activity analysis (expanded) ────────────────
row5=ctk.CTkFrame(content,fg_color="transparent"); row5.pack(fill="x",padx=20,pady=(0,20))

traffic_card=make_card(row5); traffic_card.pack(side="left",fill="x")

th=ctk.CTkFrame(traffic_card,fg_color="transparent"); th.pack(fill="x",padx=16,pady=(14,4))
make_label(th,"Traffic Analysis & Suspicious Activity",size=14,weight="bold").pack(side="left")
traffic_monitor_status_lbl=make_label(th,"Starting...",size=10,color=TEXT_MUTED)
traffic_monitor_status_lbl.pack(side="right")
export_log_btn = ctk.CTkButton(th, text="Export Log (CSV)", font=("Inter",10,"bold"),
                                fg_color=BG_ROW_ALT, hover_color=BORDER, text_color=TEXT_PRI,
                                height=26, width=130)
export_log_btn.pack(side="right", padx=10)

make_label(traffic_card,
           "Packet/connection volume on the active network vs. a rolling baseline, "
           "plus every rogue-AP, deauth-flood, and traffic-anomaly event the system has logged.",
           size=10,color=TEXT_SEC).pack(anchor="w",padx=16,pady=(0,8))

# split: chart+stats on the left, suspicious-events timeline on the right
traffic_body = ctk.CTkFrame(traffic_card, fg_color="transparent")
traffic_body.pack(fill="x", padx=16, pady=(0,16))

traffic_left = ctk.CTkFrame(traffic_body, fg_color="transparent")
traffic_left.pack(side="left", fill="both", padx=(0,12))

traffic_canvas = tk.Canvas(traffic_left, height=220, width=640, bg=BG_CARD, highlightthickness=0)
traffic_canvas.pack(fill="x", pady=(0,8))

traffic_stats_row = ctk.CTkFrame(traffic_left, fg_color="transparent")
traffic_stats_row.pack(fill="x")
traffic_pkt_lbl  = make_label(traffic_stats_row, "Packets (last window): -", size=11, color=TEXT_SEC)
traffic_pkt_lbl.pack(side="left")
traffic_conn_lbl = make_label(traffic_stats_row, "Connections: -", size=11, color=TEXT_SEC)
traffic_conn_lbl.pack(side="left", padx=20)
traffic_anomaly_lbl = make_label(traffic_stats_row, "", size=11, weight="bold", color=ORANGE)
traffic_anomaly_lbl.pack(side="right")

# suspicious events timeline (right side) - pulls from the SAME alerts table
# already fed by rogue-AP scans, deauth-flood detection, and traffic anomalies,
# so this is a unified view rather than a separate tracking mechanism.
#
# IMPORTANT: this is a plain frame, NOT a CTkScrollableFrame. Nesting a
# scrollable frame inside the dashboard's own outer scrollable area breaks
# the outer scroll region calculation and steals mousewheel focus, which is
# exactly what caused the "can't scroll past this card" bug. Instead this
# shows a short, fixed list and links out to the existing Alerts window
# (show_all_alerts) for the full history - one scrollbar for the whole page.
traffic_right = ctk.CTkFrame(traffic_body, fg_color=BG_ROW_ALT, corner_radius=8)
traffic_right.pack(side="left", fill="both", padx=(0,0))
traffic_right.configure(width=340)

make_label(traffic_right, "Suspicious Activity Timeline", size=12, weight="bold").pack(
    anchor="w", padx=12, pady=(10,4))

events_scroll = ctk.CTkFrame(traffic_right, fg_color="transparent")
events_scroll.pack(fill="x", padx=8, pady=(0,4))

ctk.CTkButton(traffic_right, text="View all in Alerts ->", font=("Inter",10),
              fg_color="transparent", text_color=BLUE, hover_color=BORDER,
              height=24, command=lambda: show_all_alerts()).pack(anchor="w", padx=10, pady=(0,10))

EVENTS_SHOWN = 6   # fixed short list - fits without needing its own scrollbar

def refresh_suspicious_events():
    for w in events_scroll.winfo_children(): w.destroy()
    rows = db_exec(f"""
        SELECT alert_type, alert_message, created_at
        FROM alerts
        WHERE alert_type IN ('SUSPICIOUS','WARNING')
        ORDER BY alert_id DESC LIMIT {EVENTS_SHOWN}
    """) or []
    if not rows:
        make_label(events_scroll, "No suspicious activity logged yet.",
                   size=10, color=TEXT_MUTED).pack(anchor="w", padx=6, pady=6)
        return
    for atype, amsg, ats in rows:
        is_deauth  = "deauth" in (amsg or "").lower()
        is_traffic = "traffic volume" in (amsg or "").lower()
        color = PURPLE if is_deauth else (BLUE if is_traffic else (RED if atype=="SUSPICIOUS" else ORANGE))
        row = ctk.CTkFrame(events_scroll, fg_color=BG_CARD, corner_radius=6)
        row.pack(fill="x", pady=3, padx=2)
        top = ctk.CTkFrame(row, fg_color="transparent"); top.pack(fill="x", padx=8, pady=(6,0))
        ctk.CTkLabel(top, text="o", text_color=color, font=("Arial",11)).pack(side="left")
        when = ats.strftime("%H:%M:%S") if ats else "-"
        make_label(top, f" {when}", size=9, color=TEXT_MUTED).pack(side="left")
        make_label(row, amsg or "-", size=10, color=TEXT_PRI, anchor="w").pack(
            fill="x", padx=10, pady=(2,6))

def export_traffic_log():
    path = filedialog.asksaveasfilename(
        defaultextension=".csv",
        filetypes=[("CSV files","*.csv")],
        initialfile="traffic_and_activity_log.csv",
        title="Export Traffic & Suspicious Activity Log")
    if not path:
        return
    try:
        traffic_rows = db_exec("""
            SELECT sample_time, packet_count, connection_count, byte_count, is_anomaly
            FROM traffic_samples ORDER BY sample_time
        """) or []
        event_rows = db_exec("""
            SELECT created_at, alert_type, alert_message
            FROM alerts WHERE alert_type IN ('SUSPICIOUS','WARNING')
            ORDER BY created_at
        """) or []

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["source", "timestamp", "detail_1", "detail_2", "detail_3"])
            for ts, pkts, conns, byts, anomaly in traffic_rows:
                writer.writerow(["TRAFFIC_SAMPLE", ts, f"packets={pkts}",
                                  f"connections={conns}", f"anomaly={anomaly}"])
            for ts, atype, amsg in event_rows:
                writer.writerow(["SUSPICIOUS_EVENT", ts, atype, amsg, ""])

        add_activity(f"Exported traffic/activity log to {os.path.basename(path)}", GREEN)
        messagebox.showinfo("Export Complete", f"Log exported to:\n{path}")
    except Exception as e:
        messagebox.showerror("Export Failed", f"Could not export log:\n{e}")

export_log_btn.configure(command=export_traffic_log)

def _draw_traffic_chart():
    traffic_canvas.delete("all")
    w = traffic_canvas.winfo_width() or 700
    h = traffic_canvas.winfo_height() or 220
    data = list(_traffic_chart_data)
    if not data:
        traffic_canvas.create_text(w/2, h/2, text="Waiting for traffic samples...",
                                    fill=TEXT_MUTED, font=("Inter", 10))
        return

    pad_bottom = 16
    chart_h = h - pad_bottom
    max_val = max((p for p,_ in data), default=1) or 1

    # rolling baseline reference line, drawn from the same history the
    # detector itself uses - makes it visually obvious why a bar was flagged
    if len(_traffic_history) >= 2:
        import statistics as _stats
        baseline = _stats.mean([hh["packets"] for hh in _traffic_history])
        base_y = chart_h - (baseline / max_val) * (chart_h - 10) if max_val else chart_h
        traffic_canvas.create_line(0, base_y, w, base_y, fill=TEXT_MUTED, dash=(3,2), width=1)
        traffic_canvas.create_text(w-4, base_y-8, text="baseline", anchor="e",
                                    fill=TEXT_MUTED, font=("Inter", 8))

    bar_w = max(w / max(len(data), 1) - 3, 3)
    x = 2
    for packets, is_anomaly in data:
        bar_h = (packets / max_val) * (chart_h - 10) if max_val else 0
        color = RED if is_anomaly else BLUE
        traffic_canvas.create_rectangle(x, chart_h - bar_h, x + bar_w, chart_h,
                                         fill=color, outline="")
        x += bar_w + 3
    traffic_canvas.create_text(4, h-4, text="older", anchor="w", fill=TEXT_MUTED, font=("Inter",8))
    traffic_canvas.create_text(w-4, h-4, text="now", anchor="e", fill=TEXT_MUTED, font=("Inter",8))

def _update_traffic_ui(packets, connections, is_anomaly):
    traffic_pkt_lbl.configure(text=f"Packets (last window): {packets}")
    traffic_conn_lbl.configure(text=f"Connections: {connections}")
    traffic_anomaly_lbl.configure(
        text="ANOMALY - unusual volume detected" if is_anomaly else "")
    _draw_traffic_chart()
    refresh_suspicious_events()

def _update_traffic_status_label():
    if _traffic_status["active"]:
        traffic_monitor_status_lbl.configure(text=_traffic_status["note"], text_color=GREEN)
    else:
        traffic_monitor_status_lbl.configure(
            text=_traffic_status["note"],
            text_color=ORANGE if SCAPY_OK else TEXT_MUTED)
    root.after(3000, _update_traffic_status_label)

# status bar
statusbar=ctk.CTkFrame(root,fg_color=BG_CARD,height=28,corner_radius=0,border_width=1,border_color=BORDER)
statusbar.pack(fill="x",side="bottom"); statusbar.pack_propagate(False)
make_label(statusbar,"Rogue AP Detection System v2.0",size=10,color=TEXT_MUTED).pack(side="left",padx=16,pady=5)
scan_status_lbl=make_label(statusbar,"Ready",size=10,color=TEXT_SEC); scan_status_lbl.pack(side="left",padx=20,pady=5)
scapy_status_lbl=make_label(statusbar,"Scapy: starting...",size=10,color=TEXT_MUTED)
scapy_status_lbl.pack(side="right",padx=16,pady=5)
make_label(statusbar,
           "Database: Connected" if DB_CONNECTED else "Database: Disconnected",
           size=10,color=GREEN if DB_CONNECTED else RED).pack(side="right",padx=16,pady=5)

def _update_scapy_status_label():
    if _scapy_status["active"]:
        scapy_status_lbl.configure(text=f"Scapy: {_scapy_status['note']}", text_color=GREEN)
    else:
        scapy_status_lbl.configure(text=f"Scapy: {_scapy_status['note']}", text_color=ORANGE if SCAPY_OK else TEXT_MUTED)
    root.after(3000, _update_scapy_status_label)

# ─────────────────────────────────────────────────────────────────────────────
# LOAD DATA
# ─────────────────────────────────────────────────────────────────────────────
def load_data():
    if not cursor: _load_fallback(); return
    rows=db_exec("""
        SELECT ssid,bssid,signal_strength,encryption_type,
               status,threat_level,admin_decision,channel
        FROM access_points
        ORDER BY
            CASE status WHEN 'IGNORED' THEN 99 ELSE 0 END,
            CASE threat_level WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END,
            ssid
    """)
    if rows is None: _load_fallback(); return
    for r in live_tree.get_children():  live_tree.delete(r)
    for r in rogue_tree.get_children(): rogue_tree.delete(r)

    safe_count=high_count=medium_count=low_count=ignored_count=available_count=0
    total=len(rows); now_str=datetime.now().strftime("%H:%M")

    for ssid,bssid,signal,enc,status,threat,decision,channel in rows:
        status  =(status   or "SUSPICIOUS").upper()
        threat  =(threat   or "HIGH").upper()
        decision=(decision or "PENDING")
        bssid_key=(bssid or "").lower().strip()
        lock_icon="L" if bssid_key in ADMIN_LOCKED else ""
        channel_display = str(channel) if channel is not None else "-"

        if status=="IGNORED":
            tag="ignored"; ignored_count+=1; lock_icon="I"
        elif status=="AVAILABLE":
            tag="available"; available_count+=1
        elif status in("SUSPICIOUS","ROGUE","BLOCKED"):
            tag="danger"
        elif status in("WARNING","QUARANTINED"):
            tag="warning"
        else:
            tag="safe"; safe_count+=1

        # Risk tally only reflects genuine rogue signals (evil-twin / open
        # networks) — AVAILABLE and SAFE networks aren't threats, so they
        # don't inflate the "Rogue APs by Risk Level" donut.
        if status in("SUSPICIOUS","WARNING","ROGUE","BLOCKED","QUARANTINED"):
            if threat=="HIGH":     high_count+=1
            elif threat=="MEDIUM": medium_count+=1
            else:                  low_count+=1

        risk_display = threat if status in("SUSPICIOUS","WARNING","ROGUE","BLOCKED","QUARANTINED") else "-"
        live_tree.insert("","end",tags=(tag,),values=(
            lock_icon,ssid,bssid,channel_display,signal or "-",enc or "-",
            status,risk_display,decision
        ))
        if status not in("SAFE","IGNORED","AVAILABLE"):
            rtag=threat.lower() if threat.lower() in("high","medium","low") else "high"
            rogue_tree.insert("","end",tags=(rtag,),values=(ssid,bssid,channel_display,threat.capitalize(),now_str))

    rogue_detected=high_count+medium_count
    alert_rows=db_exec("SELECT COUNT(*) FROM alerts WHERE alert_type NOT IN ('APPROVED','IGNORED')") or [[0]]
    alert_count=alert_rows[0][0] if alert_rows else 0

    stat_labels["ROGUE APS DETECTED"].configure(text=str(rogue_detected))
    stat_sublbls["ROGUE APS DETECTED"].configure(text=f"{high_count} high, {medium_count} medium")
    stat_labels["AVAILABLE NETWORKS"].configure(text=str(available_count))
    stat_sublbls["AVAILABLE NETWORKS"].configure(text="nearby, unreviewed, no threat signs")
    stat_labels["ACTIVE ALERTS"].configure(text=str(alert_count))
    stat_sublbls["ACTIVE ALERTS"].configure(text="unresolved alerts")
    stat_labels["IGNORED NETWORKS"].configure(text=str(ignored_count))
    stat_sublbls["IGNORED NETWORKS"].configure(text="neighbour / other zones")
    stat_labels["CLIENTS AT RISK"].configure(text=str(rogue_detected))
    stat_sublbls["CLIENTS AT RISK"].configure(text="exposed to rogue APs")
    stat_labels["TOTAL NETWORKS SCANNED"].configure(text=str(total))
    stat_sublbls["TOTAL NETWORKS SCANNED"].configure(text=f"{safe_count} safe, {available_count} available, {ignored_count} ignored")

    notif_btn.configure(text=f"Alerts {alert_count}")
    draw_donut(high=high_count,medium=medium_count,low=low_count)
    env_labels["auth"].configure(text=str(safe_count))
    env_labels["clients"].configure(text=str(total))
    env_labels["ignored"].configure(text=str(ignored_count))

    alert_data=db_exec("SELECT alert_type,alert_message,created_at FROM alerts ORDER BY alert_id DESC LIMIT 6") or []
    tl_items=[]
    for atype,amsg,ats in alert_data:
        atype=(atype or "").upper()
        if atype in("SUSPICIOUS","HIGH","ROGUE","BLOCKED"):   color=RED;    title="Rogue AP Detected"
        elif atype in("WARNING","MEDIUM","QUARANTINED"):      color=ORANGE; title="Suspicious AP"
        elif atype in("SAFE","APPROVED","LOW"):               color=GREEN;  title="Authorized Network"
        elif atype=="IGNORED":                                color=TEXT_MUTED; title="Network Ignored"
        elif atype=="AVAILABLE":                              color=BLUE;   title="Available Network"
        else:                                                 color=BLUE;   title=atype.capitalize()
        when=ats.strftime("%H:%M") if ats else "-"
        tl_items.append((color,title,amsg or "",when))
    refresh_timeline(tl_items)

    loc_data_raw=db_exec("""
        SELECT ssid,COUNT(*) FROM access_points
        WHERE status IN('SUSPICIOUS','WARNING') GROUP BY ssid ORDER BY COUNT(*) DESC LIMIT 5
    """) or []
    if not loc_data_raw: loc_data_raw=[(r[0],1) for r in rows[:5] if r[4] not in("SAFE","IGNORED","AVAILABLE")]
    update_locations([(r[0],r[1]) for r in loc_data_raw])
    refresh_suspicious_events()

def _load_fallback():
    for r in live_tree.get_children():  live_tree.delete(r)
    for r in rogue_tree.get_children(): rogue_tree.delete(r)
    live_tree.insert("","end",values=("!","No DB connection","-","-","-","-","-","-","-"))
    for key in stat_labels: stat_labels[key].configure(text="-")
    add_activity("DB unavailable",ORANGE)

# ─────────────────────────────────────────────────────────────────────────────
# SCAN - smarter classification
# ─────────────────────────────────────────────────────────────────────────────
def scan_networks():
    scanning_label.configure(text="Scanning...",text_color=ORANGE)
    scan_top_btn.configure(state="disabled")
    scan_status_lbl.configure(text="Scanning in progress...",text_color=ORANGE)
    add_activity("Wi-Fi scan started",BLUE)

    def do_scan():
        try:
            wifi=pywifi.PyWiFi(); iface=wifi.interfaces()[0]
            iface.scan(); time.sleep(5); results=iface.scan_results()
            found=ignored_n=0

            for network in results:
                ssid=network.ssid.strip()
                bssid    =network.bssid.strip().lower().rstrip(":")
                if not ssid:
                    # Hidden/blank SSID (common router "hide network name"
                    # setting). Don't drop it - a rogue AP detector should
                    # NEVER silently skip hidden networks. Give it a
                    # placeholder name keyed to its BSSID so it's still
                    # visible and trackable.
                    ssid = f"<Hidden Network {bssid[-8:]}>"
                signal   =network.signal
                encryption="WPA/WPA2" if network.akm else "OPEN"
                found+=1

                if bssid in ADMIN_LOCKED:
                    db_exec("""
                        INSERT INTO access_points
                          (ssid,bssid,signal_strength,encryption_type,status,threat_level,admin_decision)
                        VALUES (%s,%s,%s,%s,'PENDING','NONE','PENDING')
                        ON CONFLICT (bssid) DO UPDATE SET signal_strength=EXCLUDED.signal_strength
                    """,(ssid,bssid,signal,encryption))
                    ui_call(lambda s=ssid: add_activity(f"Locked (kept): {s}",PURPLE))
                    continue

                status,threat,ignored_reason=classify(ssid,bssid,encryption)

                if status=="IGNORED":
                    ignored_n+=1
                    db_exec("""
                        INSERT INTO access_points
                          (ssid,bssid,signal_strength,encryption_type,
                           status,threat_level,admin_decision,ignored_reason)
                        VALUES (%s,%s,%s,%s,'IGNORED','NONE','IGNORED',%s)
                        ON CONFLICT (bssid) DO UPDATE SET
                          signal_strength=EXCLUDED.signal_strength,
                          status='IGNORED',threat_level='NONE',
                          admin_decision='IGNORED',ignored_reason=EXCLUDED.ignored_reason
                    """,(ssid,bssid,signal,encryption,ignored_reason))
                    ui_call(lambda s=ssid,r=ignored_reason:
                               add_activity(f"Ignored: {s} ({r})",TEXT_MUTED))
                elif status=="AVAILABLE":
                    # Just another network nearby, no rogue signal — record it
                    # for the admin to review, but don't spam alerts/popups
                    # for something that isn't evidence of an attack.
                    db_exec("""
                        INSERT INTO access_points
                          (ssid,bssid,signal_strength,encryption_type,
                           status,threat_level,admin_decision,ignored_reason)
                        VALUES (%s,%s,%s,%s,'AVAILABLE','LOW','PENDING',NULL)
                        ON CONFLICT (bssid) DO UPDATE SET
                          ssid=EXCLUDED.ssid,signal_strength=EXCLUDED.signal_strength,
                          encryption_type=EXCLUDED.encryption_type,
                          status='AVAILABLE',threat_level='LOW',
                          admin_decision='PENDING',ignored_reason=NULL
                    """,(ssid,bssid,signal,encryption))
                    ui_call(lambda s=ssid: add_activity(f"Available: {s}",BLUE))
                else:
                    db_exec("""
                        INSERT INTO access_points
                          (ssid,bssid,signal_strength,encryption_type,
                           status,threat_level,admin_decision,ignored_reason)
                        VALUES (%s,%s,%s,%s,%s,%s,'PENDING',NULL)
                        ON CONFLICT (bssid) DO UPDATE SET
                          ssid=EXCLUDED.ssid,signal_strength=EXCLUDED.signal_strength,
                          encryption_type=EXCLUDED.encryption_type,
                          status=EXCLUDED.status,threat_level=EXCLUDED.threat_level,
                          admin_decision='PENDING',ignored_reason=NULL
                    """,(ssid,bssid,signal,encryption,status,threat))
                    db_exec("INSERT INTO alerts (alert_type,alert_message) VALUES (%s,%s)",
                            (status,f"{ssid} ({bssid}) detected as {status}"))
                    color=GREEN if status=="SAFE" else(ORANGE if status=="WARNING" else RED)
                    ui_call(lambda m=f"{ssid} -> {status}",c=color: add_activity(m,c))
                    push_alert(ssid,bssid,status,threat,encryption,str(signal))

            ui_call(lambda:scanning_label.configure(
                text=f"Done - {found} APs ({ignored_n} ignored)",text_color=GREEN))
            ui_call(lambda:scan_status_lbl.configure(
                text=f"Last scan: {datetime.now().strftime('%H:%M:%S')}",text_color=GREEN))
            ui_call(lambda:scan_top_btn.configure(state="normal"))
            ui_call(load_data)
            ui_call(lambda:add_activity(f"Scan done - {found} found, {ignored_n} ignored",GREEN))
        except Exception as e:
            ui_call(lambda:scanning_label.configure(text="Scan error",text_color=RED))
            ui_call(lambda:scan_status_lbl.configure(text="Scan failed",text_color=RED))
            ui_call(lambda:scan_top_btn.configure(state="normal"))
            ui_call(lambda:add_activity(f"Scan error: {str(e)[:40]}",RED))

    threading.Thread(target=do_scan,daemon=True).start()

scan_top_btn.configure(command=scan_networks)

def auto_refresh():
    load_data(); root.after(10000,auto_refresh)

# ─────────────────────────────────────────────────────────────────────────────
# BOOT
# ─────────────────────────────────────────────────────────────────────────────
ensure_ignored_column()
ensure_traffic_table()
load_locked()
load_ignored_from_db()
add_activity("Dashboard initialized",GREEN)
add_activity(f"Logged in as: {LOGGED_USER} ({LOGGED_ROLE})",BLUE)
add_activity(f"Trusted: Safaricom_B320_8F84",GREEN)
add_activity(f"Admin-locked APs: {len(ADMIN_LOCKED)} | Ignored SSIDs: {len(IGNORED_SSIDS)}",PURPLE)
add_activity("Listening for client connection events...",BLUE)

def _start_background_threads():
    """Only launch background threads once Tkinter's event loop is actually
    running. Starting them earlier (even right before root.mainloop()) is a
    race: if a thread reaches its first root.after() call before mainloop()
    has begun pumping events, Tcl raises 'main thread is not in main loop'.
    Scheduling this via root.after() guarantees mainloop is already active
    by the time any thread touches the UI."""
    threading.Thread(target=poll_client_events,  daemon=True).start()
    threading.Thread(target=start_scapy_sniffer, daemon=True).start()
    threading.Thread(target=start_traffic_monitor, daemon=True).start()

root.after(200, _start_background_threads)
_update_scapy_status_label()
_update_traffic_status_label()
_draw_traffic_chart()
_drain_ui_queue()
auto_refresh()
root.mainloop()
