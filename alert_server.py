from flask import Flask, request, jsonify
from datetime import datetime
from collections import deque
import threading

app = Flask(__name__)

# Thread-safe alert queue — holds up to 100 alerts
_lock        = threading.Lock()
alert_queue  = deque(maxlen=100)   # all alerts ever received (newest first)
pending      = deque()             # alerts not yet ACKed by any client

# Thread-safe CLIENT-CONNECTION event queue — kept entirely separate from the
# scan-alert queue above so the admin dashboard and the client device never
# steal items from each other by polling the same deque.
_client_lock     = threading.Lock()
client_events    = deque(maxlen=100)   # all client-connection events ever received
client_pending   = deque()             # events not yet ACKed by the admin dashboard

# =========================
# POST /send_alert
# Dashboard posts here whenever a network is scanned.
# Payload: { ssid, bssid, status, threat_level, encryption, signal }
# =========================

@app.route("/send_alert", methods=["POST"])
def send_alert():
    data = request.json or {}

    ssid        = data.get("ssid",        "Unknown")
    bssid       = data.get("bssid",       "—")
    status      = data.get("status",      "UNKNOWN").upper()
    threat      = data.get("threat_level","—").upper()
    encryption  = data.get("encryption",  "—")
    signal      = data.get("signal",      "—")
    timestamp   = datetime.now().strftime("%H:%M:%S")

    # Build a rich alert object
    if status == "SAFE":
        alert = {
            "type":       "safe",
            "title":      "✓  Safe Network",
            "ssid":       ssid,
            "bssid":      bssid,
            "status":     status,
            "threat":     threat,
            "encryption": encryption,
            "signal":     signal,
            "message":    f"This network is verified and safe to connect.\nEncryption: {encryption}",
            "color":      "#14532d",
            "border":     "#22c55e",
            "timestamp":  timestamp,
        }
    elif status in ("SUSPICIOUS", "ROGUE", "BLOCKED"):
        alert = {
            "type":       "danger",
            "title":      "⚠  Rogue Access Point",
            "ssid":       ssid,
            "bssid":      bssid,
            "status":     status,
            "threat":     threat,
            "encryption": encryption,
            "signal":     signal,
            "message":    "DO NOT CONNECT — this AP is not authorised.\nYour data may be intercepted.",
            "color":      "#7f1d1d",
            "border":     "#ef4444",
            "timestamp":  timestamp,
        }
    else:  # WARNING / QUARANTINED / OPEN
        alert = {
            "type":       "warning",
            "title":      "⚠  Suspicious Network",
            "ssid":       ssid,
            "bssid":      bssid,
            "status":     status,
            "threat":     threat,
            "encryption": encryption,
            "signal":     signal,
            "message":    "Proceed with caution — this network has no encryption\nor has not been verified by your administrator.",
            "color":      "#78350f",
            "border":     "#f59e0b",
            "timestamp":  timestamp,
        }

    with _lock:
        alert_queue.appendleft(alert)
        pending.append(alert)

    print(f"[{timestamp}] ALERT → {status}: {ssid}")
    return jsonify({"status": "ok", "timestamp": timestamp})

# =========================
# GET /get_alerts
# Client polls here. Returns all unACKed alerts then clears queue.
# =========================

@app.route("/get_alerts", methods=["GET"])
def get_alerts():
    with _lock:
        items = list(pending)
        pending.clear()
    return jsonify(items)

# =========================
# GET /alert_history
# Returns the last 50 alerts (newest first) for the history log.
# =========================

@app.route("/alert_history", methods=["GET"])
def alert_history():
    with _lock:
        items = list(alert_queue)
    return jsonify(items)

# =========================
# POST /client_connected
# A client device (user_client.py) posts here the moment it joins a
# network, so the ADMIN dashboard can be alerted too — separate from the
# scan-alert queue above.
# Payload: { client_name, ssid, bssid, status, threat_level, encryption, signal }
# =========================

@app.route("/client_connected", methods=["POST"])
def client_connected():
    data = request.json or {}

    client_name = data.get("client_name",  "Unknown Device")
    ssid        = data.get("ssid",         "Unknown")
    bssid       = data.get("bssid",        "—")
    status      = data.get("status",       "UNKNOWN").upper()
    threat      = data.get("threat_level", "—").upper()
    encryption  = data.get("encryption",   "—")
    signal      = data.get("signal",       "—")
    timestamp   = datetime.now().strftime("%H:%M:%S")

    if status == "SAFE":
        event = {
            "type":        "safe",
            "title":       "✓  Client Connected to Safe Network",
            "client_name": client_name,
            "ssid":        ssid,
            "bssid":       bssid,
            "status":      status,
            "threat":      threat,
            "encryption":  encryption,
            "signal":      signal,
            "message":     f"{client_name} connected to a verified, authorised network.",
            "color":       "#14532d",
            "border":      "#22c55e",
            "timestamp":   timestamp,
        }
    elif status in ("SUSPICIOUS", "ROGUE", "BLOCKED"):
        event = {
            "type":        "danger",
            "title":       "⚠  Client Connected to Rogue AP",
            "client_name": client_name,
            "ssid":        ssid,
            "bssid":       bssid,
            "status":      status,
            "threat":      threat,
            "encryption":  encryption,
            "signal":      signal,
            "message":     f"{client_name} joined an UNAUTHORISED access point. Investigate immediately.",
            "color":       "#7f1d1d",
            "border":      "#ef4444",
            "timestamp":   timestamp,
        }
    else:  # WARNING / QUARANTINED / unknown network
        event = {
            "type":        "warning",
            "title":       "⚠  Client Connected to Unverified Network",
            "client_name": client_name,
            "ssid":        ssid,
            "bssid":       bssid,
            "status":      status,
            "threat":      threat,
            "encryption":  encryption,
            "signal":      signal,
            "message":     f"{client_name} connected to a network that has not been verified.",
            "color":       "#78350f",
            "border":      "#f59e0b",
            "timestamp":   timestamp,
        }

    with _client_lock:
        client_events.appendleft(event)
        client_pending.append(event)

    print(f"[{timestamp}] CLIENT CONNECT → {client_name} on {status}: {ssid}")
    return jsonify({"status": "ok", "timestamp": timestamp})

# =========================
# GET /client_events
# Admin dashboard polls here. Returns all unACKed client-connection
# events then clears that queue (mirrors /get_alerts, but isolated).
# =========================

@app.route("/client_events", methods=["GET"])
def get_client_events():
    with _client_lock:
        items = list(client_pending)
        client_pending.clear()
    return jsonify(items)

# =========================
# GET /client_events_history
# Returns the last 50 client-connection events (newest first).
# =========================

@app.route("/client_events_history", methods=["GET"])
def client_events_history():
    with _client_lock:
        items = list(client_events)
    return jsonify(items)

# =========================
# GET /health
# =========================

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "running",
                    "queued": len(pending),
                    "total":  len(alert_queue),
                    "client_events_queued": len(client_pending),
                    "client_events_total":  len(client_events)})

# =========================
# RUN
# =========================

if __name__ == "__main__":
    print("Alert server running on port 5000")
    app.run(host="127.0.0.1", port=5000, debug=False)
    