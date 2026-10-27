"""
alert_sender.py — Rogue AP Detection System
Drop-in helper called by dashboard_gui.py and main.py after every scan.
Sends a typed alert to alert_server.py for broadcast to all user clients.
"""

import os
import requests
import logging

ALERT_SERVER = os.environ.get("ALERT_SERVER_URL", "http://127.0.0.1:5050")
ALERT_SECRET = os.environ.get("ALERT_SECRET",     "changeme-secret-123")

log = logging.getLogger(__name__)


def send_alert(alert_type: str, ssid: str, bssid: str,
               message: str, signal: int | None = None,
               encryption: str | None = None) -> bool:
    """
    Send a typed alert to the alert server.

    alert_type : "SAFE" | "ROGUE" | "WARNING"
    ssid       : network name
    bssid      : MAC address
    message    : human-readable description shown in the popup
    signal     : dBm signal strength (optional)
    encryption : e.g. "WPA2", "OPEN" (optional)

    Returns True on success, False on any error.
    """
    payload = {
        "type":    alert_type.upper(),
        "ssid":    ssid,
        "bssid":   bssid,
        "message": message,
    }
    if signal is not None:
        payload["signal"] = signal
    if encryption is not None:
        payload["encryption"] = encryption

    try:
        resp = requests.post(
            f"{ALERT_SERVER}/send_alert",
            json=payload,
            headers={"X-Alert-Secret": ALERT_SECRET},
            timeout=3,
        )
        resp.raise_for_status()
        return True
    except requests.RequestException as exc:
        log.warning("Alert server unreachable — %s", exc)
        return False


# ── Convenience wrappers ───────────────────────────────────────────────────────

def alert_rogue(ssid: str, bssid: str, trusted_bssid: str,
                signal: int | None = None, encryption: str | None = None) -> bool:
    msg = (
        f"Evil twin attack detected! '{ssid}' is broadcasting with BSSID {bssid} "
        f"instead of the trusted {trusted_bssid}. Do NOT connect."
    )
    return send_alert("ROGUE", ssid, bssid, msg, signal, encryption)


def alert_safe(ssid: str, bssid: str,
               signal: int | None = None, encryption: str | None = None) -> bool:
    msg = f"'{ssid}' is verified as the legitimate access point. Safe to connect."
    return send_alert("SAFE", ssid, bssid, msg, signal, encryption)


def alert_unknown(ssid: str, bssid: str,
                  signal: int | None = None, encryption: str | None = None) -> bool:
    enc_note = f"Encryption: {encryption}." if encryption else "Encryption unknown."
    msg = (
        f"Unrecognised access point '{ssid}' ({bssid}) detected nearby. "
        f"{enc_note} Treat with caution."
    )
    return send_alert("WARNING", ssid, bssid, msg, signal, encryption)