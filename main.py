import pywifi
import psycopg2
import time
import tkinter as tk
from tkinter import messagebox

conn = psycopg2.connect(
    host="localhost",
    database="RogueAPDetection",
    user="postgres",
    password="admin123"
)

cursor = conn.cursor()
root = tk.Tk()
root.withdraw()
trusted_ap = {
    "Safaricom_B320_8F84": "22:10:e6:84:8f:17"
}
wifi = pywifi.PyWiFi()

iface = wifi.interfaces()[0]

iface.scan()

time.sleep(5)

results = iface.scan_results()
for network in results:

    ssid = network.ssid
    bssid = network.bssid
    signal = network.signal

    # CHECK ENCRYPTION
    if network.akm:
        encryption = "WPA/WPA2"
    else:
        encryption = "OPEN"

    # DEFAULT STATUS
    status = "SAFE"

    # DETECTION RULE 1
    # Same SSID but different BSSID

    if ssid in trusted_ap:

        if trusted_ap[ssid].lower() != bssid.lower():

            status = "SUSPICIOUS"

            print("\n⚠ ROGUE ACCESS POINT DETECTED")
            print("SSID:", ssid)
            print("BSSID:", bssid)
            print("Reason: Duplicate SSID detected")
            messagebox.showwarning(
    "Rogue AP Alert",
    f"⚠ Suspicious Access Point Detected!\n\nSSID: {ssid}\n\nDo NOT connect to this network."
)

    # DETECTION RULE 2
    # Open Network

    elif encryption == "OPEN":

        status = "WARNING"

        print("\n⚠ OPEN NETWORK DETECTED")
        print("SSID:", ssid)

    else:

        print("\n✅ SAFE NETWORK")
        print("SSID:", ssid)

    # SHOW STATUS
    print("Status:", status)

    print("--------------------------------")
    # SAVE ACCESS POINT TO DATABASE

cursor.execute("""
INSERT INTO access_points
(ssid, bssid, signal_strength,
encryption_type, status)

VALUES (%s, %s, %s, %s, %s)

ON CONFLICT (bssid)
DO NOTHING
""",
(
    ssid,
    bssid,
    signal,
    encryption,
    status
))

conn.commit()

# SAVE DETECTION LOG

cursor.execute("""
INSERT INTO detection_logs
(detection_status, ssid)

VALUES (%s, %s)
""",
(
    status,
    ssid
))

conn.commit()