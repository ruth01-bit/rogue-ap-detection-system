from flask import Flask, render_template, jsonify
import psycopg2
import pywifi
import time

app = Flask(__name__)

# =========================
# DATABASE CONNECTION
# =========================

conn = psycopg2.connect(
    host="localhost",
    database="RogueAPDetection",
    user="postgres",
    password="admin123"
)

cursor = conn.cursor()

# =========================
# TRUSTED ACCESS POINTS
# =========================

trusted_ap = {
    "Safaricom_B320_8F84": "22:10:e6:84:8f:17"
}

# =========================
# HOME PAGE
# =========================

@app.route("/")
def index():

    return render_template("index.html")

# =========================
# GET ACCESS POINTS
# =========================

@app.route("/get_access_points")
def get_access_points():

    cursor.execute("""
    SELECT
    ssid,
    bssid,
    signal_strength,
    encryption_type,
    status,
    threat_level

    FROM access_points
    """)

    rows = cursor.fetchall()

    aps = []

    for row in rows:

        aps.append({
            "ssid": row[0],
            "bssid": row[1],
            "signal": row[2],
            "encryption": row[3],
            "status": row[4],
            "threat": row[5]
        })

    return jsonify(aps)

# =========================
# SCAN NETWORKS
# =========================

@app.route("/scan")
def scan():

    wifi = pywifi.PyWiFi()

    iface = wifi.interfaces()[0]

    iface.scan()

    time.sleep(5)

    results = iface.scan_results()

    for network in results:

        ssid = network.ssid

        bssid = network.bssid.lower().strip().rstrip(":")

        signal = network.signal

        if network.akm:
            encryption = "WPA/WPA2"
        else:
            encryption = "OPEN"

        status = "SAFE"

        threat_level = "LOW"

        # ROGUE AP DETECTION

        if ssid in trusted_ap:

            if trusted_ap[ssid] != bssid:

                status = "SUSPICIOUS"

                threat_level = "HIGH"

        elif encryption == "OPEN":

            status = "WARNING"

            threat_level = "MEDIUM"

        # SAVE TO DATABASE

        cursor.execute("""
        INSERT INTO access_points
        (
        ssid,
        bssid,
        signal_strength,
        encryption_type,
        status,
        threat_level,
        admin_decision
        )

        VALUES (%s,%s,%s,%s,%s,%s,%s)

        ON CONFLICT (bssid)
        DO UPDATE SET

        signal_strength = EXCLUDED.signal_strength,
        status = EXCLUDED.status,
        threat_level = EXCLUDED.threat_level
        """,
        (
            ssid,
            bssid,
            signal,
            encryption,
            status,
            threat_level,
            "PENDING"
        ))

        conn.commit()

    return jsonify({
        "message": "Scan complete"
    })

# =========================
# RUN APP
# =========================

if __name__ == "__main__":

    app.run(
        debug=True
    )
