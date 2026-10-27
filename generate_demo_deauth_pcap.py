"""
generate_demo_deauth_pcap.py

Builds a small .pcap FILE containing synthetic 802.11 deauthentication
frames aimed at a fake test BSSID. Nothing here transmits over the air or
touches a real network interface - it only constructs packet objects in
memory using Scapy and writes them to a local file with wrpcap().

Purpose: your dashboard's deauth-flood detector (_handle_deauth in
dashboard_gui.py) needs monitor-mode Wi-Fi hardware to capture real deauth
frames live, which most Windows adapters don't support. This script lets
you demonstrate that detection logic is real and working by replaying a
saved capture through the exact same code path, instead of skipping the
demo entirely.

Usage:
    python generate_demo_deauth_pcap.py

Then run the dashboard with:
    set DEAUTH_PCAP_REPLAY=demo_deauth.pcap        (Windows cmd)
    $env:DEAUTH_PCAP_REPLAY="demo_deauth.pcap"     (PowerShell)
    python dashboard_gui.py

Watch: within ~10 seconds of the replay starting, the target BSSID below
should escalate to SUSPICIOUS/HIGH in the dashboard and trigger an alert -
demonstrating the deauth-flood detector without needing monitor-mode
hardware.
"""

from scapy.all import Dot11, Dot11Deauth, RadioTap, wrpcap
import time

# A fake BSSID standing in for "the AP under attack" in this demo.
# Doesn't need to be a real device - it's just a MAC-shaped identifier the
# detector will key its per-AP counter on.
TARGET_BSSID = "aa:bb:cc:dd:ee:ff"
CLIENT_MAC   = "11:22:33:44:55:66"

# Needs to clear DEAUTH_THRESHOLD (10) within DEAUTH_WINDOW_S (10s) in
# dashboard_gui.py - 15 frames gives comfortable headroom.
NUM_FRAMES = 15

packets = []
for i in range(NUM_FRAMES):
    frame = (
        RadioTap() /
        Dot11(
            type=0, subtype=12,          # management frame, deauth subtype
            addr1=CLIENT_MAC,             # destination: the client being kicked
            addr2=TARGET_BSSID,           # source: the AP (or attacker spoofing it)
            addr3=TARGET_BSSID,
        ) /
        Dot11Deauth(reason=7)             # reason code 7: "class 3 frame from nonassociated station"
    )
    packets.append(frame)

wrpcap("demo_deauth.pcap", packets)
print(f"Wrote {NUM_FRAMES} synthetic deauth frames targeting {TARGET_BSSID} to demo_deauth.pcap")
print("This file was never transmitted - it's a local test fixture only.")