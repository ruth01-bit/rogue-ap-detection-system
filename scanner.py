import pywifi
import time

wifi = pywifi.PyWiFi()

iface = wifi.interfaces()[0]

iface.scan()

time.sleep(5)

results = iface.scan_results()


for network in results:

    print("SSID:", network.ssid)
    print("BSSID:", network.bssid)
    print("Signal:", network.signal)

    print("--------------------------------")
   if network.akm:
    encryption = "WPA/WPA2"
else:
    encryption = "OPEN"

print("Encryption:", encryption)
 