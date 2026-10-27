def detect_rogue(scanned_ap, known_aps):
    match = known_aps.get(scanned_ap["bssid"])
    if not match:
        # check for evil twin: known SSID, unknown BSSID
        for k in known_aps.values():
            if k["ssid"] == scanned_ap["ssid"]:
                return {"rogue": True, "reason": "SSID spoof / evil twin"}
        return {"rogue": True, "reason": "Unknown BSSID"}
    if match["encryption"] != scanned_ap["akm"]:
        return {"rogue": True, "reason": "Encryption downgrade"}
    return {"rogue": False, "reason": None}