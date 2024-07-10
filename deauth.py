import pywifi

def scan_wifi():
    wifi=pywifi.PyWiFi()
    iface=wifi.interfaces()[0]
    iface.scan()
    scan_results = iface.scan_results()
    for network in scan_results:
        print(f"SSID:{network.ssid},BSSID:{network.bssid}")

scan_wifi()

