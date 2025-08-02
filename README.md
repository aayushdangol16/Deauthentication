# Wi-Fi Deauthentication Tool (2.4 GHz)

This Python script uses **Scapy** to scan Wi-Fi networks on the 2.4 GHz band (channels 1-14) and perform broadcast deauthentication attacks against a selected target network. It hops channels to discover networks and allows you to disconnect all clients from a chosen Wi-Fi Access Point (AP).

---

## Features

- Scans Wi-Fi networks on 2.4 GHz channels (1-14)  
- Displays SSID, BSSID, and channel for discovered networks  
- Allows selecting a network to perform broadcast deauthentication  
- Uses channel hopping for full area coverage  

---

## Installation

### Prerequisites

- Linux system with wireless card supporting **monitor mode** on 2.4 GHz band  
- Python 3.x installed  
- `iw` tool installed (for changing Wi-Fi channels)  
- Wireless drivers supporting packet injection  

### Step-by-step

1. Clone the repository 
```bash
git clone https://github.com/paceacem/Deauthentication.git
```

2. Install dependencies using `requirements.txt`:

```bash
pip3 install -r requirements.txt
```

3. Put your wireless interface into monitor mode. Replace `wlan0` with your wireless device name:

```bash
sudo ip link set wlan0 down
sudo iw dev wlan0 set type monitor
sudo ip link set wlan0 up
```

Alternatively, use `airmon-ng`:

```bash
sudo airmon-ng start wlan0
```

This creates a monitor mode interface like `wlan0mon`.

---

## Usage

Run the script with root privileges and specify your monitor interface:

```bash
sudo python3 deauth_tool.py <monitor_interface>
```

Example:

```bash
sudo python3 deauth_tool.py wlan0mon
```

### How it works

- The tool scans all 2.4 GHz Wi-Fi channels (1-14).  
- Lists discovered networks with index numbers and SSIDs.  
- You select a network to deauthenticate by entering its index.  
- The tool switches to that network’s channel and sends broadcast deauth packets continuously.  
- Press `Ctrl+C` to stop scanning or the attack.

---

## Why Does This Tool Not Work on 5 GHz Wi-Fi Bands?

- **Channel Range:** The script only scans channels 1-14 (2.4 GHz). 5 GHz channels (e.g., 36, 40, 44) are not scanned.  
- **Hardware Support:** Many Wi-Fi cards don’t support monitor mode or injection on 5 GHz frequencies.  
- **Regulatory and Driver Limitations:** 5 GHz requires Dynamic Frequency Selection (DFS) and obeys strict regulations, making injection complex.  
- **Implementation:** Supporting 5 GHz requires hardware support and modifying the script to scan 5 GHz channels.

---

## Disclaimer

**Use this tool responsibly and legally.** Only test on networks you own or have explicit permission to test. Unauthorized deauthentication attacks are illegal.

---

## License

This project is provided "as-is" without warranty. Use at your own risk.

---

## Contact

For questions or suggestions, please open an issue or contact the author.
