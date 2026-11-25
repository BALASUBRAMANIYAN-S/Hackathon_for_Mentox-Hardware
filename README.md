# Mentox Hackathon: OT Network Intrusion Detector

Hackathon project for the problem statement **MX26-CSI-02: OT Network Intrusion Detector** (the problem PDF is included in `Mentrox/`). The goal is to detect rogue or unauthorised devices on a network and raise an alert.

The repository has two parts.

| Folder | What it is | Runs on |
|---|---|---|
| [`pi/`](pi) | **Industrial Network Monitor**: watches an industrial network that includes a Siemens LOGO! 8.3 PLC and sounds an alarm when a new device appears | Raspberry Pi 3 |
| [`Mentrox/`](Mentrox) | **NetSentinel**: scans the local network, checks devices against a MySQL whitelist, sends email alerts and can block a rogue IP in Windows Firewall | Windows PC |

## 1. Industrial Network Monitor (`pi/`)

### How it works

1. **Passive detection:** Scapy listens on the Ethernet interface. Any ARP or IP frame from a MAC address it has not seen before counts as a new device.
2. **Active detection:** every few seconds the Pi sends ARP requests across the configured subnets to find quiet devices.
3. **Alarm:** a new, unauthorised device triggers a dashboard alert and a relay or buzzer on **GPIO 17**.
4. **PLC health check:** the Siemens LOGO! PLC is checked regularly and shown as online or offline.
5. **Web dashboard** built with Flask (default port 5000) to view devices, authorise them, test or silence the buzzer, and trigger a manual scan.

### Hardware

- Raspberry Pi 3
- Siemens LOGO! 8.3 PLC and a network switch
- Relay module or buzzer on GPIO 17 (physical pin 11)

### Setup

```bash
sudo apt install python3-scapy tcpdump python3-gpiozero python3-lgpio python3-flask
cd pi
sudo python3 app.py        # root is needed for raw packet sniffing
```

Edit the settings at the top of `pi/app.py` first:

- `PLC_IP`, `PI_IP`, `NETMASK`, `IFACE`
- `BUZZER_PIN` and `DEFAULT_ACTIVE_HIGH` (match your relay type)
- `PORT`, `SWEEP_INTERVAL`, `BASELINE_SECONDS`

To start on boot, use the included `industrial-monitor.service` (systemd). `OLDapp.py` is the earlier version.

## 2. NetSentinel (`Mentrox/`)

NetSentinel scans your Wi-Fi or Ethernet network and compares what it finds with a list of authorised IPs.

- Network scanner (IP, MAC and device name)
- MySQL whitelist of authorised IPs
- Continuous background monitoring
- Warning for any IP that is not in the whitelist
- Email alerts through SMTP (Gmail App Password)
- One-click blocking of a rogue IP in Windows Firewall

See [`Mentrox/README.md`](Mentrox/README.md) for the full setup guide (`.env` settings, Gmail App Password and how to run). Run the app as administrator (see `start_admin.bat`) so firewall blocking works.

## Tech Stack

Python, Flask, Scapy, gpiozero, MySQL, SMTP, HTML/CSS/JavaScript

## Important

- Never commit your `.env` file, database passwords or email app passwords. Use a `.env.example` with empty values instead.
- Only scan and block devices on networks you own or are authorised to manage.
