"""
Industrial Network Monitoring System  (Raspberry Pi 3 + Siemens LOGO! 8.3 PLC)

How detection works (v2):
  1. PASSIVE: scapy sniffs eth0 in the background. Any ARP / IP frame from a MAC we
     have never seen = new device. A laptop plugged into the switch sends ARP within
     1-2 seconds of link-up, so it is caught almost instantly, even if its IP is in a
     completely different subnet.
  2. ACTIVE: every SWEEP_INTERVAL seconds the Pi sends one ARP "who-has" per host in
     the configured subnets (cheap: ~500 tiny packets, no subprocesses). Quiet devices
     answer, the sniffer sees the answer.
  3. A new, unauthorized device -> dashboard alert + relay/buzzer on GPIO 17.

Run:   sudo python3 app.py        (root is needed for raw packet sniffing)
Needs: sudo apt install python3-scapy tcpdump python3-gpiozero python3-lgpio python3-flask
Put index.html inside a folder named "templates" next to this file.
"""

import os
import sys
import time
import socket
import subprocess
import threading
import ipaddress
import atexit
import webbrowser
from datetime import datetime
from collections import deque
from flask import Flask, render_template, jsonify, request

try:
    from scapy.all import sniff, sendp, Ether, ARP, IP, get_if_hwaddr, get_if_addr, conf, get_if_list
except ImportError:
    sys.exit("scapy is not installed.  Run:  sudo apt install python3-scapy tcpdump")

# ==================== CONFIGURATION ====================
PLC_IP = "192.168.0.3"          # Siemens LOGO! 8.3 PLC IP
PI_IP = "172.168.74.26"         # Raspberry Pi IP
NETMASK = "255.255.255.0"       # Subnet netmask
IFACE = "eth0"                  # Interface plugged into the switch
BUZZER_PIN = 17                 # Raspberry Pi GPIO 17 (Physical Pin 11)
DEFAULT_ACTIVE_HIGH = True      # True  = NPN transistor / Active-HIGH (3.3V = ON)
                                # False = Active-LOW relay module  (0V = ON)  <- most 5V relay boards
PLC_CHECK_INTERVAL = 5          # Seconds between PLC health checks
SWEEP_INTERVAL = 5              # Seconds between active ARP sweeps
OFFLINE_AFTER = 20              # Seconds of silence before a device is shown Offline
BASELINE_SECONDS = 20           # After start, devices already on the network are auto-authorized
ALARM_SECONDS = 30              # Max time relay keeps beeping if nobody presses Silence
PORT = 5000                     # Web dashboard port
AUTO_OPEN_BROWSER = True        # Open the dashboard in the Pi's browser on start
PI_PLC_ALIAS_IP = "192.168.0.10"  # Pi's own extra address inside the PLC subnet (added to IFACE at start).
                                  # Pick a FREE address. Set "" to disable. Lost on reboot, re-added each run.
# =======================================================

app = Flask(__name__)

state_lock = threading.RLock()

devices = {}                    # ip -> device dict (shape used by index.html)
last_seen_ts = {}               # ip -> epoch seconds of last sighting
authorized_macs = set()         # hardware addresses the operator trusts
events = deque(maxlen=100)
event_counter = 0

OWN_MAC = ""
OWN_IPS = {PI_IP}
SRC_IP = PI_IP
ALIAS_IP = ""                   # set at start-up if the alias address is active
SWEEP_PACKETS = []
BASELINE_END = 0.0

monitor_state = {
    "plc_online": False,
    "plc_last_checked": "Never",
    "last_scan_time": "Never",
    "scan_engine": "Passive ARP sniffer + active ARP sweep",
    "subnets_scanned": [],
    "network_compat": {"same_subnet": False, "diagnostic": ""},
    "running": True
}


# ==================== RELAY & BUZZER CONTROLLER ====================
class HardwareBuzzer:
    """
    Drives a relay module / buzzer on a GPIO pin.
    Output is forced OFF at start-up and on exit.
    Active-HIGH / Active-LOW selectable (Invert button on dashboard).
    """
    def __init__(self, pin, active_high=True):
        self.pin = pin
        self.active_high = active_high
        self.hardware_active = False
        self.device = None
        self.status = "Idle"       # "Idle", "Beeping", "Silenced", "Test Active"
        self.is_silenced = False
        self._stop_flag = False
        self.lock = threading.Lock()
        self._init_gpio()

    def _init_gpio(self):
        try:
            if self.device:
                try:
                    self.device.off()
                    self.device.close()
                except Exception:
                    pass
            from gpiozero import OutputDevice
            self.device = OutputDevice(self.pin, active_high=self.active_high, initial_value=False)
            self.device.off()
            self.hardware_active = True
            mode_str = "Active-HIGH (0V=OFF, 3.3V=ON)" if self.active_high else "Active-LOW (3.3V=OFF, 0V=ON)"
            print(f"[Hardware] GPIO {self.pin} initialized. Mode: {mode_str}. Output: OFF")
        except Exception as e:
            self.hardware_active = False
            self.device = None
            print(f"[Simulation] GPIO running in simulation mode ({e})")

    def toggle_polarity(self):
        with self.lock:
            self.active_high = not self.active_high
            self._init_gpio()
            mode_str = "Active-HIGH" if self.active_high else "Active-LOW"
        log_event("HARDWARE", f"Relay polarity switched to {mode_str} by operator.", "info")
        return self.active_high

    def _set_output(self, on: bool):
        if self.hardware_active and self.device:
            try:
                self.device.on() if on else self.device.off()
            except Exception:
                pass
        else:
            print(f"[Simulated Output] Relay state: {'ON' if on else 'OFF'}")

    def test(self, duration=2.0):
        self.silence()
        with self.lock:
            self._stop_flag = False
            self.is_silenced = False
            self.status = "Test Active"

        def _worker():
            self._set_output(True)
            t_end = time.time() + duration
            while time.time() < t_end and not self._stop_flag:
                time.sleep(0.05)
            self._set_output(False)
            with self.lock:
                if self.status == "Test Active":
                    self.status = "Idle"

        threading.Thread(target=_worker, daemon=True).start()

    def alarm(self, max_duration=30):
        """Pulse the relay until silenced (or max_duration)."""
        with self.lock:
            if self.is_silenced or self.status == "Beeping":
                return
            self._stop_flag = False
            self.status = "Beeping"

        def _worker():
            print("[Hardware] [ALARM] New device - relay/buzzer pulsing")
            t_end = time.time() + max_duration
            while time.time() < t_end and not self._stop_flag:
                self._set_output(True)
                for _ in range(5):
                    if self._stop_flag:
                        break
                    time.sleep(0.1)
                self._set_output(False)
                for _ in range(5):
                    if self._stop_flag:
                        break
                    time.sleep(0.1)
            self._set_output(False)
            with self.lock:
                if self.status == "Beeping":
                    self.status = "Idle"

        threading.Thread(target=_worker, daemon=True).start()

    def silence(self):
        with self.lock:
            self._stop_flag = True
            self.is_silenced = True
            self.status = "Silenced"
        self._set_output(False)

    def reset_silence(self):
        with self.lock:
            self.is_silenced = False
            if self.status == "Silenced":
                self.status = "Idle"

    def cleanup(self):
        self.silence()
        if self.hardware_active and self.device:
            try:
                self.device.off()
                self.device.close()
            except Exception:
                pass
        print("[Hardware] Exiting: relay/buzzer OFF.")

    def get_status(self):
        with self.lock:
            return {
                "status": self.status,
                "is_silenced": self.is_silenced,
                "pin": self.pin,
                "hardware": self.hardware_active,
                "active_high": self.active_high,
                "mode_text": "Active-HIGH (Transistor / Standard)" if self.active_high else "Active-LOW (Relay Module)"
            }


buzzer = HardwareBuzzer(BUZZER_PIN, active_high=DEFAULT_ACTIVE_HIGH)
atexit.register(buzzer.cleanup)


# ==================== NETWORK HELPERS ====================
def get_configured_subnets():
    """Pi subnet + PLC subnet (deduplicated)."""
    subnets = []
    for ip in (PI_IP, PLC_IP):
        try:
            net = str(ipaddress.IPv4Network(f"{ip}/{NETMASK}", strict=False))
            if net not in subnets:
                subnets.append(net)
        except Exception:
            pass
    return subnets


def check_network_compatibility(pi_ip, plc_ip, netmask):
    """Warn if Pi and PLC are in different subnets. Never changes IPs automatically."""
    try:
        pi_network = ipaddress.IPv4Network(f"{pi_ip}/{netmask}", strict=False)
        same_subnet = ipaddress.IPv4Address(plc_ip) in pi_network
        if same_subnet:
            diagnostic = f"Both IPs belong to the same subnet ({pi_network})."
        else:
            diagnostic = (
                f"Subnet Mismatch: Pi ({pi_ip}) and PLC ({plc_ip}) are in different subnets. "
                f"New-device detection still works (it is MAC/ARP based), but the PLC health check "
                f"needs a secondary IP on the Pi, e.g. 'sudo ip addr add 192.168.0.10/24 dev {IFACE}'."
            )
        return {"same_subnet": same_subnet, "diagnostic": diagnostic}
    except Exception as e:
        return {"same_subnet": False, "diagnostic": f"IP validation error: {e}"}


def ping_host(ip, timeout_ms=300):
    is_win = sys.platform.startswith("win")
    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.2).returncode == 0
    except Exception:
        return False


def check_plc_port_102(ip):
    """TCP check on port 102 (Siemens S7 / ISO-on-TCP)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    try:
        return s.connect_ex((ip, 102)) == 0
    except Exception:
        return False
    finally:
        s.close()


def is_plc_online(plc_ip):
    return ping_host(plc_ip, timeout_ms=500) or check_plc_port_102(plc_ip)


def lookup_vendor(mac):
    """Best-effort manufacturer name from the MAC prefix (Dell, Intel, ...)."""
    try:
        v = conf.manufdb._get_manuf(mac)
        return "" if (not v or v.lower() == mac.lower()) else str(v)
    except Exception:
        return ""


def baseline_active():
    return time.time() < BASELINE_END


# ==================== EVENT LOG ====================
def log_event(event_type, message, severity="info"):
    global event_counter
    with state_lock:
        event_counter += 1
        events.appendleft({
            "id": event_counter,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "message": message,
            "severity": severity
        })
    print(f"[{severity.upper()}] {message}")


# ==================== DEVICE REGISTRY ====================
def init_known_devices():
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices[PLC_IP] = {
        "ip": PLC_IP, "mac": "00:1C:06:XX:XX:XX", "name": "Siemens LOGO! 8.3 PLC",
        "authorized": True, "status": "offline", "last_seen": now
    }
    devices[PI_IP] = {
        "ip": PI_IP, "mac": OWN_MAC, "name": "Raspberry Pi (Host)",
        "authorized": True, "status": "online", "last_seen": now
    }
    authorized_macs.add(OWN_MAC)
    log_event("SYSTEM", f"Industrial Monitor started. Pi: {PI_IP}, PLC: {PLC_IP}, interface: {IFACE}")
    log_event("SYSTEM", f"Learning mode for {BASELINE_SECONDS}s: devices already connected are auto-authorized.")


def register_sighting(ip, mac):
    """Called for every frame that tells us 'IP x is on MAC y'. This is the heart of detection."""
    mac = mac.lower()
    try:
        if int(mac[:2], 16) & 1:                       # multicast / broadcast source: ignore
            return
    except ValueError:
        return
    if mac == OWN_MAC or mac == "00:00:00:00:00:00" or ip in OWN_IPS:
        return

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    raise_alarm = False
    last_octet = ip.split(".")[-1]

    with state_lock:
        dev = devices.get(ip)

        if dev is None:
            # ---- never seen this IP before ----
            known = (mac in authorized_macs) or baseline_active()
            vendor = lookup_vendor(mac)
            name = f"{'Device' if known else 'New-Device'}-{last_octet}" + (f" ({vendor})" if vendor else "")
            # same hardware, new IP (DHCP change) -> replace the old row
            for old_ip, old in list(devices.items()):
                if old["mac"] == mac and old_ip not in (PI_IP, PLC_IP):
                    del devices[old_ip]
                    last_seen_ts.pop(old_ip, None)
            devices[ip] = {
                "ip": ip, "mac": mac, "name": name,
                "authorized": known, "status": "online", "last_seen": now_str
            }
            if known:
                authorized_macs.add(mac)
                log_event("BASELINE" if baseline_active() else "KNOWN_DEVICE",
                          f"Known device on network: {ip} ({mac})", "info")
            else:
                log_event("NEW_DEVICE", f"NEW DEVICE CONNECTED: {ip} ({mac}) {vendor}".strip(), "critical")
                raise_alarm = True
        else:
            # ---- IP already in table ----
            if "x" in dev["mac"].lower():
                # placeholder MAC (e.g. PLC): learn the real one
                dev["mac"] = mac
                if dev["authorized"]:
                    authorized_macs.add(mac)
            elif dev["mac"] != mac:
                if mac in authorized_macs:
                    dev["mac"] = mac
                else:
                    # different hardware answering for a known IP: spoof / IP conflict / swapped device
                    dev["mac"] = mac
                    dev["authorized"] = False
                    dev["name"] = f"IP-Conflict-{last_octet}"
                    log_event("IP_CONFLICT", f"IP {ip} is now answered by unknown hardware {mac}!", "critical")
                    raise_alarm = True

            if ip not in (PI_IP, PLC_IP):               # PLC/Pi status handled by health check
                if dev["status"] == "offline" and not dev["authorized"]:
                    log_event("NEW_DEVICE", f"Unauthorized device reconnected: {ip} ({mac})", "critical")
                    raise_alarm = True
                dev["status"] = "online"
            dev["last_seen"] = now_str

        last_seen_ts[ip] = time.time()

    if raise_alarm:
        buzzer.reset_silence()                           # a NEW intruder must ring even after an earlier Silence
        buzzer.alarm(max_duration=ALARM_SECONDS)


def expire_devices():
    """Mark devices Offline when they have been silent for OFFLINE_AFTER seconds."""
    now = time.time()
    with state_lock:
        for ip, dev in devices.items():
            if ip in (PI_IP, PLC_IP):
                continue
            if dev["status"] == "online" and now - last_seen_ts.get(ip, 0) > OFFLINE_AFTER:
                dev["status"] = "offline"
                log_event("DEVICE_OFFLINE", f"Device disconnected: {ip} ({dev['name']})", "info")


def refresh_alarm_state():
    """Stop the relay once no unauthorized device is online any more."""
    with state_lock:
        active_unauth = any((not d["authorized"]) and d["status"] == "online" for d in devices.values())
    if not active_unauth and buzzer.status in ("Beeping", "Silenced"):
        buzzer.silence()
        buzzer.reset_silence()


# ==================== SNIFFER + ARP SWEEP ====================
def on_packet(pkt):
    try:
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            if a.op in (1, 2) and a.psrc and a.psrc != "0.0.0.0":
                register_sighting(a.psrc, a.hwsrc)
        elif pkt.haslayer(IP) and pkt.haslayer(Ether):
            register_sighting(pkt[IP].src, pkt[Ether].src)
    except Exception as e:
        print(f"[Sniffer] packet error: {e}")


def sniffer_worker():
    subnets = get_configured_subnets()
    bpf = "arp or (ip and (" + " or ".join(f"src net {n}" for n in subnets) + "))"
    while monitor_state.get("running", True):
        try:
            print(f"[Sniffer] Listening on {IFACE}  filter: {bpf}")
            sniff(iface=IFACE, filter=bpf, prn=on_packet, store=False)
        except Exception as e:
            log_event("SYSTEM", f"Sniffer error: {e} (restarting in 3s)", "warning")
            time.sleep(3)


def build_sweep_packets():
    pkts = []
    for subnet in get_configured_subnets():
        for h in ipaddress.IPv4Network(subnet).hosts():
            ip = str(h)
            if ip in OWN_IPS:
                continue
            src = SRC_IP
            if ALIAS_IP and ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(f"{ALIAS_IP}/{NETMASK}", strict=False):
                src = ALIAS_IP                          # ask the PLC subnet from an address inside it
            pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, psrc=src, pdst=ip))
    return pkts


def arp_sweep():
    """Broadcast ARP who-has for every host. Replies are picked up by the sniffer."""
    sendp(SWEEP_PACKETS, iface=IFACE, inter=0.002, verbose=False)
    monitor_state["last_scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ==================== BACKGROUND MONITOR THREAD ====================
def background_worker():
    compat = check_network_compatibility(PI_IP, PLC_IP, NETMASK)
    monitor_state["network_compat"] = compat
    monitor_state["subnets_scanned"] = get_configured_subnets()
    if not compat["same_subnet"]:
        log_event("SUBNET_MISMATCH", compat["diagnostic"], "warning")

    last_plc = 0.0
    last_sweep = 0.0

    while monitor_state.get("running", True):
        now = time.time()

        if now - last_plc >= PLC_CHECK_INTERVAL:
            last_plc = now
            online = is_plc_online(PLC_IP)
            prev = monitor_state["plc_online"]
            monitor_state["plc_online"] = online
            monitor_state["plc_last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with state_lock:
                devices[PLC_IP]["status"] = "online" if online else "offline"
                if online:
                    devices[PLC_IP]["last_seen"] = monitor_state["plc_last_checked"]
            if prev != online:
                log_event("PLC_STATUS",
                          f"Siemens LOGO! 8.3 PLC ({PLC_IP}) is now {'ONLINE' if online else 'OFFLINE'}",
                          "info" if online else "critical")

        if now - last_sweep >= SWEEP_INTERVAL:
            last_sweep = now
            try:
                arp_sweep()
                expire_devices()
                refresh_alarm_state()
            except Exception as e:
                print(f"[Error] Sweep loop: {e}")

        time.sleep(0.5)


# ==================== FLASK API ROUTES ====================
@app.route("/")
def index():
    return render_template("index.html", pi_ip=PI_IP, plc_ip=PLC_IP)


@app.route("/api/devices")
def api_devices():
    with state_lock:
        return jsonify({"success": True, "devices": list(devices.values())})


@app.route("/api/status")
def api_status():
    with state_lock:
        dev_list = list(devices.values())
        unauthorized = [d for d in dev_list if not d["authorized"] and d["status"] == "online"]
        evt_list = list(events)

    return jsonify({
        "pi": {"ip": PI_IP, "status": "Online"},
        "plc": {
            "ip": PLC_IP,
            "online": monitor_state["plc_online"],
            "last_checked": monitor_state["plc_last_checked"]
        },
        "network_compat": monitor_state["network_compat"],
        "buzzer": buzzer.get_status(),
        "last_scan": monitor_state["last_scan_time"],
        "scan_engine": monitor_state["scan_engine"],
        "subnets_scanned": monitor_state["subnets_scanned"],
        "unauthorized": unauthorized,
        "devices": dev_list,
        "events": evt_list
    })


@app.route("/api/buzzer/test", methods=["POST"])
def api_buzzer_test():
    buzzer.test(duration=2.0)
    log_event("BUZZER_TEST", "Operator clicked Test Relay: relay ON for 2s.", "info")
    return jsonify({"success": True})


@app.route("/api/buzzer/silence", methods=["POST"])
def api_buzzer_silence():
    buzzer.silence()
    log_event("BUZZER_SILENCE", "Operator clicked Silence: relay OFF.", "warning")
    return jsonify({"success": True})


@app.route("/api/buzzer/toggle_mode", methods=["POST"])
def api_buzzer_toggle_mode():
    new_active_high = buzzer.toggle_polarity()
    mode = "Active-HIGH (Transistor / Standard)" if new_active_high else "Active-LOW (Relay Module)"
    return jsonify({"success": True, "active_high": new_active_high, "mode_text": mode})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """On-demand ARP sweep."""
    try:
        arp_sweep()
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    with state_lock:
        count = sum(1 for d in devices.values() if d["status"] == "online")
    return jsonify({"success": True, "count": count,
                    "engine": monitor_state["scan_engine"], "subnets": monitor_state["subnets_scanned"]})


@app.route("/api/authorize", methods=["POST"])
def api_authorize():
    data = request.get_json() or {}
    ip = data.get("ip")
    with state_lock:
        if ip in devices:
            devices[ip]["authorized"] = True
            if "x" not in devices[ip]["mac"].lower():
                authorized_macs.add(devices[ip]["mac"].lower())
            log_event("DEVICE_AUTH", f"Device {ip} authorized by operator.", "info")
    refresh_alarm_state()
    return jsonify({"success": True})


@app.route("/api/device/delete", methods=["POST"])
def api_device_delete():
    data = request.get_json() or {}
    ip = data.get("ip")
    if ip in (PI_IP, PLC_IP):
        return jsonify({"success": False, "error": "Cannot delete host or PLC"}), 400
    with state_lock:
        dev = devices.pop(ip, None)
        last_seen_ts.pop(ip, None)
        if dev:
            authorized_macs.discard(dev["mac"].lower())      # forgotten: alarm again if it returns
            log_event("DEVICE_REMOVED", f"Device {ip} removed by operator.", "info")
    return jsonify({"success": True})


@app.route("/api/simulate/unknown", methods=["POST"])
def api_simulate_unknown():
    """Fake rogue device to test dashboard + relay without a laptop."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sim_ip = f"{SRC_IP.rsplit('.', 1)[0]}.{int(time.time()) % 150 + 100}"
    sim_mac = "aa:bb:cc:11:22:33"
    with state_lock:
        devices[sim_ip] = {
            "ip": sim_ip, "mac": sim_mac, "name": "Simulated Rogue Device",
            "authorized": False, "status": "online", "last_seen": now
        }
        last_seen_ts[sim_ip] = time.time() + 3600           # keep it 'online' for the demo
    log_event("NEW_DEVICE", f"SIMULATED NEW DEVICE: {sim_ip} ({sim_mac})", "critical")
    buzzer.reset_silence()
    buzzer.alarm(max_duration=ALARM_SECONDS)
    return jsonify({"success": True, "ip": sim_ip})


# ==================== STARTUP ====================
def open_dashboard_browser():
    url = f"http://localhost:{PORT}"
    try:
        sudo_user = os.environ.get("SUDO_USER")
        if sudo_user:
            # script runs as root (needed for sniffing) but a browser must run as the desktop user
            subprocess.Popen(["sudo", "-u", sudo_user, "env", "DISPLAY=:0", "xdg-open", url],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(url)
    except Exception as e:
        print(f"[Info] Could not auto-open browser ({e}). Open {url} manually.")


def ensure_plc_alias():
    """If the PLC is in another subnet than the Pi, give the Pi a second address in the PLC subnet
    (same as: sudo ip addr add 192.168.0.10/24 dev eth0). Without it the Pi cannot reach the PLC."""
    global ALIAS_IP
    if not PI_PLC_ALIAS_IP:
        return
    try:
        if ipaddress.IPv4Address(PLC_IP) in ipaddress.IPv4Network(f"{PI_IP}/{NETMASK}", strict=False):
            return                                      # same subnet already, nothing to add
        prefix = ipaddress.IPv4Network(f"0.0.0.0/{NETMASK}").prefixlen
        shown = subprocess.run(["ip", "-4", "addr", "show", "dev", IFACE],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=3).stdout
        if f"inet {PI_PLC_ALIAS_IP}/" not in shown:
            res = subprocess.run(["ip", "addr", "add", f"{PI_PLC_ALIAS_IP}/{prefix}", "dev", IFACE],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=3)
            if res.returncode != 0:
                print(f"[Warning] Could not add alias {PI_PLC_ALIAS_IP}: {res.stderr.strip()}")
                return
            print(f"[Network] Added {PI_PLC_ALIAS_IP}/{prefix} to {IFACE} so the Pi can reach the PLC")
        ALIAS_IP = PI_PLC_ALIAS_IP
        OWN_IPS.add(ALIAS_IP)
    except Exception as e:
        print(f"[Warning] PLC alias setup failed: {e}")


def init_network_identity():
    global OWN_MAC, SRC_IP, SWEEP_PACKETS, BASELINE_END
    ensure_plc_alias()
    if IFACE not in get_if_list():
        sys.exit(f"Interface '{IFACE}' not found. Available: {', '.join(get_if_list())}  -> edit IFACE in app.py")
    OWN_MAC = get_if_hwaddr(IFACE).lower()
    try:
        iface_ip = get_if_addr(IFACE)
        if iface_ip and iface_ip != "0.0.0.0":
            OWN_IPS.add(iface_ip)
            SRC_IP = iface_ip
    except Exception:
        pass
    SWEEP_PACKETS = build_sweep_packets()
    BASELINE_END = time.time() + BASELINE_SECONDS


if __name__ == "__main__":
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("Packet sniffing needs root.  Run:  sudo python3 app.py")

    init_network_identity()
    init_known_devices()

    print("============================================================")
    print(" Industrial Network Monitoring System")
    print(f" Interface:        {IFACE}  (MAC {OWN_MAC})")
    print(f" Siemens PLC IP:   {PLC_IP}")
    print(f" Raspberry Pi IP:  {PI_IP}")
    print(f" Scan Subnets:     {', '.join(get_configured_subnets())}")
    print(f" Relay/Buzzer:     GPIO {BUZZER_PIN}")
    print(f" Dashboard URL:    http://{PI_IP}:{PORT}   (from your laptop)")
    print(f" Learning mode:    {BASELINE_SECONDS}s - connect the laptop AFTER this")
    print("============================================================")

    threading.Thread(target=sniffer_worker, daemon=True).start()
    threading.Thread(target=background_worker, daemon=True).start()
    if AUTO_OPEN_BROWSER:
        threading.Timer(2.0, open_dashboard_browser).start()
    try:
        app.run(host="0.0.0.0", port=PORT, debug=False)
    finally:
        buzzer.cleanup()
