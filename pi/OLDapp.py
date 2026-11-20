"""
Industrial Network Monitoring System
Simple, ultra-lightweight monitor for Raspberry Pi & Siemens LOGO! 8.3 PLC.
No database required - runs entirely in memory for minimum CPU and RAM usage.
"""

import os
import sys
import time
import socket
import subprocess
import threading
import ipaddress
import re
import atexit
from datetime import datetime
from collections import deque
from flask import Flask, render_template, jsonify, request

# ==================== CONFIGURATION ====================
PLC_IP = "192.168.0.3"          # Siemens LOGO! 8.3 PLC IP
PI_IP = "172.168.74.26"         # Raspberry Pi IP
NETMASK = "255.255.255.0"       # Subnet netmask
BUZZER_PIN = 17                 # Raspberry Pi GPIO 17 (Physical Pin 11)
DEFAULT_ACTIVE_HIGH = True      # True = NPN Transistor / Active-HIGH (0V=OFF, 3.3V=ON)
                                # False = Active-LOW Relay Module (3.3V=OFF, 0V=ON)
PLC_CHECK_INTERVAL = 10         # Seconds between PLC pings
SCAN_INTERVAL = 15              # Seconds between network device scans
PORT = 5000                     # Web dashboard port
# =======================================================

app = Flask(__name__)

# Lock for thread-safe in-memory state (RLock allows re-entrant calls)
state_lock = threading.RLock()

# In-memory storage (Zero database overhead)
devices = {}
events = deque(maxlen=100)
event_counter = 0

# Flag to record network baseline at startup without triggering alarm
is_baseline_recorded = False

# Monitoring state
monitor_state = {
    "plc_online": False,
    "plc_last_checked": "Never",
    "last_scan_time": "Never",
    "network_compat": {"same_subnet": False, "diagnostic": ""},
    "running": True
}

# ==================== RELAY & BUZZER CONTROLLER ====================
class HardwareBuzzer:
    """
    Manages 5V Relay Module or NPN Transistor Buzzer via GPIO 17.
    Ensures Relay/Buzzer is strictly OFF when script starts and when script stops.
    Supports switching between Active-HIGH and Active-LOW modes.
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
        """Initialize or re-initialize GPIO with correct polarity."""
        try:
            if self.device:
                try:
                    self.device.off()
                    self.device.close()
                except Exception:
                    pass

            from gpiozero import OutputDevice
            # active_high=True:  off()=0V (LOW),   on()=3.3V (HIGH) -> For NPN Transistor / Active-HIGH relay
            # active_high=False: off()=3.3V (HIGH), on()=0V (LOW)   -> For Active-LOW relay
            self.device = OutputDevice(
                self.pin,
                active_high=self.active_high,
                initial_value=False
            )
            # Force output to OFF immediately at startup
            self.device.off()
            self.hardware_active = True
            mode_str = "Active-HIGH (0V=OFF, 3.3V=ON)" if self.active_high else "Active-LOW (3.3V=OFF, 0V=ON)"
            print(f"[Hardware] GPIO {self.pin} initialized. Mode: {mode_str}. Output: OFF")
        except Exception as e:
            self.hardware_active = False
            self.device = None
            print(f"[Simulation] GPIO running in simulation mode ({e})")

    def toggle_polarity(self):
        """Toggle between Active-HIGH and Active-LOW modes."""
        with self.lock:
            self.active_high = not self.active_high
            self._init_gpio()
            mode_str = "Active-HIGH" if self.active_high else "Active-LOW"
        log_event("HARDWARE", f"Relay polarity switched to {mode_str} by operator.", "info")
        return self.active_high

    def _set_output(self, on: bool):
        if self.hardware_active and self.device:
            try:
                if on:
                    self.device.on()
                else:
                    self.device.off()
            except Exception:
                pass
        else:
            state = "ON (SOUNDING / ENERGIZED)" if on else "OFF (SILENT / IDLE)"
            print(f"[Simulated Output] Relay state: {state}")

    def test(self, duration=2.0):
        """Brief 2-second test activation: Turns relay ON, then turns it OFF."""
        self.silence()
        with self.lock:
            self._stop_flag = False
            self.is_silenced = False
            self.status = "Test Active"

        def _worker():
            print("[Hardware] Testing Relay/Buzzer: Turning ON for 2s...")
            self._set_output(True)
            t_end = time.time() + duration
            while time.time() < t_end and not self._stop_flag:
                time.sleep(0.05)
            self._set_output(False)
            with self.lock:
                if self.status == "Test Active":
                    self.status = "Idle"
            print("[Hardware] Test completed: Relay/Buzzer turned OFF.")

        threading.Thread(target=_worker, daemon=True).start()

    def alarm(self, max_duration=30):
        """Alarm pattern for new unauthorized devices: Beeps until silenced."""
        with self.lock:
            if self.is_silenced or self.status == "Beeping":
                return
            self._stop_flag = False
            self.status = "Beeping"

        def _worker():
            print("[Hardware] [ALARM TRIGGERED] Beeping relay/buzzer!")
            t_end = time.time() + max_duration
            while time.time() < t_end and not self._stop_flag:
                # Beep ON: 0.5s
                self._set_output(True)
                for _ in range(5):
                    if self._stop_flag: break
                    time.sleep(0.1)
                # Beep OFF: 0.5s
                self._set_output(False)
                for _ in range(5):
                    if self._stop_flag: break
                    time.sleep(0.1)
            self._set_output(False)
            with self.lock:
                if self.status == "Beeping":
                    self.status = "Idle"
            print("[Hardware] Alarm pattern stopped. Relay/Buzzer OFF.")

        threading.Thread(target=_worker, daemon=True).start()

    def silence(self):
        """Immediately stop sound and turn relay OFF."""
        with self.lock:
            self._stop_flag = True
            self.is_silenced = True
            self.status = "Silenced"
        self._set_output(False)
        print("[Hardware] Relay/Buzzer SILENCED: Output set to OFF.")

    def reset_silence(self):
        """Reset silence flag so future new device alarms can ring."""
        with self.lock:
            self.is_silenced = False
            if self.status == "Silenced":
                self.status = "Idle"

    def cleanup(self):
        """Ensure relay is safely turned off when script terminates."""
        self.silence()
        if self.hardware_active and self.device:
            try:
                self.device.off()
                self.device.close()
            except Exception:
                pass
        print("[Hardware] Script exiting: Relay/Buzzer turned OFF.")

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

# ==================== NETWORK & COMPATIBILITY ====================
def check_network_compatibility(pi_ip, plc_ip, netmask):
    """
    Check if Pi and PLC are in the same subnet.
    IMPORTANT: Does NOT change IPs automatically.
    """
    try:
        pi_network = ipaddress.IPv4Network(f"{pi_ip}/{netmask}", strict=False)
        plc_addr = ipaddress.IPv4Address(plc_ip)
        same_subnet = plc_addr in pi_network

        if same_subnet:
            diagnostic = f"Both IPs belong to the same subnet ({pi_network})."
        else:
            diagnostic = (
                f"Subnet Mismatch Warning: Pi ({pi_ip}) and PLC ({plc_ip}) are in different subnets! "
                f"On a standard switch, communication will fail unless a router connects them, "
                f"or a secondary IP alias is added to the Pi (e.g. 'sudo ip addr add 192.168.0.10/24 dev eth0')."
            )
        return {"same_subnet": same_subnet, "diagnostic": diagnostic}
    except Exception as e:
        return {"same_subnet": False, "diagnostic": f"IP validation error: {e}"}

def ping_host(ip):
    """Single lightweight ping (1 packet, 400ms timeout)."""
    is_win = sys.platform.startswith("win")
    cmd = ["ping", "-n", "1", "-w", "400", ip] if is_win else ["ping", "-c", "1", "-W", "1", ip]
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.0).returncode == 0
    except Exception:
        return False

def check_plc_port_102(ip):
    """Lightweight TCP check on port 102 (Siemens LOGO! 8.3 S7 / ISO-on-TCP)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.8)
    try:
        return s.connect_ex((ip, 102)) == 0
    except Exception:
        return False
    finally:
        s.close()

def is_plc_online(plc_ip):
    """Returns True if PLC responds to ICMP ping or TCP port 102."""
    return ping_host(plc_ip) or check_plc_port_102(plc_ip)

def read_arp_devices():
    """
    Lightweight discovery via ARP table.
    On Linux reads /proc/net/arp (zero CPU). On Windows falls back to arp -a.
    """
    found = []
    # 1. Linux /proc/net/arp
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[2] != "0x0" and parts[3] != "00:00:00:00:00:00":
                        ip = parts[0]
                        mac = parts[3].lower()
                        if not ip.startswith("224.") and not ip.startswith("239.") and not ip.endswith(".255"):
                            found.append({"ip": ip, "mac": mac})
            return found
        except Exception:
            pass

    # 2. Fallback command arp -a
    try:
        res = subprocess.run(["arp", "-a"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=2)
        pattern = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-fA-F:-]{17})")
        for m in pattern.finditer(res.stdout):
            ip, mac = m.group(1), m.group(2).replace("-", ":").lower()
            if (not ip.startswith("224.") and not ip.startswith("239.") and 
                ip != "255.255.255.255" and not ip.endswith(".255") and 
                mac != "ff:ff:ff:ff:ff:ff"):
                found.append({"ip": ip, "mac": mac})
    except Exception:
        pass
    return found

# ==================== EVENT & DEVICE MANAGEMENT ====================
def log_event(event_type, message, severity="info"):
    """Record timestamped event in memory."""
    global event_counter
    with state_lock:
        event_counter += 1
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        events.appendleft({
            "id": event_counter,
            "timestamp": now,
            "event_type": event_type,
            "message": message,
            "severity": severity
        })
    print(f"[{severity.upper()}] {message}")

def init_known_devices():
    """Register initial authorized devices (Pi and PLC)."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    devices[PLC_IP] = {
        "ip": PLC_IP,
        "mac": "00:1C:06:XX:XX:XX",
        "name": "Siemens LOGO! 8.3 PLC",
        "authorized": True,
        "status": "offline",
        "last_seen": now
    }
    devices[PI_IP] = {
        "ip": PI_IP,
        "mac": "B8:27:EB:XX:XX:XX",
        "name": "Raspberry Pi (Host)",
        "authorized": True,
        "status": "online",
        "last_seen": now
    }
    log_event("SYSTEM", f"Industrial Monitor initialized. Pi: {PI_IP}, PLC: {PLC_IP}")

init_known_devices()

def perform_scan():
    """
    Scan network devices.
    - FIRST SCAN (startup): Establishes baseline without sounding the buzzer.
    - SUBSEQUENT SCANS: Only triggers the buzzer if a NEW device connects.
    """
    global is_baseline_recorded
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    monitor_state["last_scan_time"] = now
    discovered = read_arp_devices()
    discovered_ips = {d["ip"]: d["mac"] for d in discovered}

    has_new_unauthorized = False

    with state_lock:
        # 1. Startup baseline check: Mark currently existing devices as baseline authorized
        if not is_baseline_recorded:
            for ip, mac in discovered_ips.items():
                if ip not in devices:
                    devices[ip] = {
                        "ip": ip,
                        "mac": mac,
                        "name": f"Device-{ip.split('.')[-1]}",
                        "authorized": True,  # Pre-existing devices (e.g. laptop) authorized at startup
                        "status": "online",
                        "last_seen": now
                    }
                    log_event("BASELINE", f"Existing device saved to baseline: {ip} ({mac})", "info")
                else:
                    devices[ip]["mac"] = mac
                    devices[ip]["status"] = "online"
                    devices[ip]["last_seen"] = now
            is_baseline_recorded = True
            print("[INFO] Startup network baseline established. Buzzer stays SILENT.")
            return discovered

        # 2. Subsequent scans: Check for real NEW devices that connect while running
        for ip, mac in discovered_ips.items():
            if ip in devices:
                devices[ip]["mac"] = mac
                is_alive = ping_host(ip)
                devices[ip]["status"] = "online" if is_alive else "offline"
                if is_alive:
                    devices[ip]["last_seen"] = now
                if not devices[ip]["authorized"] and is_alive:
                    has_new_unauthorized = True
            else:
                # BRAND NEW DEVICE DETECTED!
                is_alive = ping_host(ip)
                devices[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "name": f"New-Device-{ip.split('.')[-1]}",
                    "authorized": False,  # Flagged as unauthorized
                    "status": "online" if is_alive else "offline",
                    "last_seen": now
                }
                if is_alive:
                    has_new_unauthorized = True
                    log_event("NEW_DEVICE", f"NEW DEVICE CONNECTED: {ip} ({mac})", "critical")

        # 3. Check existing devices: If disconnected, mark OFFLINE
        for ip, dev in list(devices.items()):
            if ip in (PI_IP, PLC_IP):
                continue
            if ip not in discovered_ips and not ping_host(ip):
                if dev["status"] == "online":
                    dev["status"] = "offline"
                    log_event("DEVICE_OFFLINE", f"Device disconnected: {ip} ({dev.get('name', '')})", "info")

        active_unauth = [d for d in devices.values() if not d["authorized"] and d["status"] == "online"]

    # 4. Trigger buzzer ONLY when a new device connects online
    if len(active_unauth) > 0 and has_new_unauthorized:
        buzzer.alarm(max_duration=30)
    elif len(active_unauth) == 0:
        buzzer.silence()
        buzzer.reset_silence()

    return discovered

# ==================== BACKGROUND MONITOR THREAD ====================
def background_worker():
    """Low-overhead background loop."""
    compat = check_network_compatibility(PI_IP, PLC_IP, NETMASK)
    monitor_state["network_compat"] = compat
    if not compat["same_subnet"]:
        log_event("SUBNET_MISMATCH", compat["diagnostic"], "warning")

    # Run initial baseline scan once silently
    try:
        perform_scan()
    except Exception:
        pass

    last_plc_check = time.time()
    last_scan_check = time.time()

    while monitor_state.get("running", True):
        now = time.time()

        # 1. Check Siemens PLC
        if now - last_plc_check >= PLC_CHECK_INTERVAL:
            last_plc_check = now
            online = is_plc_online(PLC_IP)
            prev_status = monitor_state["plc_online"]
            monitor_state["plc_online"] = online
            monitor_state["plc_last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            with state_lock:
                devices[PLC_IP]["status"] = "online" if online else "offline"
                if online:
                    devices[PLC_IP]["last_seen"] = monitor_state["plc_last_checked"]

            if prev_status != online:
                status_str = "ONLINE" if online else "OFFLINE"
                severity = "info" if online else "critical"
                log_event("PLC_STATUS", f"Siemens LOGO! 8.3 PLC ({PLC_IP}) is now {status_str}", severity)

        # 2. Check Device Discovery
        if now - last_scan_check >= SCAN_INTERVAL:
            last_scan_check = now
            try:
                perform_scan()
            except Exception:
                pass

        time.sleep(1)

# ==================== FLASK API ROUTES ====================
@app.route("/")
def index():
    return render_template("index.html", pi_ip=PI_IP, plc_ip=PLC_IP)

@app.route("/api/devices")
def api_devices():
    """Return all known devices."""
    with state_lock:
        return jsonify({"success": True, "devices": list(devices.values())})

@app.route("/api/status")
def api_status():
    with state_lock:
        dev_list = list(devices.values())
        # Only currently connected unauthorized devices show in alert banner
        unauthorized = [d for d in dev_list if not d["authorized"] and d["status"] == "online"]
        evt_list = list(events)

    return jsonify({
        "pi": {
            "ip": PI_IP,
            "status": "Online"
        },
        "plc": {
            "ip": PLC_IP,
            "online": monitor_state["plc_online"],
            "last_checked": monitor_state["plc_last_checked"]
        },
        "network_compat": monitor_state["network_compat"],
        "buzzer": buzzer.get_status(),
        "last_scan": monitor_state["last_scan_time"],
        "unauthorized": unauthorized,
        "devices": dev_list,
        "events": evt_list
    })

@app.route("/api/buzzer/test", methods=["POST"])
def api_buzzer_test():
    """Trigger 2-second test activation of relay/buzzer."""
    buzzer.test(duration=2.0)
    log_event("BUZZER_TEST", "Operator clicked Test Relay: Buzzer turned ON for 2s.", "info")
    return jsonify({"success": True})

@app.route("/api/buzzer/silence", methods=["POST"])
def api_buzzer_silence():
    """Immediately silence alarm and turn relay/buzzer OFF."""
    buzzer.silence()
    log_event("BUZZER_SILENCE", "Operator clicked Silence: Buzzer turned OFF.", "warning")
    return jsonify({"success": True})

@app.route("/api/buzzer/toggle_mode", methods=["POST"])
def api_buzzer_toggle_mode():
    """Toggle between Active-HIGH (transistor) and Active-LOW (relay module)."""
    new_active_high = buzzer.toggle_polarity()
    mode = "Active-HIGH (Transistor / Standard)" if new_active_high else "Active-LOW (Relay Module)"
    return jsonify({"success": True, "active_high": new_active_high, "mode_text": mode})

@app.route("/api/scan", methods=["POST"])
def api_scan():
    """Trigger on-demand scan."""
    discovered = perform_scan()
    return jsonify({"success": True, "count": len(discovered)})

@app.route("/api/authorize", methods=["POST"])
def api_authorize():
    """Authorize a device and silence alarm."""
    data = request.get_json() or {}
    ip = data.get("ip")
    with state_lock:
        if ip in devices:
            devices[ip]["authorized"] = True
            log_event("DEVICE_AUTH", f"Device {ip} authorized by operator.", "info")
        unauth = [d for d in devices.values() if not d["authorized"] and d["status"] == "online"]

    if not unauth:
        buzzer.silence()
        buzzer.reset_silence()
    return jsonify({"success": True})

@app.route("/api/device/delete", methods=["POST"])
def api_device_delete():
    """Remove a disconnected device from the table."""
    data = request.get_json() or {}
    ip = data.get("ip")
    if ip in (PI_IP, PLC_IP):
        return jsonify({"success": False, "error": "Cannot delete host or PLC"}), 400

    with state_lock:
        if ip in devices:
            del devices[ip]
            log_event("DEVICE_REMOVED", f"Device {ip} removed by operator.", "info")
    return jsonify({"success": True})

@app.route("/api/simulate/unknown", methods=["POST"])
def api_simulate_unknown():
    """Simulate a new device connecting to test buzzer alarm."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sim_ip = f"172.168.74.{int(time.time()) % 150 + 100}"
    sim_mac = "AA:BB:CC:11:22:33"
    with state_lock:
        devices[sim_ip] = {
            "ip": sim_ip,
            "mac": sim_mac,
            "name": "Simulated Rogue Device",
            "authorized": False,
            "status": "online",
            "last_seen": now
        }
    log_event("NEW_DEVICE", f"SIMULATED NEW DEVICE: {sim_ip} ({sim_mac})", "critical")
    buzzer.alarm(max_duration=30)
    return jsonify({"success": True, "ip": sim_ip})

if __name__ == "__main__":
    mode_desc = "Active-HIGH (Transistor / Standard: 0V=OFF, 3.3V=ON)" if DEFAULT_ACTIVE_HIGH else "Active-LOW (Relay: 3.3V=OFF, 0V=ON)"
    print(f"============================================================")
    print(f" Industrial Network Monitoring System")
    print(f" Siemens PLC IP:   {PLC_IP}")
    print(f" Raspberry Pi IP:  {PI_IP}")
    print(f" Relay/Buzzer:     GPIO {BUZZER_PIN} [{mode_desc}]")
    print(f" Dashboard URL:    http://{PI_IP}:{PORT}")
    print(f" Local URL:        http://localhost:{PORT}")
    print(f"============================================================")
    threading.Thread(target=background_worker, daemon=True).start()
    try:
        app.run(host="0.0.0.0", port=PORT, debug=False)
    finally:
        buzzer.cleanup()
