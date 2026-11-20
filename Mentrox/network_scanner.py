"""
NetSentinel OT: High-Performance Ethernet-Only Network Scanner.

Dedicated to Operational Technology (OT) and Industrial Control Systems (ICS).
Scans exclusively on the physical Ethernet adapter (Interface Index 9 / Realtek PCIe GbE)
connected to the 8-channel OT Ethernet Switch.

Key Architectural Guarantees:
1. Strict Ethernet Interface Binding:
   - Identifies the physical 802.3 wired Ethernet adapter (Index: 9, IP: 192.168.0.12).
   - Strictly ignores Wi-Fi, Bluetooth, VPN, Virtual, and loopback adapters.
2. Dynamic OT Subnet Calculation:
   - Dynamically calculates the active OT subnet (192.168.0.0/24) from IP and prefix length.
   - Supports additional authorized OT subnets via OT_ADDITIONAL_SUBNETS in .env.
3. Strict Ethernet-Only Discovery:
   - Queries Windows ARP cache exclusively for the Ethernet IP via 'arp -a -N {ethernet_ip}'.
   - Binds ICMP echo pings strictly to the Ethernet source IP via 'ping -S {ethernet_ip}'.
   - Binds TCP socket probes strictly to the Ethernet IP via s.bind((ethernet_ip, 0)).
   - Every candidate IP is strictly validated against the allowed OT subnets; all Wi-Fi IPs (172.170.x.x) are strictly dropped.
4. Conservative OT Scanning:
   - Low concurrency (max 10-15 workers) to avoid packet flooding or disruption to OT switches and PLCs.
   - Gentle, non-intrusive probing on common OT ports (502 Modbus, 1883 MQTT, 44818 CIP, 102 S7, 80/443/8080 Web, 22 SSH).
5. Hardware & OT Role Identification:
   - Raspberry Pi 4 (OT Controller)
   - Industrial PLCs (Siemens, Schneider, Rockwell, Omron, ABB)
   - Industrial Switches & Gateways (Hirschmann, Moxa, Phoenix Contact, Cisco, Netgear, TP-Link)
   - OT Engineering Workstation (Local Host)
"""

from __future__ import annotations
import os
import re
import socket
import subprocess
import concurrent.futures
import ipaddress
import time
import json
from typing import List, Dict, Any, Optional, Tuple, Set
from dotenv import load_dotenv

load_dotenv()

# ====================================================================
# MAC Vendor OUI Database & OT Role Mapping
# ====================================================================
OT_VENDOR_OUI_MAP: Dict[str, Tuple[str, str]] = {
    # --- Raspberry Pi (OT Controllers / Nodes) ---
    "B8:27:EB": ("Raspberry Pi Foundation", "Raspberry Pi (OT Controller)"),
    "DC:A6:32": ("Raspberry Pi Foundation", "Raspberry Pi (OT Controller)"),
    "E4:5F:01": ("Raspberry Pi Foundation", "Raspberry Pi (OT Controller)"),
    "28:CD:C1": ("Raspberry Pi Foundation", "Raspberry Pi (OT Controller)"),
    "D8:3A:DD": ("Raspberry Pi Foundation", "Raspberry Pi (OT Controller)"),

    # --- Industrial Ethernet Switches & Gateways ---
    "00:0C:7C": ("Hirschmann / Belden", "OT Network Switch / Gateway"),
    "00:80:63": ("Hirschmann", "OT Network Switch / Gateway"),
    "00:01:E7": ("Hirschmann", "OT Network Switch / Gateway"),
    "00:90:E8": ("Moxa Technologies", "OT Network Switch / Gateway"),
    "00:08:4F": ("Moxa Technologies", "OT Network Switch / Gateway"),
    "00:02:18": ("Moxa Technologies", "OT Network Switch / Gateway"),
    "00:A0:45": ("Phoenix Contact", "OT Network Switch / Gateway"),
    "00:1C:18": ("Phoenix Contact", "OT Network Switch / Gateway"),
    "00:0F:74": ("Phoenix Contact", "OT Network Switch / Gateway"),
    "00:0A:EB": ("TP-Link Technologies", "OT Network Switch / Gateway"),
    "14:CC:20": ("TP-Link Technologies", "OT Network Switch / Gateway"),
    "18:A6:F7": ("TP-Link Technologies", "OT Network Switch / Gateway"),
    "00:09:5B": ("Netgear Inc.", "OT Network Switch / Gateway"),
    "00:14:6C": ("Netgear Inc.", "OT Network Switch / Gateway"),
    "00:05:5D": ("D-Link Systems", "OT Network Switch / Gateway"),
    "00:00:0C": ("Cisco Systems", "OT Network Switch / Gateway"),
    "00:01:42": ("Cisco Systems", "OT Network Switch / Gateway"),
    "00:0C:42": ("MikroTik", "OT Network Switch / Gateway"),
    "00:15:6D": ("Ubiquiti Networks", "OT Network Switch / Gateway"),

    # --- Industrial PLCs & Automation Controllers ---
    "00:1B:1B": ("Siemens AG (SIMATIC S7 / Scalance)", "Industrial PLC / Controller"),
    "00:1D:9C": ("Siemens AG", "Industrial PLC / Controller"),
    "00:0E:8C": ("Siemens AG", "Industrial PLC / Controller"),
    "00:1C:06": ("Siemens AG", "Industrial PLC / Controller"),
    "00:08:74": ("Siemens AG", "Industrial PLC / Controller"),
    "00:80:F4": ("Schneider Electric (Modicon)", "Industrial PLC / Controller"),
    "00:00:54": ("Schneider Electric", "Industrial PLC / Controller"),
    "00:1D:C0": ("Schneider Electric", "Industrial PLC / Controller"),
    "00:00:BC": ("Rockwell Automation / Allen-Bradley", "Industrial PLC / Controller"),
    "00:80:37": ("Rockwell Automation", "Industrial PLC / Controller"),
    "00:00:0A": ("Omron Corporation", "Industrial PLC / Controller"),
    "00:20:4A": ("ABB Group", "Industrial PLC / Controller"),
    "00:30:DE": ("WAGO Kontakttechnik", "Industrial PLC / Controller"),
    "00:01:05": ("Beckhoff Automation", "Industrial PLC / Controller"),
    "24:0A:C4": ("Espressif Systems (IoT Node)", "IoT / Sensor Node"),
    "30:AE:A4": ("Espressif Systems (IoT Node)", "IoT / Sensor Node"),

    # --- Hardware Chipsets & Workstations ---
    "40:C2:BA": ("Realtek PCIe GbE Family", "OT Engineering Workstation"),
    "F8:F2:1E": ("Intel Corporate", "OT Engineering Workstation"),
    "00:1B:21": ("Intel Corporate", "OT Engineering Workstation"),
    "00:E0:4C": ("Realtek Semiconductor", "OT Engineering Workstation"),
    "00:14:22": ("Dell Inc.", "OT Engineering Workstation"),
    "B4:B0:24": ("Dell Inc.", "OT Engineering Workstation"),
    "50:BB:B5": ("HP Inc.", "OT Engineering Workstation"),
    "C4:23:60": ("Lenovo Inc.", "OT Engineering Workstation"),
}


def normalize_mac(mac: str) -> str:
    """Normalizes MAC address format to XX:XX:XX:XX:XX:XX."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(cleaned) == 12:
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac.upper()


def get_ot_mac_vendor_and_type(
    mac: str,
    ip: str,
    open_port: Optional[int] = None,
    is_local_host: bool = False
) -> Tuple[str, str]:
    """Identifies the hardware vendor and OT device classification role."""
    if is_local_host:
        return "Local Host Controller", "OT Engineering Workstation"

    norm_mac = normalize_mac(mac)
    prefix = ":".join(norm_mac.split(":")[:3]) if ":" in norm_mac else ""

    vendor = ""
    dev_type = ""

    if prefix in OT_VENDOR_OUI_MAP:
        vendor, dev_type = OT_VENDOR_OUI_MAP[prefix]

    # OT Port-based role identification:
    if open_port in (502, 102, 44818):
        dev_type = "Industrial PLC / Controller"
        if not vendor:
            vendor = "Modbus / S7 / CIP Industrial Device"
    elif open_port == 1883:
        if not dev_type:
            dev_type = "IoT / MQTT Sensor Node"
        if not vendor:
            vendor = "MQTT Industrial Node"
    elif open_port == 22 and "Raspberry" in vendor:
        dev_type = "Raspberry Pi (OT Controller)"

    # IP-based switch / gateway convention
    last_octet = ip.split(".")[-1] if "." in ip else ""
    if last_octet in ("1", "254") and not dev_type:
        dev_type = "OT Network Switch / Gateway"
        if not vendor:
            vendor = "OT Switch / Default Gateway"

    if not vendor:
        vendor = "Generic OT Device"
    if not dev_type:
        dev_type = "OT Connected Device"

    return vendor, dev_type


# ====================================================================
# Dedicated Ethernet Interface Detection
# ====================================================================

def get_ot_ethernet_adapter() -> Optional[Dict[str, Any]]:
    """
    Detects the physical wired Ethernet adapter (802.3 wired Ethernet).
    Specifically identifies InterfaceIndex 9 (Realtek PCIe GbE Family Controller).
    Strictly excludes Wi-Fi, Bluetooth, VPN, Tunnel, and virtual adapters.
    """
    ps_script = """
    $adapters = Get-NetAdapter | Where-Object { 
        ($_.PhysicalMediaType -eq '802.3' -or $_.MediaType -eq '802.3' -or $_.InterfaceIndex -eq 9) -and 
        $_.Name -notlike '*Wi-Fi*' -and 
        $_.Name -notlike '*Wireless*' -and 
        $_.InterfaceDescription -notlike '*Wi-Fi*' -and 
        $_.InterfaceDescription -notlike '*Wireless*' -and 
        $_.InterfaceDescription -notlike '*Bluetooth*' -and 
        $_.InterfaceDescription -notlike '*Virtual*' -and 
        $_.InterfaceDescription -notlike '*Loopback*'
    }
    
    $result = @()
    foreach ($a in $adapters) {
        $ipInfo = Get-NetIPAddress -InterfaceIndex $a.InterfaceIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1
        $result += [PSCustomObject]@{
            Name = $a.Name
            InterfaceIndex = $a.InterfaceIndex
            InterfaceDescription = $a.InterfaceDescription
            Status = $a.Status
            MacAddress = $a.MacAddress
            IPAddress = if ($ipInfo) { $ipInfo.IPAddress } else { "" }
            PrefixLength = if ($ipInfo) { $ipInfo.PrefixLength } else { 24 }
        }
    }
    $result | ConvertTo-Json
    """
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=5.0
        )
        out = res.stdout.strip()
        if not out:
            return None

        data = json.loads(out)
        item = data[0] if isinstance(data, list) else data

        ip = item.get("IPAddress", "").strip()
        prefix = int(item.get("PrefixLength", 24))
        status = item.get("Status", "Disconnected")

        if ip:
            net = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)
            item["Subnet"] = str(net)
            item["Netmask"] = str(net.netmask)
        else:
            item["Subnet"] = ""
            item["Netmask"] = ""

        # Normalize MAC
        if item.get("MacAddress"):
            item["MacAddress"] = normalize_mac(item["MacAddress"])

        return item

    except Exception as e:
        print(f"[-] Error detecting OT Ethernet adapter: {e}")
        return None


# ====================================================================
# Hostname Resolution
# ====================================================================
_hostname_cache: Dict[str, str] = {}


def resolve_ot_hostname(ip: str, timeout: float = 0.3) -> str:
    """Attempts fast reverse DNS lookup for an OT device IP."""
    if ip in _hostname_cache:
        return _hostname_cache[ip]
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        _hostname_cache[ip] = hostname
        return hostname
    except Exception:
        _hostname_cache[ip] = "Unknown Device"
        return "Unknown Device"


# ====================================================================
# Ethernet-Scoped ARP Table Parser
# ====================================================================

def parse_ethernet_arp_table(
    ethernet_ip: str,
    allowed_subnets: List[ipaddress.IPv4Network]
) -> List[Dict[str, Any]]:
    """
    Queries Windows ARP cache EXCLUSIVELY for the Ethernet interface IP.
    Runs 'arp -a -N {ethernet_ip}'.
    Strictly verifies that every discovered IP belongs to the allowed OT subnets.
    Wi-Fi devices (172.170.x.x) are strictly excluded.
    """
    devices: List[Dict[str, Any]] = []
    if not ethernet_ip:
        return devices

    try:
        cmd = f"arp -a -N {ethernet_ip}"
        output = subprocess.check_output(cmd, shell=True, text=True, stderr=subprocess.DEVNULL)

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue

            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F\-]{11,17})\s+(\w+)", line)
            if match:
                ip, mac, arp_type = match.groups()
                norm_mac = normalize_mac(mac)

                # Filter broadcast / multicast / loopback
                first = int(ip.split(".")[0])
                last = int(ip.split(".")[3])
                if (
                    first >= 224
                    or ip.startswith("127.")
                    or last in (0, 255)
                    or "FF:FF:FF:FF:FF:FF" in norm_mac
                    or "00:00:00:00:00:00" in norm_mac
                    or ip == ethernet_ip
                ):
                    continue

                # STRICT OT SUBNET CHECK:
                try:
                    ip_obj = ipaddress.IPv4Address(ip)
                    if not any(ip_obj in subnet for subnet in allowed_subnets):
                        # Device is outside OT subnets (e.g. Wi-Fi leak) -> REJECT
                        continue
                except Exception:
                    continue

                devices.append({
                    "ip": ip,
                    "mac": norm_mac,
                    "arp_type": arp_type.lower(),
                    "interface_ip": ethernet_ip,
                })

    except Exception as e:
        print(f"[-] Error reading Ethernet ARP table: {e}")

    return devices


# ====================================================================
# Ethernet-Bound Liveness Probing (ICMP + TCP)
# ====================================================================

def ping_ethernet_ip(target_ip: str, ethernet_ip: str, timeout_ms: int = 250) -> bool:
    """
    Sends an ICMP Echo Ping strictly bound to the Ethernet interface.
    The '-S {ethernet_ip}' flag forces Windows to use the Ethernet adapter.
    """
    try:
        cmd = f"ping -n 1 -w {timeout_ms} -S {ethernet_ip} {target_ip}"
        res = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def probe_ethernet_tcp_ports(
    target_ip: str,
    ethernet_ip: str,
    ports: Tuple[int, ...] = (502, 1883, 44818, 102, 80, 443, 8080, 22, 23),
    timeout: float = 0.25
) -> Tuple[bool, Optional[int]]:
    """
    Probes common OT / ICS ports strictly bound to the Ethernet interface.
    Explicitly binds socket to (ethernet_ip, 0) before initiating connection.
    """
    for p in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            # Explicit source interface binding to Ethernet adapter:
            s.bind((ethernet_ip, 0))
            code = s.connect_ex((target_ip, p))
            s.close()
            # 0 = Connected / Port Open
            # 10061 = Host actively refused with TCP RST (host is alive!)
            if code in (0, 10061):
                return True, p
        except Exception:
            pass
    return False, None


def sweep_ethernet_subnet(
    subnet: ipaddress.IPv4Network,
    ethernet_ip: str,
    max_workers: int = 15
) -> None:
    """
    Conservatively sweeps the OT Ethernet subnet to stimulate switch & ARP cache.
    Uses controlled concurrency (max 15 workers) suitable for OT switches and PLCs.
    """
    hosts = [str(ip) for ip in subnet.hosts() if str(ip) != ethernet_ip]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(lambda ip: ping_ethernet_ip(ip, ethernet_ip, timeout_ms=180), hosts)


# ====================================================================
# Main OT NetworkScanner Class
# ====================================================================

class NetworkScanner:
    """
    Exclusively scans and manages the OT Ethernet network.
    Guarantees that Wi-Fi devices are never scanned, discovered, or reported.
    """

    def __init__(self):
        self.adapter_info: Optional[Dict[str, Any]] = None
        self.is_connected: bool = False
        self.local_ip: str = "127.0.0.1"
        self.subnet: str = "Disconnected"
        self.interface_name: str = "Ethernet"
        self.interface_index: int = 9
        self.error_message: str = ""
        self.allowed_subnets: List[ipaddress.IPv4Network] = []

        self.refresh_interface()

    def refresh_interface(self) -> bool:
        """
        Re-detects the physical Ethernet adapter (Interface Index 9).
        Calculates dynamic subnet and sets connection status.
        """
        info = get_ot_ethernet_adapter()
        self.adapter_info = info

        if not info:
            self.is_connected = False
            self.error_message = "Ethernet adapter (Index 9) not found on system."
            self.local_ip = "127.0.0.1"
            self.subnet = "Disconnected (No Ethernet Adapter)"
            self.allowed_subnets = []
            return False

        self.interface_name = info.get("Name", "Ethernet")
        self.interface_index = int(info.get("InterfaceIndex", 9))
        status = info.get("Status", "Disconnected")

        if status != "Up" or not info.get("IPAddress"):
            self.is_connected = False
            self.error_message = "Ethernet (OT Network) interface is disconnected. Please connect Ethernet cable to the OT switch."
            self.local_ip = info.get("IPAddress", "127.0.0.1")
            self.subnet = "Disconnected (Ethernet Cable Unplugged)"
            self.allowed_subnets = []
            return False

        self.local_ip = info["IPAddress"]
        self.subnet = info.get("Subnet", "192.168.0.0/24")
        self.is_connected = True
        self.error_message = ""

        # Build allowed OT subnets list
        subnets = []
        try:
            subnets.append(ipaddress.IPv4Network(self.subnet, strict=False))
        except Exception:
            subnets.append(ipaddress.IPv4Network("192.168.0.0/24", strict=False))

        # Check for additional authorized OT subnets in .env
        add_subnets = os.getenv("OT_ADDITIONAL_SUBNETS", "").strip()
        if add_subnets:
            for s in add_subnets.split(","):
                s = s.strip()
                if s:
                    try:
                        subnets.append(ipaddress.IPv4Network(s, strict=False))
                    except Exception:
                        pass

        self.allowed_subnets = subnets
        return True

    def scan_network(self, active_sweep: bool = False) -> List[Dict[str, Any]]:
        """
        Executes a real-time OT network scan exclusively on the Ethernet adapter.
        Guarantees:
        - Wi-Fi devices (172.170.x.x) are never included.
        - Only Ethernet-connected devices (Raspberry Pi, PLCs, Switches, Hosts) are returned.
        """
        self.refresh_interface()

        if not self.is_connected or not self.allowed_subnets:
            return []

        primary_subnet = self.allowed_subnets[0]

        # 1. Conservative active sweep if requested
        if active_sweep:
            sweep_ethernet_subnet(
                subnet=primary_subnet,
                ethernet_ip=self.local_ip,
                max_workers=15
            )

        # 2. Parse Ethernet-scoped ARP table
        arp_devices = parse_ethernet_arp_table(
            ethernet_ip=self.local_ip,
            allowed_subnets=self.allowed_subnets
        )

        # 3. Multi-probe liveness check bound to Ethernet
        def _probe_ot_device(dev: Dict[str, Any]) -> Dict[str, Any]:
            ip = dev["ip"]
            # Probe via bound ICMP ping
            p_ok = ping_ethernet_ip(ip, self.local_ip, timeout_ms=250)
            tcp_ok, open_p = (False, None)
            if not p_ok:
                # Probe via bound TCP socket
                tcp_ok, open_p = probe_ethernet_tcp_ports(ip, self.local_ip, timeout=0.25)

            probe_status = "ICMP Ping" if p_ok else (f"TCP Port {open_p}" if tcp_ok else "ARP Active")
            return {
                "ip": ip,
                "mac": dev["mac"],
                "arp_type": dev.get("arp_type", "dynamic"),
                "is_online": True,
                "probe_status": probe_status,
                "open_port": open_p,
            }

        with concurrent.futures.ThreadPoolExecutor(max_workers=15) as executor:
            probed_candidates = list(executor.map(_probe_ot_device, arp_devices))

        discovered_map: Dict[str, Dict[str, Any]] = {}

        # 4. Add Local OT Monitoring Station (Ethernet host IP 192.168.0.12)
        try:
            local_hostname = socket.gethostname()
        except Exception:
            local_hostname = "OT-Workstation"

        discovered_map[self.local_ip] = {
            "ip": self.local_ip,
            "mac": self.adapter_info.get("MacAddress", "40:C2:BA:AE:43:60"),
            "hostname": f"{local_hostname} (OT Engineering Station)",
            "device_type": "OT Engineering Workstation",
            "vendor": "Local Ethernet Interface (Realtek PCIe GbE)",
            "interface_name": "Ethernet",
            "is_switch": False,
            "is_online": True,
            "probe_status": "Local Ethernet Station",
        }

        # 5. Add Discovered OT Devices
        for dev in probed_candidates:
            ip = dev["ip"]
            if ip in discovered_map:
                continue

            mac = dev["mac"]
            vendor, dev_type = get_ot_mac_vendor_and_type(
                mac=mac,
                ip=ip,
                open_port=dev.get("open_port"),
                is_local_host=False
            )

            discovered_map[ip] = {
                "ip": ip,
                "mac": mac,
                "hostname": "Unknown",
                "device_type": dev_type,
                "vendor": vendor,
                "interface_name": "Ethernet",
                "is_switch": ("Switch" in dev_type or "Gateway" in dev_type),
                "is_online": True,
                "probe_status": dev["probe_status"],
            }

        # 6. Resolve Hostnames concurrently
        def _enrich_ot_hostname(d: Dict[str, Any]) -> Dict[str, Any]:
            if d["hostname"] == "Unknown":
                d["hostname"] = resolve_ot_hostname(d["ip"])
            return d

        device_list = list(discovered_map.values())
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            enriched_devices = list(executor.map(_enrich_ot_hostname, device_list))

        # Sort: Switches/PLCs first, then by IP
        def _ot_sort_key(d: Dict[str, Any]) -> Tuple[int, List[int]]:
            priority = 0 if "Switch" in d.get("device_type", "") or "PLC" in d.get("device_type", "") else 1
            try:
                ip_parts = [int(p) for p in d["ip"].split(".")]
            except Exception:
                ip_parts = [999, 999, 999, 999]
            return (priority, ip_parts)

        return sorted(enriched_devices, key=_ot_sort_key)
