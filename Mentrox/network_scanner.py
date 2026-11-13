"""
NetSentinel: High-Performance Network Scanner.

Discovers all connected devices on the local network using:
1. Fast Windows ARP cache inspection
2. Concurrent multithreaded ping/socket sweeps
3. Hostname resolution
"""

from __future__ import annotations
import os
import re
import socket
import subprocess
import concurrent.futures
from typing import List, Dict, Any, Optional, Set
from dotenv import load_dotenv

load_dotenv()


def get_local_ip_and_subnet() -> tuple[str, str]:
    """Auto-detects the active local IPv4 address and /24 subnet."""
    custom_subnet = os.getenv("CUSTOM_SUBNET", "").strip()
    if custom_subnet:
        # e.g., 192.168.1.0/24
        prefix = ".".join(custom_subnet.split("/")[0].split(".")[:3])
        return f"{prefix}.1", f"{prefix}.0/24"

    local_ip = "127.0.0.1"
    try:
        # Connect to a public DNS IP to determine default egress interface
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            local_ip = "127.0.0.1"

    parts = local_ip.split(".")
    if len(parts) == 4 and parts[0] != "127":
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    else:
        subnet = "192.168.1.0/24"

    return local_ip, subnet


def normalize_mac(mac: str) -> str:
    """Normalizes MAC address format to XX:XX:XX:XX:XX:XX."""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac).upper()
    if len(cleaned) == 12:
        return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2))
    return mac.upper()


def resolve_hostname(ip: str, timeout: float = 0.3) -> str:
    """Attempts fast reverse DNS lookup for a device IP."""
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname
    except Exception:
        return "Unknown Device"


def parse_arp_table() -> List[Dict[str, str]]:
    """Reads system ARP cache using 'arp -a' on Windows."""
    devices = []
    try:
        output = subprocess.check_output("arp -a", shell=True, text=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            line = line.strip()
            # Match: 172.168.64.1   f8-f2-1e-1a-8a-70   dynamic
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F\-]{11,17})\s+(\w+)", line)
            if match:
                ip, mac, arp_type = match.groups()
                # Exclude broadcast, loopback, and multicast ranges (224.0.0.0 - 239.255.255.255)
                first_octet = int(ip.split(".")[0])
                last_octet = int(ip.split(".")[3])
                if (
                    first_octet >= 224
                    or ip.startswith("127.")
                    or last_octet in (0, 255)
                    or "ff-ff-ff-ff-ff-ff" in mac.lower()
                ):
                    continue

                devices.append({
                    "ip": ip,
                    "mac": normalize_mac(mac),
                    "type": arp_type,
                })
    except Exception as e:
        print(f"[-] Error reading ARP table: {e}")

    return devices


def ping_ip(ip: str, timeout_ms: int = 250) -> bool:
    """Sends a fast single ICMP echo to stimulate the ARP cache."""
    try:
        cmd = f"ping -n 1 -w {timeout_ms} {ip}"
        res = subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False


def sweep_subnet(base_subnet_prefix: str, start: int = 1, end: int = 254, max_workers: int = 50) -> None:
    """Concurrently pings an IP range to populate the system ARP cache."""
    ips = [f"{base_subnet_prefix}.{i}" for i in range(start, end + 1)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        executor.map(ping_ip, ips)


def is_network_interface_active() -> bool:
    """Verifies if the machine has an active external network connection (Wi-Fi or Ethernet)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.4)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return not ip.startswith("127.") and not ip.startswith("169.254.")
    except Exception:
        return False


def get_local_ip_and_subnet() -> tuple[str, str, bool]:
    """Auto-detects the active local IPv4 address and /24 subnet. Returns (ip, subnet, is_connected)."""
    custom_subnet = os.getenv("CUSTOM_SUBNET", "").strip()
    if custom_subnet:
        prefix = ".".join(custom_subnet.split("/")[0].split(".")[:3])
        return f"{prefix}.1", f"{prefix}.0/24", True

    local_ip = "127.0.0.1"
    is_connected = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.4)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        is_connected = not local_ip.startswith("127.") and not local_ip.startswith("169.254.")
    except Exception:
        try:
            local_ip = socket.gethostbyname(socket.gethostname())
            is_connected = not local_ip.startswith("127.") and not local_ip.startswith("169.254.")
        except Exception:
            local_ip = "127.0.0.1"
            is_connected = False

    parts = local_ip.split(".")
    if is_connected and len(parts) == 4:
        subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    else:
        subnet = "Disconnected (No Wi-Fi/Ethernet)"

    return local_ip, subnet, is_connected


class NetworkScanner:
    """Orchestrates network discovery and continuous scanning."""

    def __init__(self):
        self.local_ip, self.subnet, self.is_connected = get_local_ip_and_subnet()
        self.subnet_prefix = ".".join(self.local_ip.split(".")[:3])

    def refresh_interface(self) -> None:
        """Re-checks interface in case Wi-Fi was toggled ON or OFF."""
        self.local_ip, self.subnet, self.is_connected = get_local_ip_and_subnet()
        self.subnet_prefix = ".".join(self.local_ip.split(".")[:3])

    def scan_network(self, active_sweep: bool = False) -> List[Dict[str, Any]]:
        """
        Executes a real-time network scan.
        Only returns devices that are ACTIVELY reachable right now.
        If Wi-Fi is disconnected, returns empty list.
        """
        self.refresh_interface()

        if not self.is_connected:
            # Wi-Fi is disconnected!
            return []

        if active_sweep:
            sweep_subnet(self.subnet_prefix, start=1, end=254, max_workers=40)

        arp_devices = parse_arp_table()
        candidate_ips = [dev["ip"] for dev in arp_devices]

        # Fast active ping check: verify which devices are ACTUALLY ALIVE right now
        # (This purges old stale entries from Windows ARP cache when devices disconnect!)
        alive_ips = set()
        with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
            future_to_ip = {executor.submit(ping_ip, ip, 200): ip for ip in candidate_ips}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    if future.result():
                        alive_ips.add(ip)
                except Exception:
                    pass

        discovered_map: Dict[str, Dict[str, Any]] = {}

        # Add local machine (always online if interface is up)
        try:
            local_hostname = socket.gethostname()
        except Exception:
            local_hostname = "This Host"

        discovered_map[self.local_ip] = {
            "ip": self.local_ip,
            "mac": "LOCAL-HOST",
            "hostname": f"{local_hostname} (Monitoring Station)",
            "is_online": True,
        }

        # Add ARP devices that are genuinely alive
        for dev in arp_devices:
            ip = dev["ip"]
            mac = dev["mac"]
            # Device must respond to active ping, or be the gateway / local subnet neighbor
            if ip in alive_ips and ip not in discovered_map:
                discovered_map[ip] = {
                    "ip": ip,
                    "mac": mac,
                    "hostname": "Unknown",
                    "is_online": True,
                }

        # Resolve hostnames concurrently
        def _enrich_device(d: Dict[str, Any]) -> Dict[str, Any]:
            if d["hostname"] == "Unknown":
                d["hostname"] = resolve_hostname(d["ip"])
            return d

        device_list = list(discovered_map.values())
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            enriched_devices = list(executor.map(_enrich_device, device_list))

        return sorted(enriched_devices, key=lambda x: [int(p) for p in x["ip"].split(".")])
