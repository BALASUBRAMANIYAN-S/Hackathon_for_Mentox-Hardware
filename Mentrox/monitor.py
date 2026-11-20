"""
NetSentinel OT: Continuous Network Monitoring Engine.

Specifically monitors the physical wired Ethernet interface (Interface Index 9).
Periodically sweeps the OT subnet (192.168.0.0/24),
identifies Raspberry Pi, PLCs, and OT Switches,
flags unrecognized rogue OT devices, dispatches alert notifications,
and enforces strict Ethernet-only isolation.
"""

from __future__ import annotations
import os
import time
import threading
from datetime import datetime
from typing import Dict, Any, List, Set, Optional
from dotenv import load_dotenv

import db
from network_scanner import NetworkScanner
import blocker
import notifier

load_dotenv()


class ContinuousMonitor:
    def __init__(self):
        self.scanner = NetworkScanner()
        # Scan interval in seconds (default 10s)
        self.scan_interval = int(os.getenv("SCAN_INTERVAL_SECONDS", 10))
        self.auto_block = os.getenv("AUTO_BLOCK_ROGUE_IPS", "False").strip().lower() in ("true", "1")
        
        self.running = False
        self.is_scanning = False
        self._thread: threading.Thread | None = None
        self._scan_event = threading.Event()

        self.pending_active_sweep: bool = False

        # Track alerted IPs to avoid email spamming within a cooldown period (10 minutes)
        self._last_alerted_times: Dict[str, float] = {}

        # Real-time state metrics
        self.last_scan_timestamp: str = "Never"
        self.total_devices: int = 0
        self.online_devices: int = 0
        self.switch_devices: int = 0
        self.plc_devices: int = 0
        self.offline_devices: int = 0
        self.authorized_devices: int = 0
        self.unauthorized_devices: int = 0
        self.blocked_devices: int = 0

    def start(self) -> None:
        """Starts the background continuous monitoring thread."""
        if not self.running:
            # Purge any legacy or cached non-OT Wi-Fi devices from DB on startup
            try:
                purged = db.purge_non_ot_devices("192.168.0.")
                if purged > 0:
                    print(f"[+] Cleaned up {purged} cached non-OT Wi-Fi records from database.")
            except Exception as e:
                print(f"[-] Database cleanup notice: {e}")

            self.running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
            print("[+] NetSentinel OT Continuous Monitoring Thread started (Ethernet Interface Index 9).")

    def stop(self) -> None:
        """Stops the background monitoring thread."""
        self.running = False
        self._scan_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def trigger_scan_now(self, active_sweep: bool = True) -> None:
        """Wakes up the scanner to execute an immediate OT network sweep."""
        self.pending_active_sweep = active_sweep
        self._scan_event.set()

    def _monitor_loop(self) -> None:
        while self.running:
            try:
                self.run_single_scan()
            except Exception as e:
                print(f"[-] Error during OT network scan cycle: {e}")

            # Wait scan_interval or until manual scan trigger button is pressed
            self._scan_event.wait(timeout=self.scan_interval)
            self._scan_event.clear()

    def run_single_scan(
        self,
        active_sweep: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """Executes one OT scan cycle, reconciles with MySQL, and triggers warnings/emails."""
        self.is_scanning = True
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        if active_sweep is None:
            active_sweep = self.pending_active_sweep
        self.pending_active_sweep = False

        try:
            # 1. Discover all active devices on OT Ethernet network
            discovered = self.scanner.scan_network(active_sweep=active_sweep)
            active_ips = [dev["ip"] for dev in discovered]

            # 2. Mark any device not currently responding as OFFLINE in MySQL
            db.mark_absent_devices_offline(active_ips, interface_name="Ethernet")

            self.online_devices = len(discovered)
            auth_count = 0
            unauth_count = 0
            blocked_count = 0
            switch_count = 0
            plc_count = 0

            current_time = time.time()

            # 3. Process currently online devices
            for dev in discovered:
                ip = dev["ip"]
                mac = dev["mac"]
                hostname = dev["hostname"]
                dev_type = dev.get("device_type", "OT Connected Device")
                iface_name = "Ethernet"
                vendor = dev.get("vendor", "")

                if "Switch" in dev_type or "Gateway" in dev_type or dev.get("is_switch"):
                    switch_count += 1
                elif "PLC" in dev_type or "Raspberry" in dev_type or "Controller" in dev_type:
                    plc_count += 1

                # Check if device is in MySQL authorized list
                is_auth = db.is_ip_authorized(ip)
                is_blk = db.is_ip_blocked(ip)

                if is_blk:
                    blocked_count += 1

                if is_auth:
                    auth_count += 1
                else:
                    unauth_count += 1

                # Update MySQL discovered_devices with ONLINE status
                db.upsert_discovered_device(
                    ip_address=ip,
                    mac_address=mac,
                    hostname=hostname,
                    is_authorized=is_auth,
                    is_blocked=is_blk,
                    status="ONLINE",
                    device_type=dev_type,
                    interface_name=iface_name,
                    vendor=vendor
                )

                # If IP is NOT in authorized list -> TRIGGER WARNING & EMAIL
                if not is_auth:
                    # Cooldown check: send email at most once every 10 minutes per IP
                    last_alert = self._last_alerted_times.get(ip, 0.0)
                    should_alert = (current_time - last_alert) > 600.0

                    if should_alert:
                        self._last_alerted_times[ip] = current_time
                        msg = f"Unauthorized device detected on OT Ethernet Network ({dev_type}). IP: {ip}, MAC: {mac}, Hostname: {hostname}, Vendor: {vendor}"
                        
                        # Record alert in MySQL
                        alert_id = db.record_alert(
                            ip_address=ip,
                            mac_address=mac,
                            hostname=hostname,
                            alert_type="ROGUE_OT_DEVICE",
                            message=msg,
                            email_sent=False
                        )

                        # Dispatch Email Notification Asynchronously (non-blocking)
                        threading.Thread(
                            target=self._dispatch_alert_async,
                            args=(alert_id, ip, mac, hostname, now_str),
                            daemon=True
                        ).start()

                        # Optional Automatic Firewall Block
                        if self.auto_block and not is_blk:
                            blocker.block_ip(ip, reason="Auto-blocked unauthorized rogue OT device")
                            blocked_count += 1

            self.switch_devices = switch_count
            self.plc_devices = plc_count
            self.authorized_devices = auth_count
            self.unauthorized_devices = unauth_count
            self.blocked_devices = blocked_count
            self.last_scan_timestamp = now_str

            return discovered

        finally:
            self.is_scanning = False

    def _dispatch_alert_async(
        self,
        alert_id: int,
        ip: str,
        mac: str,
        hostname: str,
        timestamp: str
    ) -> None:
        """Dispatches security alert email in background thread without blocking scanner."""
        try:
            email_sent = notifier.send_security_alert_email(
                rogue_ip=ip,
                mac_address=mac,
                hostname=hostname,
                timestamp=timestamp
            )
            if email_sent:
                db.mark_alert_email_sent(alert_id)
        except Exception as e:
            print(f"[-] Error in background alert dispatch: {e}")

    def get_status(self) -> Dict[str, Any]:
        """Returns real-time OT monitor stats for dashboard UI."""
        adapter = self.scanner.adapter_info or {}
        return {
            "is_scanning": self.is_scanning,
            "is_connected": self.scanner.is_connected,
            "error_message": self.scanner.error_message,
            "last_scan_timestamp": self.last_scan_timestamp,
            "scan_interval_seconds": self.scan_interval,
            "interface_name": self.scanner.interface_name,
            "interface_index": self.scanner.interface_index,
            "adapter_description": adapter.get("InterfaceDescription", "Realtek PCIe GbE Family Controller"),
            "adapter_mac": adapter.get("MacAddress", "40:C2:BA:AE:43:60"),
            "local_ip": self.scanner.local_ip,
            "subnet": self.scanner.subnet,
            "online_devices": self.online_devices,
            "switch_devices": self.switch_devices,
            "plc_devices": self.plc_devices,
            "total_devices": self.online_devices,
            "authorized_devices": self.authorized_devices,
            "unauthorized_devices": self.unauthorized_devices,
            "blocked_devices": self.blocked_devices,
            "auto_block_enabled": self.auto_block,
            "email_configured": notifier.is_email_configured(),
            "is_admin": blocker.is_admin(),
        }
