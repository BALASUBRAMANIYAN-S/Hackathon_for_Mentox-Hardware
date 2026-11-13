"""
NetSentinel: Continuous Network Monitoring Engine.

Periodically sweeps the network, queries MySQL for authorization,
flags unrecognized rogue IPs, dispatches email notifications,
and optionally triggers automated firewall blocks.
"""

from __future__ import annotations
import os
import time
import threading
from datetime import datetime
from typing import Dict, Any, List, Set
from dotenv import load_dotenv

import db
from network_scanner import NetworkScanner
import blocker
import notifier

load_dotenv()


class ContinuousMonitor:
    def __init__(self):
        self.scanner = NetworkScanner()
        # Scan every 10 seconds as requested
        self.scan_interval = int(os.getenv("SCAN_INTERVAL_SECONDS", 10))
        self.auto_block = os.getenv("AUTO_BLOCK_ROGUE_IPS", "False").strip().lower() in ("true", "1")
        
        self.running = False
        self.is_scanning = False
        self._thread: threading.Thread | None = None
        self._scan_event = threading.Event()

        # Track alerted IPs to avoid email spamming within a cooldown period (10 minutes)
        self._last_alerted_times: Dict[str, float] = {}

        # Real-time state metrics
        self.last_scan_timestamp: str = "Never"
        self.total_devices: int = 0
        self.online_devices: int = 0
        self.offline_devices: int = 0
        self.authorized_devices: int = 0
        self.unauthorized_devices: int = 0
        self.blocked_devices: int = 0

    def start(self) -> None:
        """Starts the background continuous monitoring thread."""
        if not self.running:
            self.running = True
            self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self._thread.start()
            print("[+] NetSentinel Continuous Monitoring Thread started (10s cycle).")

    def stop(self) -> None:
        """Stops the background monitoring thread."""
        self.running = False
        self._scan_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)

    def trigger_scan_now(self) -> None:
        """Wakes up the scanner to execute an immediate network sweep."""
        self._scan_event.set()

    def _monitor_loop(self) -> None:
        while self.running:
            try:
                self.run_single_scan()
            except Exception as e:
                print(f"[-] Error during network scan cycle: {e}")

            # Wait 10 seconds or until manual scan trigger button is pressed
            self._scan_event.wait(timeout=self.scan_interval)
            self._scan_event.clear()

    def run_single_scan(self) -> List[Dict[str, Any]]:
        """Executes one scan cycle, reconciles with MySQL, and triggers warnings/emails."""
        self.is_scanning = True
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            # 1. Discover all active devices on network
            discovered = self.scanner.scan_network(active_sweep=False)
            active_ips = [dev["ip"] for dev in discovered]

            # 2. Mark any device not currently responding as OFFLINE in MySQL
            db.mark_absent_devices_offline(active_ips)

            self.online_devices = len(discovered)
            auth_count = 0
            unauth_count = 0
            blocked_count = 0

            current_time = time.time()

            # 3. Process currently online devices
            for dev in discovered:
                ip = dev["ip"]
                mac = dev["mac"]
                hostname = dev["hostname"]

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
                    status="ONLINE"
                )

                # If IP is NOT in authorized list -> TRIGGER WARNING & EMAIL
                if not is_auth:
                    # Cooldown check: send email at most once every 10 minutes per IP
                    last_alert = self._last_alerted_times.get(ip, 0.0)
                    should_alert = (current_time - last_alert) > 600.0

                    if should_alert:
                        self._last_alerted_times[ip] = current_time
                        msg = f"Unregistered device detected active on network. IP: {ip}, MAC: {mac}, Hostname: {hostname}"
                        
                        # Record alert in MySQL
                        alert_id = db.record_alert(
                            ip_address=ip,
                            mac_address=mac,
                            hostname=hostname,
                            alert_type="ROGUE_IP_DETECTED",
                            message=msg,
                            email_sent=False
                        )

                        # Dispatch Email Notification
                        email_sent = notifier.send_security_alert_email(
                            rogue_ip=ip,
                            mac_address=mac,
                            hostname=hostname,
                            timestamp=now_str
                        )
                        if email_sent:
                            db.mark_alert_email_sent(alert_id)

                        # Optional Automatic Firewall Block
                        if self.auto_block and not is_blk:
                            blocker.block_ip(ip, reason="Auto-blocked unauthorized rogue IP")
                            blocked_count += 1

            self.authorized_devices = auth_count
            self.unauthorized_devices = unauth_count
            self.blocked_devices = blocked_count
            self.last_scan_timestamp = now_str

            return discovered

        finally:
            self.is_scanning = False

    def get_status(self) -> Dict[str, Any]:
        """Returns real-time monitor stats for dashboard UI."""
        return {
            "is_scanning": self.is_scanning,
            "is_connected": self.scanner.is_connected,
            "last_scan_timestamp": self.last_scan_timestamp,
            "scan_interval_seconds": self.scan_interval,
            "local_ip": self.scanner.local_ip,
            "subnet": self.scanner.subnet,
            "online_devices": self.online_devices,
            "total_devices": self.online_devices,
            "authorized_devices": self.authorized_devices,
            "unauthorized_devices": self.unauthorized_devices,
            "blocked_devices": self.blocked_devices,
            "auto_block_enabled": self.auto_block,
            "email_configured": notifier.is_email_configured(),
        }
