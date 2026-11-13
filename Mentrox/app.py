"""
NetSentinel: Web Application and REST API.

Provides real-time web dashboard for:
- Viewing all network devices (IP, MAC, Hostname, Online Status)
- Highlighting unauthorized rogue devices with WARNING badges
- Managing MySQL authorized whitelist (Add / Revoke)
- One-click Windows Firewall IP Blocking / Unblocking
- Managing Email alert settings and scan intervals
"""

from __future__ import annotations
import os
import json
import http.server
import socketserver
import urllib.parse
from pathlib import Path
from typing import Any
from dotenv import load_dotenv

import db
from monitor import ContinuousMonitor
import blocker
import notifier

load_dotenv()

STATIC_DIR = Path(__file__).parent / "static"
PORT = int(os.getenv("WEB_PORT", 5000))

# Initialize Database and Monitoring Engine
db.init_db()
monitor = ContinuousMonitor()
monitor.start()


class NetSentinelHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        if path in ("/", "/index.html"):
            self.serve_file(STATIC_DIR / "index.html", "text/html")
        elif path == "/style.css":
            self.serve_file(STATIC_DIR / "style.css", "text/css")
        elif path == "/app.js":
            self.serve_file(STATIC_DIR / "app.js", "application/javascript")
        elif path == "/api/status":
            self.send_json(monitor.get_status())
        elif path == "/api/devices":
            self.send_json(db.get_all_discovered_devices())
        elif path == "/api/alerts":
            self.send_json(db.get_active_alerts())
        elif path == "/api/authorized":
            self.send_json(db.get_all_authorized_ips())
        elif path == "/api/blocked":
            self.send_json(db.get_all_blocked_ips())
        else:
            self.send_error(404, "Page or endpoint not found")

    def do_POST(self) -> None:
        parsed_url = urllib.parse.urlparse(self.path)
        path = parsed_url.path

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length > 0 else b"{}"

        try:
            payload = json.loads(body.decode("utf-8")) if body else {}
        except Exception:
            payload = {}

        if path == "/api/scan":
            monitor.trigger_scan_now()
            self.send_json({"status": "scan_triggered"})

        elif path == "/api/authorize":
            ip = payload.get("ip", "").strip()
            mac = payload.get("mac", "")
            name = payload.get("name", "Authorized Device")
            notes = payload.get("notes", "Whitelisted via Web Dashboard")
            if ip:
                success = db.add_authorized_ip(ip, mac, name, notes)
                self.send_json({"status": "success" if success else "failed", "ip": ip})
            else:
                self.send_error(400, "Missing IP address")

        elif path == "/api/deauthorize":
            ip = payload.get("ip", "").strip()
            if ip:
                success = db.remove_authorized_ip(ip)
                self.send_json({"status": "success" if success else "failed", "ip": ip})
            else:
                self.send_error(400, "Missing IP address")

        elif path == "/api/block":
            ip = payload.get("ip", "").strip()
            reason = payload.get("reason", "Manual block from dashboard")
            if ip:
                res = blocker.block_ip(ip, reason)
                self.send_json(res)
            else:
                self.send_error(400, "Missing IP address")

        elif path == "/api/unblock":
            ip = payload.get("ip", "").strip()
            if ip:
                res = blocker.unblock_ip(ip)
                self.send_json(res)
            else:
                self.send_error(400, "Missing IP address")

        elif path == "/api/clear_alerts":
            db.clear_all_alerts()
            self.send_json({"status": "cleared"})

        elif path == "/api/clear_offline":
            count = db.clear_offline_devices()
            self.send_json({"status": "cleared", "deleted_count": count})

        elif path == "/api/delete_device":
            ip = payload.get("ip", "").strip()
            if ip:
                db.delete_discovered_device(ip)
                self.send_json({"status": "deleted", "ip": ip})
            else:
                self.send_error(400, "Missing IP address")

        elif path == "/api/test_email":
            res = notifier.test_email_settings()
            self.send_json(res)

        else:
            self.send_error(404, "Endpoint not found")

    def serve_file(self, filepath: Path, content_type: str) -> None:
        if not filepath.exists():
            self.send_error(404, "File not found")
            return
        with open(filepath, "rb") as f:
            data = f.read()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, data: Any) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        # Suppress noisy HTTP polling logs
        pass


class ReusableTCPServer(socketserver.TCPServer):
    allow_reuse_address = True


def main():
    global PORT
    import sys
    sys.stdout.reconfigure(line_buffering=True)

    server = None
    for test_port in [PORT, 5000, 5001, 5050]:
        try:
            server = ReusableTCPServer(("0.0.0.0", test_port), NetSentinelHandler)
            PORT = test_port
            break
        except OSError:
            continue

    if not server:
        print(f"[-] Could not bind to port {PORT}. Please ensure previous python processes are closed.")
        return

    print("=" * 72)
    print("   NETSENTINEL: REAL-TIME NETWORK INTRUSION & ROGUE IP DETECTOR")
    print("=" * 72)
    print(f"[+] Web Dashboard running at: http://localhost:{PORT}")
    print(f"[+] MySQL Database: {db.DB_NAME} on {db.DB_HOST}:{db.DB_PORT}")
    print(f"[+] Local Network Subnet: {monitor.scanner.subnet} (Local IP: {monitor.scanner.local_ip})")
    print(f"[+] Email Alerts: {'ENABLED' if notifier.is_email_configured() else 'DISABLED (Waiting for App Password in .env)'}")
    print("[+] Press Ctrl+C to stop the server.")
    print("=" * 72)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping NetSentinel...")
        monitor.stop()
        server.shutdown()
        print("[+] NetSentinel stopped cleanly.")


if __name__ == "__main__":
    main()
