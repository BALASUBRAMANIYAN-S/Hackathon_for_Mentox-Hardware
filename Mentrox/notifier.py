"""
NetSentinel: Email Alert Dispatcher.

Sends immediate HTML security alerts when an unauthorized rogue IP is detected.
Reads SMTP credentials and Gmail App Password securely from .env.
"""

from __future__ import annotations
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()


def is_email_configured() -> bool:
    """Verifies whether real SMTP credentials are provided in .env."""
    sender = os.getenv("SENDER_EMAIL", "").strip()
    pw = os.getenv("SENDER_APP_PASSWORD", "").strip()
    enabled = os.getenv("ENABLE_EMAIL_ALERTS", "True").strip().lower() in ("true", "1", "yes")

    if not enabled:
        return False
    if not sender or "@" not in sender or "your_email" in sender:
        return False
    if not pw or "your_" in pw or len(pw) < 6:
        return False
    return True


def send_security_alert_email(
    rogue_ip: str,
    mac_address: str = "Unknown",
    hostname: str = "Unknown",
    timestamp: str = ""
) -> bool:
    """
    Dispatches a high-priority security alert email for an unauthorized rogue IP.
    Returns True if sent, False otherwise.
    """
    if not is_email_configured():
        print(f"[EMAIL INFO] Alert email skipped for {rogue_ip}: SENDER_APP_PASSWORD not yet entered in .env.")
        return False

    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com").strip()
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    use_tls = os.getenv("SMTP_USE_TLS", "True").strip().lower() in ("true", "1")
    sender_email = os.getenv("SENDER_EMAIL", "").strip()
    sender_pw = os.getenv("SENDER_APP_PASSWORD", "").strip()
    recipient_email = os.getenv("ALERT_RECIPIENT_EMAIL", sender_email).strip()

    dt_str = timestamp or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Compose Email Message
    msg = MIMEMultipart("alternative")
    msg["Subject"] = f"🚨 SECURITY WARNING: Unauthorized Rogue Device Detected on Network [{rogue_ip}]"
    msg["From"] = f"NetSentinel Security <{sender_email}>"
    msg["To"] = recipient_email

    # Plain text version
    text_content = f"""
SECURITY ALERT: Rogue Device Detected!

An unauthorized device has connected to your network:
- IP Address: {rogue_ip}
- MAC Address: {mac_address}
- Hostname: {hostname}
- Detection Time: {dt_str}

Action: Log in to your NetSentinel Dashboard to authorize or block this device immediately.
"""

    # Rich HTML version
    html_content = f"""
<!DOCTYPE html>
<html>
<head>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #0f172a; color: #f8fafc; margin: 0; padding: 24px; }}
    .container {{ max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 12px; border: 1px solid #334155; overflow: hidden; }}
    .header {{ background: #dc2626; color: white; padding: 20px; text-align: center; }}
    .header h2 {{ margin: 0; font-size: 20px; letter-spacing: 0.5px; }}
    .content {{ padding: 24px; }}
    .alert-box {{ background: rgba(220, 38, 38, 0.1); border-left: 4px solid #ef4444; padding: 14px; border-radius: 6px; margin-bottom: 20px; }}
    .details-table {{ width: 100%; border-collapse: collapse; margin-top: 16px; font-size: 14px; }}
    .details-table td {{ padding: 10px 12px; border-bottom: 1px solid #334155; }}
    .details-table td.label {{ color: #94a3b8; font-weight: 600; width: 35%; }}
    .details-table td.val {{ color: #f8fafc; font-family: monospace; font-weight: bold; }}
    .footer {{ padding: 16px; text-align: center; color: #64748b; font-size: 12px; background: #0f172a; border-top: 1px solid #334155; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h2>🚨 ROGUE DEVICE DETECTED ON LOCAL NETWORK</h2>
    </div>
    <div class="content">
      <div class="alert-box">
        <strong style="color: #ef4444;">WARNING:</strong> An unrecognized device not present in your MySQL authorized whitelist has connected to your network.
      </div>

      <table class="details-table">
        <tr>
          <td class="label">IP Address:</td>
          <td class="val" style="color: #f87171;">{rogue_ip}</td>
        </tr>
        <tr>
          <td class="label">MAC Address:</td>
          <td class="val">{mac_address}</td>
        </tr>
        <tr>
          <td class="label">Host Name:</td>
          <td class="val">{hostname}</td>
        </tr>
        <tr>
          <td class="label">Detection Timestamp:</td>
          <td class="val">{dt_str}</td>
        </tr>
        <tr>
          <td class="label">Database Status:</td>
          <td class="val" style="color: #fbbf24;">UNAUTHORIZED (WARNING ACTIVE)</td>
        </tr>
      </table>

      <p style="margin-top: 24px; font-size: 13px; color: #cbd5e1;">
        Recommended Action: Open your <strong>NetSentinel Web Dashboard</strong> to either <strong>Authorize</strong> this device if legitimate, or <strong>Block</strong> it via Windows Firewall.
      </p>
    </div>
    <div class="footer">
      Sent automatically by NetSentinel Intrusion & Rogue IP Detector
    </div>
  </div>
</body>
</html>
"""

    msg.attach(MIMEText(text_content, "plain"))
    msg.attach(MIMEText(html_content, "html"))

    try:
        if use_tls:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)

        server.login(sender_email, sender_pw)
        server.send_message(msg)
        server.quit()
        print(f"[+] Security Alert Email sent successfully for rogue IP: {rogue_ip} -> {recipient_email}")
        return True
    except Exception as e:
        print(f"[-] Failed to dispatch alert email: {e}")
        return False


def test_email_settings() -> dict:
    """Tests the configured email credentials by checking connection and authentication."""
    if not is_email_configured():
        return {
            "success": False,
            "message": "Email is not configured yet. Please enter SENDER_EMAIL and SENDER_APP_PASSWORD in .env file."
        }

    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com").strip()
    smtp_port = int(os.getenv("SMTP_PORT", 587))
    use_tls = os.getenv("SMTP_USE_TLS", "True").strip().lower() in ("true", "1")
    sender_email = os.getenv("SENDER_EMAIL", "").strip()
    sender_pw = os.getenv("SENDER_APP_PASSWORD", "").strip()

    try:
        if use_tls:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=8)
            server.ehlo()
            server.starttls()
            server.ehlo()
        else:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=8)

        server.login(sender_email, sender_pw)
        server.quit()
        return {"success": True, "message": "SMTP Email connection and authentication verified!"}
    except Exception as e:
        return {"success": False, "message": f"SMTP Authentication failed: {str(e)}"}
