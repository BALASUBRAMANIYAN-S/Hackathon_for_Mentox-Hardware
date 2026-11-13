"""
NetSentinel: MySQL Database Layer.

Handles database connection, table initialization, and CRUD operations for:
- Authorized IP whitelist (exempt from warnings)
- Discovered network devices (IP, MAC, Hostname, Status)
- Security warnings and incidents (unauthorized rogue IPs)
- Blocked IPs (Windows Firewall blocked list)
"""

from __future__ import annotations
import os
import pymysql
import pymysql.cursors
from datetime import datetime
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

# Load configuration from .env
load_dotenv()

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "root")
DB_NAME = os.getenv("DB_NAME", "net_sentinel_db")


def get_connection(include_db: bool = True) -> pymysql.Connection:
    """Returns a pymysql connection to the database."""
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME if include_db else None,
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True,
    )


def init_db() -> None:
    """Creates database and schema tables if they do not exist."""
    # 1. Create database if missing
    root_conn = get_connection(include_db=False)
    with root_conn.cursor() as cur:
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci")
    root_conn.close()

    # 2. Create tables
    conn = get_connection(include_db=True)
    with conn.cursor() as cur:
        # Table 1: Authorized IPs Whitelist
        cur.execute("""
        CREATE TABLE IF NOT EXISTS authorized_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            mac_address VARCHAR(50),
            device_name VARCHAR(100) DEFAULT 'Authorized Device',
            added_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            notes TEXT
        ) ENGINE=InnoDB;
        """)

        # Table 2: Discovered Network Devices
        cur.execute("""
        CREATE TABLE IF NOT EXISTS discovered_devices (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            mac_address VARCHAR(50),
            hostname VARCHAR(150),
            is_authorized BOOLEAN DEFAULT FALSE,
            is_blocked BOOLEAN DEFAULT FALSE,
            first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_seen DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            status VARCHAR(20) DEFAULT 'ONLINE'
        ) ENGINE=InnoDB;
        """)

        # Table 3: Security Alerts (Rogue Device Detections)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS security_alerts (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL,
            mac_address VARCHAR(50),
            hostname VARCHAR(150),
            alert_type VARCHAR(50) DEFAULT 'ROGUE_IP_DETECTED',
            message TEXT,
            detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            email_sent BOOLEAN DEFAULT FALSE,
            is_resolved BOOLEAN DEFAULT FALSE
        ) ENGINE=InnoDB;
        """)

        # Table 4: Blocked IPs
        cur.execute("""
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id INT AUTO_INCREMENT PRIMARY KEY,
            ip_address VARCHAR(45) NOT NULL UNIQUE,
            reason VARCHAR(255) DEFAULT 'Unauthorized Rogue Device',
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            is_active BOOLEAN DEFAULT TRUE
        ) ENGINE=InnoDB;
        """)

    conn.close()
    print(f"[+] MySQL Database '{DB_NAME}' initialized successfully.")


# -------------------------------------------------------------
# Authorized IP Whitelist Operations
# -------------------------------------------------------------

def is_ip_authorized(ip_address: str) -> bool:
    """Checks if an IP is registered in the authorized whitelist."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM authorized_ips WHERE ip_address = %s", (ip_address,))
            return cur.fetchone() is not None
    finally:
        conn.close()


def add_authorized_ip(
    ip_address: str,
    mac_address: Optional[str] = None,
    device_name: str = "Authorized Device",
    notes: str = ""
) -> bool:
    """Adds an IP address to the authorized whitelist."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO authorized_ips (ip_address, mac_address, device_name, notes)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    mac_address = COALESCE(%s, mac_address),
                    device_name = %s,
                    notes = %s
            """, (ip_address, mac_address, device_name, notes, mac_address, device_name, notes))

            # Also update discovered_devices flag
            cur.execute("""
                UPDATE discovered_devices SET is_authorized = TRUE WHERE ip_address = %s
            """, (ip_address,))
        return True
    except Exception as e:
        print(f"[-] Error adding authorized IP: {e}")
        return False
    finally:
        conn.close()


def remove_authorized_ip(ip_address: str) -> bool:
    """Removes an IP address from the authorized whitelist."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM authorized_ips WHERE ip_address = %s", (ip_address,))
            cur.execute("UPDATE discovered_devices SET is_authorized = FALSE WHERE ip_address = %s", (ip_address,))
        return True
    except Exception as e:
        print(f"[-] Error removing authorized IP: {e}")
        return False
    finally:
        conn.close()


def get_all_authorized_ips() -> List[Dict[str, Any]]:
    """Returns all authorized IPs."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM authorized_ips ORDER BY added_at DESC")
            rows = cur.fetchall()
            for r in rows:
                if isinstance(r.get("added_at"), datetime):
                    r["added_at"] = r["added_at"].strftime("%Y-%m-%d %H:%M:%S")
            return rows
    finally:
        conn.close()


# -------------------------------------------------------------
# Discovered Network Devices Operations
# -------------------------------------------------------------

def upsert_discovered_device(
    ip_address: str,
    mac_address: Optional[str] = None,
    hostname: Optional[str] = None,
    is_authorized: bool = False,
    is_blocked: bool = False,
    status: str = "ONLINE"
) -> None:
    """Inserts or updates a detected network device."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO discovered_devices 
                    (ip_address, mac_address, hostname, is_authorized, is_blocked, status, last_seen)
                VALUES 
                    (%s, %s, %s, %s, %s, %s, NOW())
                ON DUPLICATE KEY UPDATE
                    mac_address = COALESCE(%s, mac_address),
                    hostname = COALESCE(%s, hostname),
                    is_authorized = %s,
                    is_blocked = %s,
                    status = %s,
                    last_seen = NOW()
            """, (
                ip_address, mac_address, hostname, is_authorized, is_blocked, status,
                mac_address, hostname, is_authorized, is_blocked, status
            ))
    finally:
        conn.close()


def get_all_discovered_devices() -> List[Dict[str, Any]]:
    """Retrieves all currently known network devices."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM discovered_devices ORDER BY is_authorized ASC, last_seen DESC")
            rows = cur.fetchall()
            for r in rows:
                for dt_col in ("first_seen", "last_seen"):
                    if isinstance(r.get(dt_col), datetime):
                        r[dt_col] = r[dt_col].strftime("%Y-%m-%d %H:%M:%S")
            return rows
    finally:
        conn.close()


def mark_absent_devices_offline(active_ips: List[str]) -> None:
    """Marks any device not present in active_ips as OFFLINE."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            if active_ips:
                placeholders = ", ".join(["%s"] * len(active_ips))
                cur.execute(f"UPDATE discovered_devices SET status = 'OFFLINE' WHERE ip_address NOT IN ({placeholders})", tuple(active_ips))
            else:
                cur.execute("UPDATE discovered_devices SET status = 'OFFLINE'")
    finally:
        conn.close()


def clear_offline_devices() -> int:
    """Purges all past disconnected (OFFLINE) devices from history."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM discovered_devices WHERE status = 'OFFLINE'")
            return cur.rowcount
    finally:
        conn.close()


def delete_discovered_device(ip_address: str) -> bool:
    """Removes a device record from the discovered list."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM discovered_devices WHERE ip_address = %s", (ip_address,))
        return True
    finally:
        conn.close()


# -------------------------------------------------------------
# Security Alerts & Incidents Operations
# -------------------------------------------------------------

def record_alert(
    ip_address: str,
    mac_address: Optional[str],
    hostname: Optional[str],
    alert_type: str = "ROGUE_IP_DETECTED",
    message: str = "",
    email_sent: bool = False
) -> int:
    """Logs a new security warning into MySQL."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO security_alerts 
                    (ip_address, mac_address, hostname, alert_type, message, email_sent, detected_at)
                VALUES 
                    (%s, %s, %s, %s, %s, %s, NOW())
            """, (ip_address, mac_address, hostname, alert_type, message, email_sent))
            return cur.lastrowid
    finally:
        conn.close()


def mark_alert_email_sent(alert_id: int) -> None:
    """Updates email_sent flag once alert notification is successfully dispatched."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE security_alerts SET email_sent = TRUE WHERE id = %s", (alert_id,))
    finally:
        conn.close()


def get_active_alerts(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns the most recent security warnings."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM security_alerts 
                ORDER BY detected_at DESC 
                LIMIT %s
            """, (limit,))
            rows = cur.fetchall()
            for r in rows:
                if isinstance(r.get("detected_at"), datetime):
                    r["detected_at"] = r["detected_at"].strftime("%Y-%m-%d %H:%M:%S")
            return rows
    finally:
        conn.close()


def clear_all_alerts() -> None:
    """Clears all stored security alerts."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("TRUNCATE TABLE security_alerts")
    finally:
        conn.close()


# -------------------------------------------------------------
# Blocked IPs Operations
# -------------------------------------------------------------

def is_ip_blocked(ip_address: str) -> bool:
    """Checks if an IP is currently blocked in the database."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT id FROM blocked_ips WHERE ip_address = %s AND is_active = TRUE", (ip_address,))
            return cur.fetchone() is not None
    finally:
        conn.close()


def record_blocked_ip(ip_address: str, reason: str = "Unauthorized Device") -> None:
    """Records an IP block in MySQL."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO blocked_ips (ip_address, reason, blocked_at, is_active)
                VALUES (%s, %s, NOW(), TRUE)
                ON DUPLICATE KEY UPDATE reason = %s, is_active = TRUE, blocked_at = NOW()
            """, (ip_address, reason, reason))
            cur.execute("UPDATE discovered_devices SET is_blocked = TRUE WHERE ip_address = %s", (ip_address,))
    finally:
        conn.close()


def record_unblocked_ip(ip_address: str) -> None:
    """Removes an IP block from MySQL."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM blocked_ips WHERE ip_address = %s", (ip_address,))
            cur.execute("UPDATE discovered_devices SET is_blocked = FALSE WHERE ip_address = %s", (ip_address,))
    finally:
        conn.close()


def get_all_blocked_ips() -> List[Dict[str, Any]]:
    """Returns all blocked IPs."""
    conn = get_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM blocked_ips WHERE is_active = TRUE ORDER BY blocked_at DESC")
            rows = cur.fetchall()
            for r in rows:
                if isinstance(r.get("blocked_at"), datetime):
                    r["blocked_at"] = r["blocked_at"].strftime("%Y-%m-%d %H:%M:%S")
            return rows
    finally:
        conn.close()
