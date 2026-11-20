"""
NetSentinel: Windows Firewall Dynamic IP Blocker and Mitigator.

Dynamically blocks and unblocks unauthorized rogue IPs on the OT network
using bidirectional Windows Defender Firewall rules and ARP cache invalidation:
- Inbound Rule:  `NetSentinel_Block_In_{ip}`  (dir=in,  action=block, remoteip={ip}, protocol=any)
- Outbound Rule: `NetSentinel_Block_Out_{ip}` (dir=out, action=block, remoteip={ip}, protocol=any)

When blocked:
- Outbound ICMP (ping) and TCP/UDP packets from the host laptop to the device are dropped at the kernel IP layer.
- Inbound packets from the device to the host laptop are dropped.
- The physical switch port remains connected (green link LED), but zero IP packets can pass between host and target.

When unblocked:
- Both rules are deleted from Windows Firewall.
- Immediate ping responses and normal network communication resume.
"""

from __future__ import annotations
import os
import sys
import ctypes
import subprocess
import re
from typing import Dict, Any, Tuple
import db


def is_admin() -> bool:
    """Checks if the current Python process is running with Administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _get_rule_names(ip_address: str) -> Tuple[str, str]:
    """Generates standard inbound and outbound rule names for a given IP."""
    clean_ip = ip_address.strip()
    return f"NetSentinel_Block_In_{clean_ip}", f"NetSentinel_Block_Out_{clean_ip}"


def verify_firewall_rule(rule_name: str) -> bool:
    """Checks whether a specific Windows Firewall rule is currently active."""
    cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=5)
        # If rule exists, netsh returns exitcode 0 and prints rule details
        return res.returncode == 0 and "Enabled:" in res.stdout and "Action:" in res.stdout
    except Exception:
        return False


def check_ip_firewall_status(ip_address: str) -> Dict[str, Any]:
    """Returns the live Windows Firewall blocking status for a given IP."""
    in_rule, out_rule = _get_rule_names(ip_address)
    in_active = verify_firewall_rule(in_rule)
    out_active = verify_firewall_rule(out_rule)
    return {
        "ip_address": ip_address,
        "is_blocked_in": in_active,
        "is_blocked_out": out_active,
        "is_fully_blocked": in_active and out_active,
    }


def _execute_firewall_command(cmd: str) -> Tuple[bool, str]:
    """
    Executes a netsh firewall command.
    If running as Admin, runs directly via subprocess.
    If not running as Admin, attempts elevated execution via PowerShell Start-Process -Verb RunAs.
    Returns (success, output_message).
    """
    if is_admin():
        try:
            res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=8)
            combined_output = (res.stdout + " " + res.stderr).strip()
            if res.returncode == 0:
                return True, combined_output or "Ok."
            else:
                return False, combined_output or f"Command failed with exit code {res.returncode}"
        except Exception as e:
            return False, str(e)

    # Fallback for non-elevated process: attempt elevated execution through PowerShell
    try:
        ps_cmd = f"Start-Process cmd -ArgumentList '/c {cmd}' -Verb RunAs -WindowStyle Hidden -Wait"
        res = subprocess.run(["powershell", "-NoProfile", "-Command", ps_cmd], capture_output=True, text=True, timeout=12)
        if res.returncode == 0:
            return True, "Executed via elevated prompt."
        else:
            err = (res.stdout + " " + res.stderr).strip()
            return False, err or "Elevation was cancelled or not supported."
    except Exception as e:
        return False, str(e)


def block_ip(ip_address: str, reason: str = "Unauthorized Rogue OT Device") -> Dict[str, Any]:
    """
    Dynamically blocks incoming and outgoing network communication with an IP address.
    1. Removes any existing or duplicate rules for this IP.
    2. Adds Windows Defender Firewall Inbound Block rule.
    3. Adds Windows Defender Firewall Outbound Block rule.
    4. Invalidates the ARP entry to instantly drop established socket connections.
    5. Persists block state in MySQL database.
    """
    ip_address = ip_address.strip()
    in_rule, out_rule = _get_rule_names(ip_address)

    admin_mode = is_admin()

    # Step 1: Clean up any pre-existing rules first to prevent stale or duplicate states
    _execute_firewall_command(f'netsh advfirewall firewall delete rule name="{in_rule}"')
    _execute_firewall_command(f'netsh advfirewall firewall delete rule name="{out_rule}"')

    # Step 2: Build robust netsh commands
    # Explicitly set protocol=any, profile=any, enable=yes
    cmd_in = (
        f'netsh advfirewall firewall add rule name="{in_rule}" '
        f'dir=in action=block remoteip={ip_address} protocol=any profile=any enable=yes '
        f'description="NetSentinel OT: Block inbound traffic from rogue device"'
    )
    cmd_out = (
        f'netsh advfirewall firewall add rule name="{out_rule}" '
        f'dir=out action=block remoteip={ip_address} protocol=any profile=any enable=yes '
        f'description="NetSentinel OT: Block outbound traffic to rogue device"'
    )

    ok_in, msg_in = _execute_firewall_command(cmd_in)
    ok_out, msg_out = _execute_firewall_command(cmd_out)

    # Step 3: Verify whether Windows Firewall actually created the rules
    verified_in = verify_firewall_rule(in_rule)
    verified_out = verify_firewall_rule(out_rule)
    firewall_active = verified_in and verified_out

    # Step 4: Flush ARP entry so ping/TCP cannot use cached L2 mapping
    try:
        subprocess.run(f"arp -d {ip_address}", shell=True, capture_output=True, text=True, timeout=3)
    except Exception:
        pass

    # Step 5: Persist block state in MySQL
    db.record_blocked_ip(ip_address, reason=reason)

    if firewall_active:
        return {
            "success": True,
            "ip_address": ip_address,
            "firewall_active": True,
            "is_admin": admin_mode,
            "message": f"IP {ip_address} is now dynamically BLOCKED in Windows Firewall. All ping and socket traffic dropped.",
        }
    else:
        err_details = msg_out if not ok_out else msg_in
        return {
            "success": False,
            "ip_address": ip_address,
            "firewall_active": False,
            "is_admin": admin_mode,
            "message": (
                f"Failed to create Windows Firewall rule for {ip_address}. "
                "Administrator elevation is required to modify firewall rules. "
                "Please run NetSentinel using 'start_admin.bat' (Run as Administrator)."
            ),
            "details": err_details,
        }


def unblock_ip(ip_address: str) -> Dict[str, Any]:
    """
    Dynamically unblocks an IP address by deleting its Windows Firewall rules
    and clearing the block status in the MySQL database.
    """
    ip_address = ip_address.strip()
    in_rule, out_rule = _get_rule_names(ip_address)

    admin_mode = is_admin()

    cmd_del_in = f'netsh advfirewall firewall delete rule name="{in_rule}"'
    cmd_del_out = f'netsh advfirewall firewall delete rule name="{out_rule}"'

    _execute_firewall_command(cmd_del_in)
    _execute_firewall_command(cmd_del_out)

    # Verify rules are successfully removed
    verified_in = verify_firewall_rule(in_rule)
    verified_out = verify_firewall_rule(out_rule)
    still_blocked = verified_in or verified_out

    # Step: Invalidate ARP cache to force fresh resolution
    try:
        subprocess.run(f"arp -d {ip_address}", shell=True, capture_output=True, text=True, timeout=3)
    except Exception:
        pass

    # Remove block record from MySQL
    db.record_unblocked_ip(ip_address)

    if not still_blocked:
        return {
            "success": True,
            "ip_address": ip_address,
            "firewall_active": False,
            "is_admin": admin_mode,
            "message": f"IP {ip_address} has been UNBLOCKED. Full network communication and ping restored.",
        }
    else:
        return {
            "success": False,
            "ip_address": ip_address,
            "firewall_active": True,
            "is_admin": admin_mode,
            "message": (
                f"Failed to remove Windows Firewall rules for {ip_address}. "
                "Administrator privileges required. Please run using 'start_admin.bat'."
            ),
        }
