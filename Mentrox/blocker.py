"""
NetSentinel: Windows Firewall IP Blocker and Mitigator.

Blocks and unblocks unauthorized rogue IPs using Windows Firewall rules:
`netsh advfirewall firewall add rule name="NetSentinel_Block_In_{ip}" dir=in action=block remoteip={ip}`
`netsh advfirewall firewall add rule name="NetSentinel_Block_Out_{ip}" dir=out action=block remoteip={ip}`
"""

from __future__ import annotations
import subprocess
from typing import Dict, Any
import db


def block_ip(ip_address: str, reason: str = "Unauthorized Rogue Device") -> Dict[str, Any]:
    """
    Blocks incoming and outgoing communication with an IP address via Windows Firewall.
    Also persists the block in the MySQL database.
    """
    in_rule_name = f"NetSentinel_Block_In_{ip_address}"
    out_rule_name = f"NetSentinel_Block_Out_{ip_address}"

    firewall_success = True
    error_msg = ""

    # Execute Windows Firewall Inbound Block
    cmd_in = f'netsh advfirewall firewall add rule name="{in_rule_name}" dir=in action=block remoteip={ip_address}'
    cmd_out = f'netsh advfirewall firewall add rule name="{out_rule_name}" dir=out action=block remoteip={ip_address}'

    try:
        res_in = subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
        res_out = subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
        if res_in.returncode != 0 and "administrator" in res_in.stderr.lower():
            firewall_success = False
            error_msg = "Administrator privilege required to create Windows Firewall rule."
    except Exception as e:
        firewall_success = False
        error_msg = str(e)

    # Record block in MySQL database
    db.record_blocked_ip(ip_address, reason=reason)

    return {
        "success": True,
        "ip_address": ip_address,
        "firewall_active": firewall_success,
        "message": f"IP {ip_address} is now BLOCKED." + (f" ({error_msg})" if error_msg else ""),
    }


def unblock_ip(ip_address: str) -> Dict[str, Any]:
    """Removes firewall rules and updates MySQL database."""
    in_rule_name = f"NetSentinel_Block_In_{ip_address}"
    out_rule_name = f"NetSentinel_Block_Out_{ip_address}"

    cmd_in = f'netsh advfirewall firewall delete rule name="{in_rule_name}"'
    cmd_out = f'netsh advfirewall firewall delete rule name="{out_rule_name}"'

    try:
        subprocess.run(cmd_in, shell=True, capture_output=True, text=True)
        subprocess.run(cmd_out, shell=True, capture_output=True, text=True)
    except Exception:
        pass

    # Remove block in MySQL database
    db.record_unblocked_ip(ip_address)

    return {
        "success": True,
        "ip_address": ip_address,
        "message": f"IP {ip_address} has been UNBLOCKED.",
    }
