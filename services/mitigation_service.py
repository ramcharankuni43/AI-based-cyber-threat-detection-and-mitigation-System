import os
import time
import subprocess
import ipaddress

# Whitelist of Trusted Protected Specific IPs (Critical Infrastructure)
TRUSTED_WHITELIST_IPS = {
    "10.0.0.1": "Perimeter Default Gateway",
    "8.8.8.8": "Primary Google Public DNS",
    "1.1.1.1": "Cloudflare Anycast Resolver",
    "127.0.0.1": "Loopback Localhost Interface",
    "::1": "IPv6 Loopback Interface",
    "10.0.0.254": "Internal DNS Server",
    "192.168.1.1": "Core Switch Gateway"
}

# Protected CIDR Subnets (Internal Subnet Range)
PROTECTED_CIDR_SUBNETS = [
    (ipaddress.ip_network("10.0.0.0/24"), "Protected Internal Subnet"),
    (ipaddress.ip_network("127.0.0.0/8"), "Localhost Loopback Network"),
    (ipaddress.ip_network("192.168.1.0/24"), "Protected Management LAN")
]

def check_ip_whitelist(ip_str: str) -> tuple[bool, str]:
    """
    Checks if an IP address is immune to quarantine via specific IP whitelist or CIDR subnet.
    Returns (is_whitelisted: bool, reason: str).
    """
    if not ip_str or not isinstance(ip_str, str):
        return False, ""
    
    clean_ip = ip_str.strip()
    if clean_ip in TRUSTED_WHITELIST_IPS:
        return True, TRUSTED_WHITELIST_IPS[clean_ip]
        
    try:
        ip_obj = ipaddress.ip_address(clean_ip)
        for subnet, desc in PROTECTED_CIDR_SUBNETS:
            if ip_obj in subnet:
                return True, f"{desc} ({subnet})"
    except ValueError:
        pass
        
    return False, ""

def validate_ip_address(ip_str: str) -> str:
    """
    Validates that ip_str is a legitimate IPv4 or IPv6 address.
    Returns normalized canonical IP string if valid, otherwise raises ValueError.
    Prevents shell command injection, formatting bypasses, and malformed inputs.
    """
    if not ip_str or not isinstance(ip_str, str):
        raise ValueError(f"Invalid IP address input: '{ip_str}' (expected non-empty string)")
    clean = ip_str.strip()
    try:
        ip_obj = ipaddress.ip_address(clean)
        return str(ip_obj)
    except ValueError as e:
        raise ValueError(f"Invalid IP address '{clean}': {e}")

def is_valid_ip(ip_str: str) -> bool:
    """Checks if an input string is a valid IPv4 or IPv6 address."""
    try:
        validate_ip_address(ip_str)
        return True
    except (ValueError, TypeError):
        return False

def is_safe_to_block_ip(ip_str: str) -> tuple[bool, str]:
    """
    Strict safety check: Verifies that an IP address is safe to block on host firewalls.
    Rejects loopback, unspecified (0.0.0.0), broadcast, multicast, and allowlisted infrastructure.
    """
    try:
        canonical_ip = validate_ip_address(ip_str)
    except ValueError as e:
        return False, str(e)

    ip_obj = ipaddress.ip_address(canonical_ip)

    # 1. Reject Loopback
    if ip_obj.is_loopback:
        return False, "Cannot block loopback localhost interface (system instability hazard)"

    # 2. Reject Unspecified (0.0.0.0 or ::)
    if ip_obj.is_unspecified:
        return False, "Cannot block unspecified address (0.0.0.0 / ::)"

    # 3. Reject Multicast
    if ip_obj.is_multicast:
        return False, "Cannot block multicast IP group"

    # 4. Reject IPv4 Broadcast
    if isinstance(ip_obj, ipaddress.IPv4Address) and str(ip_obj) == "255.255.255.255":
        return False, "Cannot block global broadcast address"

    # 5. Reject Whitelisted / Protected Infrastructure
    is_whitelisted, reason = check_ip_whitelist(canonical_ip)
    if is_whitelisted:
        return False, f"Protected infrastructure IP: {reason}"

    return True, "Safe to block"

def generate_firewall_rule(ip_str: str, direction: str = "inbound") -> dict:
    """
    Generates sanitized Windows Defender Firewall rule specifications.
    Performs strict safety checks to prevent self-lockout or command injection.
    """
    try:
        valid_ip = validate_ip_address(ip_str)
    except ValueError as err:
        return {
            "valid": False,
            "error": str(err),
            "ip": str(ip_str),
            "rule_name": "",
            "netsh_command": "",
            "netsh_args": [],
            "powershell_command": "",
            "rollback_command": "",
            "rollback_args": []
        }

    safe, reason = is_safe_to_block_ip(valid_ip)
    if not safe:
        return {
            "valid": False,
            "error": f"Safety Violation: {reason}",
            "ip": valid_ip,
            "rule_name": "",
            "netsh_command": "",
            "netsh_args": [],
            "powershell_command": "",
            "rollback_command": "",
            "rollback_args": []
        }

    sanitized_ip_tag = valid_ip.replace(".", "_").replace(":", "_")
    rule_name = f"AI_IDS_BLOCK_{sanitized_ip_tag}"
    dir_flag = "in" if direction.lower() == "inbound" else "out"

    netsh_args = ["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", f"dir={dir_flag}", "action=block", f"remoteip={valid_ip}"]
    rollback_args = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"]

    netsh_cmd = f'netsh advfirewall firewall add rule name="{rule_name}" dir={dir_flag} action=block remoteip={valid_ip}'
    powershell_cmd = f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction {"Inbound" if dir_flag=="in" else "Outbound"} -Action Block -RemoteAddress "{valid_ip}"'
    rollback_cmd = f'netsh advfirewall firewall delete rule name="{rule_name}"'

    return {
        "valid": True,
        "error": None,
        "rule_name": rule_name,
        "ip": valid_ip,
        "direction": dir_flag,
        "netsh_command": netsh_cmd,
        "netsh_args": netsh_args,
        "powershell_command": powershell_cmd,
        "rollback_command": rollback_cmd,
        "rollback_args": rollback_args
    }

def verify_firewall_rule_exists(rule_name: str) -> bool:
    """Queries netsh to verify if a firewall rule is physically registered on host OS."""
    try:
        proc = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
            shell=False,
            timeout=5
        )
        return (proc.returncode == 0) and ("rule name:" in proc.stdout.lower() or rule_name.lower() in proc.stdout.lower())
    except Exception:
        return False

def execute_firewall_rule(ip_str: str, simulate_safe: bool = True) -> dict:
    """
    Applies firewall quarantine rule.
    - simulate_safe=True: Safe Sandbox Lab mode (no changes to host OS firewall).
    - simulate_safe=False: Executes netsh rule with verified rule existence check.
    """
    rule_spec = generate_firewall_rule(ip_str)
    if not rule_spec.get("valid", False):
        return {
            "success": False,
            "requires_elevation": False,
            "returncode": -1,
            "stdout": "",
            "stderr": rule_spec.get("error", "Invalid IP address"),
            "status_message": f"Validation Error: {rule_spec.get('error')}",
            "command": "",
            "rule_name": "",
            "mode": "Simulated Sandbox" if simulate_safe else "Windows Defender Netsh",
            "simulated": simulate_safe
        }
        
    valid_ip = rule_spec["ip"]
    rule_name = rule_spec["rule_name"]
    cmd_display = rule_spec["netsh_command"]
    args_list = rule_spec["netsh_args"]

    if simulate_safe:
        return {
            "success": True,
            "requires_elevation": False,
            "returncode": 0,
            "stdout": f"[SIMULATED_LAB] Rule {rule_name} added for IP {valid_ip} in software memory.",
            "stderr": "",
            "status_message": f"Simulated Quarantine Active: Traffic from {valid_ip} dropped in memory (Host OS unmodified)",
            "command": cmd_display,
            "rule_name": rule_name,
            "mode": "Simulated Sandbox",
            "simulated": True
        }

    try:
        proc = subprocess.run(args_list, shell=False, capture_output=True, text=True, timeout=8)
        stdout_txt = proc.stdout.strip()
        stderr_txt = proc.stderr.strip()
        combined_out = f"{stdout_txt} {stderr_txt}".strip()

        requires_elevation = "requires elevation" in combined_out.lower() or "administrator" in combined_out.lower()
        cmd_ok = (proc.returncode == 0) and ("ok." in stdout_txt.lower() or "ok" in stdout_txt.lower())

        # Post-execution verification
        rule_verified = verify_firewall_rule_exists(rule_name) if cmd_ok else False
        success = cmd_ok and rule_verified

        if success:
            status_msg = f"Successfully committed and verified in Windows Defender Firewall ({rule_name})"
        elif requires_elevation:
            status_msg = "Elevation required: Run terminal as Administrator to enforce OS rule"
        elif cmd_ok and not rule_verified:
            status_msg = "Command completed but netsh rule verification failed"
        else:
            status_msg = f"Command failed: {combined_out}"

        return {
            "success": success,
            "requires_elevation": requires_elevation,
            "returncode": proc.returncode,
            "stdout": stdout_txt,
            "stderr": stderr_txt,
            "status_message": status_msg,
            "command": cmd_display,
            "rule_name": rule_name,
            "mode": "Windows Defender Netsh",
            "simulated": False
        }
    except Exception as e:
        return {
            "success": False,
            "requires_elevation": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "status_message": f"Execution error: {str(e)}",
            "command": cmd_display,
            "rule_name": rule_name,
            "mode": "Windows Defender Netsh",
            "simulated": False
        }

def remove_firewall_rule(ip_str: str, simulate_safe: bool = True) -> dict:
    """
    Deletes or simulates deletion of Windows Defender firewall rule with rollback verification.
    """
    rule_spec = generate_firewall_rule(ip_str)
    if not rule_spec.get("valid", False):
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": rule_spec.get("error", "Invalid IP address"),
            "status_message": f"Validation Error: {rule_spec.get('error')}",
            "command": "",
            "rule_name": "",
            "mode": "Simulated Sandbox" if simulate_safe else "Windows Defender Netsh",
            "simulated": simulate_safe
        }

    valid_ip = rule_spec["ip"]
    rule_name = rule_spec["rule_name"]
    cmd_display = rule_spec["rollback_command"]
    args_list = rule_spec["rollback_args"]

    if simulate_safe:
        return {
            "success": True,
            "returncode": 0,
            "stdout": f"[SIMULATED_LAB] Rule {rule_name} removed for IP {valid_ip}.",
            "stderr": "",
            "status_message": f"Simulated Quarantine Released: IP {valid_ip} unblocked in memory.",
            "command": cmd_display,
            "rule_name": rule_name,
            "mode": "Simulated Sandbox",
            "simulated": True
        }

    try:
        proc = subprocess.run(args_list, shell=False, capture_output=True, text=True, timeout=8)
        stdout_txt = proc.stdout.strip()
        stderr_txt = proc.stderr.strip()
        combined_out = f"{stdout_txt} {stderr_txt}".strip()

        # Check deletion
        still_exists = verify_firewall_rule_exists(rule_name)
        success = (proc.returncode == 0) and not still_exists

        return {
            "success": success,
            "returncode": proc.returncode,
            "stdout": stdout_txt,
            "stderr": stderr_txt,
            "status_message": "Firewall rule successfully deleted and verified" if success else (
                f"Rule still detected in firewall table after deletion attempt: {combined_out}"
            ),
            "command": cmd_display,
            "rule_name": rule_name,
            "mode": "Windows Defender Netsh",
            "simulated": False
        }
    except Exception as e:
        return {
            "success": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "status_message": f"Rollback error: {str(e)}",
            "command": cmd_display,
            "rule_name": rule_name,
            "mode": "Windows Defender Netsh",
            "simulated": False
        }
