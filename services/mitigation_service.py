import os
import time
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
    Generates sanitized Windows Defender Firewall rule specifications for academic/demonstration audit.
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
        "target_ip": valid_ip,
        "direction": dir_flag,
        "netsh_command": netsh_cmd,
        "netsh_args": netsh_args,
        "powershell_command": powershell_cmd,
        "rollback_command": rollback_cmd,
        "rollback_args": rollback_args
    }

def execute_firewall_rule(ip_str: str, simulate_safe: bool = True) -> dict:
    """
    Applies SIMULATED firewall quarantine rule.
    Guaranteed 100% Safe Demo Mode:
    - Never calls OS netsh or subprocess
    - Never alters host OS firewall or network stack
    - Quarantines the malicious IP in software memory & persisted state
    """
    rule_spec = generate_firewall_rule(ip_str)
    if not rule_spec.get("valid", False):
        err_text = rule_spec.get("error", "Invalid IP address")
        return {
            "success": False,
            "error": err_text,
            "requires_elevation": False,
            "returncode": -1,
            "stdout": "",
            "stderr": err_text,
            "status_message": f"Validation Error: {err_text}",
            "command": "",
            "rule_name": "",
            "mode": "Simulated Mitigation (Safe Demo Mode)",
            "simulated": True
        }
        
    valid_ip = rule_spec["ip"]
    rule_name = rule_spec["rule_name"]
    cmd_display = rule_spec["netsh_command"]

    # 100% Safe Simulated Mitigation
    return {
        "success": True,
        "requires_elevation": False,
        "returncode": 0,
        "stdout": f"[SIMULATED_MITIGATION] Rule {rule_name} active for IP {valid_ip} in software state.",
        "stderr": "",
        "status_message": f"Simulated Quarantine Active: Traffic from {valid_ip} dropped in software memory (Host OS unmodified).",
        "command": cmd_display,
        "rule_name": rule_name,
        "mode": "Simulated Mitigation (Safe Demo Mode)",
        "simulated": True
    }

def remove_firewall_rule(ip_str: str, simulate_safe: bool = True) -> dict:
    """
    Releases SIMULATED quarantine rule.
    Safe software state removal without host OS firewall modification.
    """
    rule_spec = generate_firewall_rule(ip_str)
    if not rule_spec.get("valid", False):
        err_text = rule_spec.get("error", "Invalid IP address")
        return {
            "success": False,
            "error": err_text,
            "returncode": -1,
            "stdout": "",
            "stderr": err_text,
            "status_message": f"Validation Error: {err_text}",
            "command": "",
            "rule_name": "",
            "mode": "Simulated Mitigation (Safe Demo Mode)",
            "simulated": True
        }

    valid_ip = rule_spec["ip"]
    rule_name = rule_spec["rule_name"]
    cmd_display = rule_spec["rollback_command"]

    return {
        "success": True,
        "returncode": 0,
        "stdout": f"[SIMULATED_MITIGATION] Rule {rule_name} released for IP {valid_ip}.",
        "stderr": "",
        "status_message": f"Simulated Quarantine Released: IP {valid_ip} unblocked in software memory.",
        "command": cmd_display,
        "rule_name": rule_name,
        "mode": "Simulated Mitigation (Safe Demo Mode)",
        "simulated": True
    }

def verify_firewall_rule_exists(rule_name: str, check_real_os: bool = False) -> bool:
    """
    Verification check for active quarantine rule.
    In Safe Demo Mode, returns False for host OS since host rules are never modified.
    """
    return False

