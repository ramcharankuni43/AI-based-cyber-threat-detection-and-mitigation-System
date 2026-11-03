import hashlib
import time

# Pre-computed SHA-256 hashes for default demo accounts with salt "cybersentinel_soc_salt"
# admin / admin123
# analyst / analyst123
SALT = "cybersentinel_soc_salt"

def _hash_pw(pw: str) -> str:
    return hashlib.sha256((SALT + pw).encode("utf-8")).hexdigest()

USER_DATABASE = {
    "admin": {
        "username": "admin",
        "display_name": "Chief Security Architect (Admin)",
        "password_hash": _hash_pw("admin123"),
        "role": "admin",
        "email": "soc-admin@enterprise.internal"
    },
    "analyst": {
        "username": "analyst",
        "display_name": "Tier-2 SOC Analyst",
        "password_hash": _hash_pw("analyst123"),
        "role": "analyst",
        "email": "soc-analyst@enterprise.internal"
    }
}

ROLE_PERMISSIONS = {
    "admin": {
        "view_dashboard": True,
        "view_monitoring": True,
        "investigate_threats": True,
        "approve_quarantine": True,
        "manual_unblock": True,
        "toggle_real_firewall": True,
        "retrain_models": True,
        "clear_demo_state": True,
        "view_audit_logs": True,
        "run_replay_tests": True,
        "batch_csv_inference": True
    },
    "analyst": {
        "view_dashboard": True,
        "view_monitoring": True,
        "investigate_threats": True,
        "approve_quarantine": True,
        "manual_unblock": True,
        "toggle_real_firewall": False, # Restricted: Admin only
        "retrain_models": False,       # Restricted: Admin only
        "clear_demo_state": False,     # Restricted: Admin only
        "view_audit_logs": True,
        "run_replay_tests": True,
        "batch_csv_inference": True
    }
}

def authenticate_user(username_input: str, password_input: str) -> dict | None:
    """Authenticates username and password against the secure credentials store."""
    if not username_input or not password_input:
        return None
    user = USER_DATABASE.get(username_input.strip().lower())
    if not user:
        return None
    input_hash = _hash_pw(password_input.strip())
    if input_hash == user["password_hash"]:
        return {
            "username": user["username"],
            "display_name": user["display_name"],
            "role": user["role"],
            "email": user["email"],
            "authenticated_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    return None

def has_permission(role: str, permission_name: str) -> bool:
    """Checks whether the given role has the requested capability."""
    perms = ROLE_PERMISSIONS.get(role, {})
    return perms.get(permission_name, False)
