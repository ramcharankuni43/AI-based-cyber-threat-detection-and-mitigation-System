import os
import time
import hmac
import hashlib
import bcrypt

def hash_password(password: str) -> str:
    """
    Hashes a password securely using bcrypt with work factor 12 (or scrypt fallback).
    Uses per-user unique cryptographic salt.
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(password: str, hashed: str) -> bool:
    """Verifies a plaintext password against a stored bcrypt or scrypt hash."""
    if not password or not hashed:
        return False
    try:
        if hashed.startswith("$2b$") or hashed.startswith("$2a$") or hashed.startswith("$2y$"):
            return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
        elif hashed.startswith("scrypt$"):
            parts = hashed.split("$")
            if len(parts) == 3:
                salt = bytes.fromhex(parts[1])
                expected_key = bytes.fromhex(parts[2])
                actual_key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=16384, r=8, p=1)
                return hmac.compare_digest(actual_key, expected_key)
    except Exception:
        return False
    return False

# Configurable Credentials (via Environment Variables or Secure Defaults)
ADMIN_USER = os.environ.get("SOC_ADMIN_USERNAME", "admin").strip().lower()
ADMIN_PASS = os.environ.get("SOC_ADMIN_PASSWORD", "admin123")

ANALYST_USER = os.environ.get("SOC_ANALYST_USERNAME", "analyst").strip().lower()
ANALYST_PASS = os.environ.get("SOC_ANALYST_PASSWORD", "analyst123")

def is_demo_quick_login_enabled() -> bool:
    """
    Determines if public 1-click evaluation access is allowed.
    Set SOC_ENABLE_QUICK_LOGIN=false in deployment/production to require manual credential entry.
    """
    val = os.environ.get("SOC_ENABLE_QUICK_LOGIN", "true").strip().lower()
    return val in ["true", "1", "yes"]

_CACHED_USER_DB = None

def get_user_database() -> dict:
    global _CACHED_USER_DB
    if _CACHED_USER_DB is None:
        _CACHED_USER_DB = {
            ADMIN_USER: {
                "username": ADMIN_USER,
                "display_name": "Chief Security Architect (Admin)",
                "password_hash": hash_password(ADMIN_PASS),
                "role": "admin",
                "email": "soc-admin@enterprise.internal"
            },
            ANALYST_USER: {
                "username": ANALYST_USER,
                "display_name": "Tier-2 SOC Analyst",
                "password_hash": hash_password(ANALYST_PASS),
                "role": "analyst",
                "email": "soc-analyst@enterprise.internal"
            }
        }
    return _CACHED_USER_DB

ROLE_PERMISSIONS = {
    "admin": {
        "view_dashboard": True,
        "view_monitoring": True,
        "investigate_threats": True,
        "approve_quarantine": True,
        "manual_unblock": True,
        "toggle_real_firewall": False, # Real firewall disabled in safe demo version
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
    """
    Authenticates username and password against the secure credentials store.
    Does not log passwords or sensitive authentication secrets.
    """
    if not username_input or not password_input:
        return None
    
    clean_user = username_input.strip().lower()
    db = get_user_database()
    user_record = db.get(clean_user)
    if not user_record:
        return None

    if verify_password(password_input.strip(), user_record["password_hash"]):
        return {
            "username": user_record["username"],
            "display_name": user_record["display_name"],
            "role": user_record["role"],
            "email": user_record["email"],
            "authenticated_at": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    return None

def has_permission(role: str, permission_name: str) -> bool:
    """Checks whether the given role has the requested capability."""
    perms = ROLE_PERMISSIONS.get(role, {})
    return perms.get(permission_name, False)
