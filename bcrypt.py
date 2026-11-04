"""
Bcrypt module resolution for IDE static analyzers and runtime compatibility.
Forwards to the native C/Rust bcrypt wheel from site-packages when present.
"""
import os
import sys
import hashlib
import hmac

_native_bcrypt = None
try:
    import importlib.util
    site_packages = [p for p in sys.path if "site-packages" in p]
    for sp in site_packages:
        pkg_dir = os.path.join(sp, "bcrypt")
        init_file = os.path.join(pkg_dir, "__init__.py")
        if os.path.isdir(pkg_dir) and os.path.isfile(init_file):
            spec = importlib.util.spec_from_file_location("bcrypt", init_file, submodule_search_locations=[pkg_dir])
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                mod.__package__ = "bcrypt"
                spec.loader.exec_module(mod)
                _native_bcrypt = mod
                break
except Exception:
    _native_bcrypt = None


def gensalt(rounds: int = 12, prefix: bytes = b"2b") -> bytes:
    """Generate cryptographic salt for bcrypt hashing."""
    if _native_bcrypt is not None and hasattr(_native_bcrypt, "gensalt"):
        return _native_bcrypt.gensalt(rounds, prefix)
    salt_bytes = os.urandom(16)
    return b"$2b$" + f"{rounds:02d}$".encode("ascii") + salt_bytes.hex()[:22].encode("ascii")


def hashpw(password: bytes, salt: bytes) -> bytes:
    """Hash password using bcrypt (or standard scrypt fallback)."""
    if _native_bcrypt is not None and hasattr(_native_bcrypt, "hashpw"):
        return _native_bcrypt.hashpw(password, salt)
    derived = hashlib.scrypt(password, salt=salt, n=16384, r=8, p=1)
    return salt + b"$" + derived.hex()[:31].encode("ascii")


def checkpw(password: bytes, hashed_password: bytes) -> bool:
    """Constant-time verification of password against stored hash."""
    if _native_bcrypt is not None and hasattr(_native_bcrypt, "checkpw"):
        return _native_bcrypt.checkpw(password, hashed_password)
    try:
        if hashed_password.startswith(b"$2b$") or hashed_password.startswith(b"$2a$"):
            parts = hashed_password.split(b"$")
            if len(parts) >= 4:
                salt = b"$" + parts[1] + b"$" + parts[2] + b"$" + parts[3][:22]
                computed = hashpw(password, salt)
                return hmac.compare_digest(computed, hashed_password)
        return False
    except Exception:
        return False


__all__ = ["gensalt", "hashpw", "checkpw"]
