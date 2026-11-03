import os
import json
import time
import shutil
import tempfile
import threading

class StateStore:
    """
    Thread-safe, atomic persistence manager for SOC operational state.
    Guarantees zero file corruption on crashes/power cuts via atomic tempfile replacement
    and maintains automatic .bak recovery backups.
    """
    def __init__(self, state_file_path: str):
        self.state_file_path = state_file_path
        self.backup_file_path = state_file_path + ".bak"
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.state_file_path), exist_ok=True)

    def load_state(self) -> dict:
        """
        Loads persisted SOC state. If the primary file is corrupted, attempts
        recovery from the .bak file. Returns clean initial defaults if neither exists.
        """
        with self._lock:
            # 1. Try primary state file
            if os.path.exists(self.state_file_path):
                try:
                    with open(self.state_file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            return self._sanitize_loaded_state(data)
                except Exception:
                    pass

            # 2. Try backup recovery file
            if os.path.exists(self.backup_file_path):
                try:
                    with open(self.backup_file_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        if isinstance(data, dict):
                            return self._sanitize_loaded_state(data)
                except Exception:
                    pass

            # 3. Clean fallback defaults
            return self._default_state()

    def save_state(self, state_data: dict) -> bool:
        """
        Atomically saves state data to disk using temporary file + atomic rename (os.replace).
        Also updates the .bak backup file for fail-safe durability.
        """
        with self._lock:
            dir_name = os.path.dirname(self.state_file_path)
            temp_path = None
            try:
                payload = {
                    "blocklist": state_data.get("blocklist", {}),
                    "incidents": state_data.get("incidents", [])[:200],
                    "audit_logs": state_data.get("audit_logs", [])[:200],
                    "total_flows_processed": int(state_data.get("total_flows_processed", 0)),
                    "blocked_traffic_drops": int(state_data.get("blocked_traffic_drops", 0)),
                    "dismissed_ips": list(state_data.get("dismissed_ips", [])),
                    "last_saved": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # Write to temp file in same directory (guarantees same filesystem for atomic rename)
                with tempfile.NamedTemporaryFile("w", dir=dir_name, delete=False, encoding="utf-8") as tf:
                    temp_path = tf.name
                    json.dump(payload, tf, indent=2)
                    tf.flush()
                    os.fsync(tf.fileno())

                # Atomic replace on Windows/POSIX
                os.replace(temp_path, self.state_file_path)
                # Keep .bak backup synchronized for fail-safe durability
                try:
                    shutil.copy2(self.state_file_path, self.backup_file_path)
                except Exception:
                    pass
                return True
            except Exception as e:
                print(f"[!] Error saving state atomically: {e}")
                if temp_path and os.path.exists(temp_path):
                    try:
                        os.remove(temp_path)
                    except Exception:
                        pass
                return False

    def clear_state(self) -> bool:
        """Wipes persisted state file and backup for complete demo reset."""
        with self._lock:
            for p in [self.state_file_path, self.backup_file_path]:
                if os.path.exists(p):
                    try:
                        os.remove(p)
                    except Exception:
                        pass
            return True

    def _sanitize_loaded_state(self, data: dict) -> dict:
        return {
            "blocklist": data.get("blocklist", {}) if isinstance(data.get("blocklist"), dict) else {},
            "incidents": data.get("incidents", []) if isinstance(data.get("incidents"), list) else [],
            "audit_logs": data.get("audit_logs", []) if isinstance(data.get("audit_logs"), list) else [],
            "total_flows_processed": int(data.get("total_flows_processed", 0)),
            "blocked_traffic_drops": int(data.get("blocked_traffic_drops", 0)),
            "dismissed_ips": set(data.get("dismissed_ips", [])) if isinstance(data.get("dismissed_ips"), list) else set()
        }

    def _default_state(self) -> dict:
        return {
            "blocklist": {},
            "incidents": [],
            "audit_logs": [],
            "total_flows_processed": 0,
            "blocked_traffic_drops": 0,
            "dismissed_ips": set()
        }
