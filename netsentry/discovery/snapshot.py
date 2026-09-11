import json
import os
from pathlib import Path

from .models import Device


def snapshot_path() -> Path:
    """Return the user-local path for the current discovery snapshot."""
    return Path.home() / ".netsentry" / "current_discovery.json"


def save_current_snapshot(devices: list[Device], path: Path | None = None) -> None:
    """Atomically replace the current discovery snapshot."""
    destination = path or snapshot_path()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(f"{destination.suffix}.tmp")
    payload = {
        "version": 1,
        "devices": [
            {
                "ip": device.ip,
                "mac": device.mac,
                "hostname": device.hostname,
                "vendor": device.vendor,
            }
            for device in devices
        ],
    }
    temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(temporary, destination)


def load_current_snapshot(path: Path | None = None) -> list[Device]:
    """Load only the current discovery snapshot, never historical records."""
    source = path or snapshot_path()
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
        return [Device(**item) for item in payload["devices"]]
    except (FileNotFoundError, OSError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise FileNotFoundError(
            "No current discovery snapshot exists. Run `netsentry discover` first."
        ) from exc