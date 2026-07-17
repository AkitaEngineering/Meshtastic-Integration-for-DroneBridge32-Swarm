"""Telemetry receive helpers for the ground-control station."""
import os
import time
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError:  # pragma: no cover - exercised only in minimal installs
    AESGCM: Any = None
else:
    AESGCM = _AESGCM

from meshtastic_crypto import DEFAULT_KEY, load_key, unpack_telemetry_plaintext

REQUIRE_CONFIGURED_KEY = (
    os.environ.get("MESHTASTIC_PRODUCTION") == "1"
    or os.environ.get("MESHTASTIC_REQUIRE_KEY") == "1"
)
KEY = load_key(DEFAULT_KEY, require_configured=REQUIRE_CONFIGURED_KEY)
DRONE_TELEMETRY_DATA_TYPE = 100

drone_data: dict[int, dict[str, float]] = {}
last_telemetry_seq: dict[int, int] = {}


def _decoded_data(packet):
    decoded = packet.get("decoded") or {}
    return decoded.get("data") or decoded


def _portnum_matches(portnum, expected):
    if portnum == expected:
        return True
    value = getattr(portnum, "value", None)
    if value == expected:
        return True
    try:
        return int(portnum) == expected
    except (TypeError, ValueError):
        return False


def on_receive(packet, interface=None):
    data = _decoded_data(packet)
    payload = data.get("payload")
    if not _portnum_matches(data.get("portnum"), DRONE_TELEMETRY_DATA_TYPE) or not payload:
        return

    if AESGCM is None or len(payload) < 12 + 16:
        return

    nonce = payload[:12]
    ciphertext = payload[12:]

    try:
        plaintext = AESGCM(KEY).decrypt(nonce, ciphertext, None)
        seq, lat, lon, alt, bat, roll, pitch, yaw, drone_id = (
            unpack_telemetry_plaintext(plaintext)
        )
    except Exception:
        return

    last = last_telemetry_seq.get(drone_id, 0)
    if seq <= last:
        return

    last_telemetry_seq[drone_id] = seq
    drone_data[drone_id] = {
        "latitude": round(lat, 6),
        "longitude": round(lon, 6),
        "altitude": round(alt, 3),
        "battery": round(bat, 2),
        "roll": round(roll, 3),
        "pitch": round(pitch, 3),
        "yaw": round(yaw, 3),
        "last_seen": time.time(),
    }
