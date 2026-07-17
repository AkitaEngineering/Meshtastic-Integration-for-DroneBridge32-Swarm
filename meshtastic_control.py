"""Control command helpers for Meshtastic drone nodes."""
import os
import struct
import threading
from typing import Any

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError:  # pragma: no cover - exercised only in minimal installs
    AESGCM: Any = None
else:
    AESGCM = _AESGCM

from meshtastic_crypto import DEFAULT_KEY, load_key, next_seq, pack_control_plaintext

REQUIRE_CONFIGURED_KEY = (
    os.environ.get("MESHTASTIC_PRODUCTION") == "1"
    or os.environ.get("MESHTASTIC_REQUIRE_KEY") == "1"
)
KEY = load_key(DEFAULT_KEY, require_configured=REQUIRE_CONFIGURED_KEY)
DRONE_CONTROL_COMMAND_DATA_TYPE = 101
CONTROL_ACK_DATA_TYPE = 102
COMMAND_RTL = 1
COMMAND_LAND = 2
COMMAND_EMERGENCY_LAND = 3
COMMAND_SYNC_REQUEST = 4
ACK_STATUS_ACCEPTED = 1
ACK_STATUS_SYNC = 2
ACK_STATUS_REJECTED = 3

interface = None
_acks: dict[tuple[int, int], int] = {}
_ack_condition = threading.Condition()


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


def _encrypt_payload(payload):
    if AESGCM is None:
        raise RuntimeError("cryptography is required for encrypted control")
    nonce = os.urandom(12)
    return nonce + AESGCM(KEY).encrypt(nonce, payload, None)


def send_control_command(drone_id, command):
    if interface is None:
        raise RuntimeError("Meshtastic not connected")

    seq = next_seq()
    payload = pack_control_plaintext(seq, int(drone_id), int(command))
    interface.sendData(
        _encrypt_payload(payload),
        portNum=DRONE_CONTROL_COMMAND_DATA_TYPE,
        wantAck=True,
    )
    return seq


def _on_receive_control(packet, received_interface=None):
    data = _decoded_data(packet)
    payload = data.get("payload")
    if not _portnum_matches(data.get("portnum"), CONTROL_ACK_DATA_TYPE) or not payload:
        return

    try:
        if AESGCM is None:
            return
        plaintext = AESGCM(KEY).decrypt(payload[:12], payload[12:], None)
        seq, drone_id, status = struct.unpack("<IBB", plaintext)
    except Exception:
        return

    with _ack_condition:
        _acks[(drone_id, status)] = seq
        _ack_condition.notify_all()


def request_seq_sync(drone_id, timeout=2.0):
    seq = send_control_command(drone_id, COMMAND_SYNC_REQUEST)

    with _ack_condition:
        ok = _ack_condition.wait_for(
            lambda: _acks.get((int(drone_id), 2)) == seq,
            timeout=timeout,
        )
        if not ok:
            return None
        return _acks[(int(drone_id), 2)]
