"""
Utility helpers for AES key loading, sequence persistence and plaintext packing
(kept independent from GUI modules so they can be unit-tested).
"""
import os
import struct

# Default AES-128 test key (example). Use secure provisioning in production.
DEFAULT_KEY = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6,
                   0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])

try:
    import keyring
except Exception:
    keyring = None


def load_key(default_key: bytes) -> bytes:
    """Load AES key from (in order): file (MESHTASTIC_AES_KEY_FILE),
    env (MESHTASTIC_AES_KEY), system keyring (keyring.get_password),
    fallback to default_key.

    Keys are expected as 32-hex-character strings (16 bytes).
    """
    # 1) file
    keyfile = os.environ.get("MESHTASTIC_AES_KEY_FILE")
    if keyfile and os.path.exists(keyfile):
        try:
            data = open(keyfile, "r").read().strip()
            k = bytes.fromhex(data)
            if len(k) == 16:
                return k
        except Exception:
            pass

    # 2) env var
    env = os.environ.get("MESHTASTIC_AES_KEY")
    if env:
        try:
            k = bytes.fromhex(env.strip())
            if len(k) == 16:
                return k
        except Exception:
            pass

    # 3) keyring (optional)
    if keyring is not None:
        try:
            v = keyring.get_password("meshtastic", "aes_key")
            if v:
                k = bytes.fromhex(v.strip())
                if len(k) == 16:
                    return k
        except Exception:
            pass

    # fallback
    return default_key


# Sequence persistence helpers (used by control clients)
def load_seq(seq_file: str = ".control_seq") -> int:
    try:
        with open(seq_file, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0


def save_seq(seq: int, seq_file: str = ".control_seq") -> None:
    try:
        with open(seq_file, "w") as f:
            f.write(str(int(seq)))
    except Exception:
        pass


def next_seq(seq_file: str = ".control_seq") -> int:
    s = load_seq(seq_file) + 1
    save_seq(s, seq_file)
    return s


# Key persistence helpers
def save_key_to_file(key: bytes, path: str) -> bool:
    try:
        with open(path, "w") as f:
            f.write(key.hex())
        return True
    except Exception:
        return False


def save_key_to_keyring(key: bytes) -> bool:
    if keyring is None:
        return False
    try:
        keyring.set_password("meshtastic", "aes_key", key.hex())
        return True
    except Exception:
        return False


# Plaintext packing/unpacking helpers
def pack_control_plaintext(seq: int, drone_id: int, command: int) -> bytes:
    return struct.pack("<IBi", int(seq), int(drone_id), int(command))


def unpack_control_plaintext(b: bytes):
    return struct.unpack("<IBi", b)


def pack_telemetry_plaintext(seq: int, latitude: float, longitude: float, altitude: float, battery: float, roll: float, pitch: float, yaw: float, drone_id: int) -> bytes:
    return struct.pack("<IfffffffB", int(seq), float(latitude), float(longitude), float(altitude), float(battery), float(roll), float(pitch), float(yaw), int(drone_id))


def unpack_telemetry_plaintext(b: bytes):
    return struct.unpack("<IfffffffB", b)
