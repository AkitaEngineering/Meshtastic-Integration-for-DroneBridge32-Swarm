"""Provision AES key for Meshtastic apps.

Usage:
  python scripts/provision_key.py --hex 0011... (32 hex chars) --file /path/to/keyfile
  python scripts/provision_key.py --hex 0011... --keyring
"""
import argparse
from meshtastic_crypto import save_key_to_file, save_key_to_keyring

parser = argparse.ArgumentParser()
parser.add_argument("--hex", required=True, help="32 hex chars (16 bytes) AES key")
parser.add_argument("--file", help="Write key to file")
parser.add_argument(
    "--keyring",
    action="store_true",
    help="Save key to system keyring (if available)",
)
parser.add_argument(
    "--sign-pem",
    help="Sign the key using this ECDSA private PEM and print SETKEYSIG string",
)
parser.add_argument(
    "--serial",
    help="Send provisioning line directly to MCU serial port (e.g. COM3 or /dev/ttyUSB0)",
)
args = parser.parse_args()
hexs = args.hex.strip()
if len(hexs) != 32:
    raise SystemExit("Key must be 32 hex chars (16 bytes)")
try:
    key = bytes.fromhex(hexs)
except Exception as e:
    raise SystemExit(f"Invalid hex: {e}")
if args.file:
    ok = save_key_to_file(key, args.file)
    print(f"Saved to file: {ok}")
if args.keyring:
    ok = save_key_to_keyring(key)
    print(f"Saved to keyring: {ok}")

# signing/provisioning
if args.sign_pem:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    priv_pem = open(args.sign_pem, "rb").read()
    priv = load_pem_private_key(priv_pem, password=None)
    if not isinstance(priv, ec.EllipticCurvePrivateKey):
        raise SystemExit("Signing key must be an ECDSA private key")
    sig = priv.sign(bytes.fromhex(hexs), ec.ECDSA(hashes.SHA256()))
    # sig is DER-encoded. Send as hex
    sighex = sig.hex()
    sets = f"SETKEYSIG:{hexs}:{sighex}"
    print(sets)
    if args.serial:
        import time

        import serial

        s = serial.Serial(args.serial, 115200, timeout=1)
        s.write((sets + "\n").encode())
        time.sleep(0.1)
        print(s.read_all().decode(errors='ignore'))

if not args.file and not args.keyring and not args.sign_pem:
    print("No destination specified; use --file, --keyring, or --sign-pem")
