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
parser.add_argument("--keyring", action="store_true", help="Save key to system keyring (if available)")
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
if not args.file and not args.keyring:
    print("No destination specified; use --file or --keyring")