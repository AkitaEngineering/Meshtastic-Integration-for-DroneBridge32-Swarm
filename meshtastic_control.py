import meshtastic
import meshtastic.serial_interface
import struct
import tkinter as tk
from tkinter import ttk
import os
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

# AES-128 default key (example). Must match the drone-side key if not overridden.
DEFAULT_KEY = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
# load key from env/file/keyring (if present)
from meshtastic_crypto import load_key, next_seq as crypto_next_seq
KEY = load_key(DEFAULT_KEY)

DRONE_CONTROL_COMMAND_DATA_TYPE = 101
CONTROL_ACK_DATA_TYPE = 102
interface = None

# ack tracking
import threading
_pending_acks = {}
_pending_acks_lock = threading.Lock()
_pending_sync_events = {}
_last_sync_result = {}

# delegate sequence handling to meshtastic_crypto for testability
SEQ_FILE = ".control_seq"

def load_seq(seq_file: str = SEQ_FILE):
    from meshtastic_crypto import load_seq as crypto_load_seq
    return crypto_load_seq(seq_file)

def save_seq(seq, seq_file: str = SEQ_FILE):
    from meshtastic_crypto import save_seq as crypto_save_seq
    return crypto_save_seq(seq, seq_file)

def next_seq(seq_file: str = SEQ_FILE):
    from meshtastic_crypto import next_seq as crypto_next_seq
    return crypto_next_seq(seq_file)

def send_control_command(drone_id, command, wait_for_ack=False, timeout=1.0):
    global interface
    if interface is None:
        print("Meshtastic interface not connected")
        return False
    try:
        seq = next_seq()
        # use helper pack to ensure format consistency with MCU
        from meshtastic_crypto import pack_control_plaintext
        payload = pack_control_plaintext(seq, int(drone_id), int(command))
        if AESGCM is None:
            print("cryptography package required for AES-GCM encryption")
            return False
        aesgcm = AESGCM(KEY)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)  # ciphertext || tag
        wire = nonce + ciphertext

        # subscribe for ACKs once (lazy)
        try:
            interface.onReceive += _on_receive_control
        except Exception:
            pass

        if wait_for_ack:
            ev = threading.Event()
            with _pending_acks_lock:
                _pending_acks[seq] = ev

        interface.sendData(wire, DRONE_CONTROL_COMMAND_DATA_TYPE)

        if wait_for_ack:
            ok = ev.wait(timeout)
            with _pending_acks_lock:
                _pending_acks.pop(seq, None)
            return ok
        return True
    except Exception as e:
        print(f"Failed to send control command: {e}")
        return False


def request_seq_sync(drone_id, timeout=1.0):
    """Send a sync-request to a drone and wait for its sync-response.

    The sync request uses command value 0x7FFFFFFF (special) and the MCU
    replies with an ACK whose status==2 containing its last sequence.
    Returns the reported last sequence (int) on success, or None on timeout/failure.
    """
    # prepare waiting event keyed by drone_id
    ev = threading.Event()
    with _pending_acks_lock:
        _pending_sync_events[drone_id] = ev
    try:
        sent = send_control_command(drone_id, 0x7FFFFFFF, wait_for_ack=False)
        if not sent:
            with _pending_acks_lock:
                _pending_sync_events.pop(drone_id, None)
            return None

        got = ev.wait(timeout)
        with _pending_acks_lock:
            _pending_sync_events.pop(drone_id, None)
        if not got:
            return None
        # return the last sync result recorded by the receive handler
        return _last_sync_result.get(drone_id)
    except Exception:
        with _pending_acks_lock:
            _pending_sync_events.pop(drone_id, None)
        return None


def _on_receive_control(packet, iface):
    # handle ACKs coming back from the drone; decrypt and set pending event
    try:
        if packet.get('decoded', {}).get('data', {}).get('portnum') is None:
            return
        payload = packet['decoded']['data']['payload']
        # decrypt payload using AES-GCM
        if AESGCM is None:
            return
        try:
            plaintext = AESGCM(KEY).decrypt(payload[:12], payload[12:], None)
        except Exception:
            return
        # ack format: uint32_t seq | uint8_t drone_id | uint8_t status
        if len(plaintext) == 6:
            seq, drone_id, status = struct.unpack('<IBB', plaintext)
            # persist acknowledged seq
            save_seq(seq)
            if status == 2:
                # sync-response -> notify waiting sync caller
                ev = None
                with _pending_acks_lock:
                    ev = _pending_sync_events.get(drone_id)
                if ev:
                    _last_sync_result[drone_id] = seq
                    ev.set()
            else:
                with _pending_acks_lock:
                    ev = _pending_acks.get(seq)
                    if ev:
                        ev.set()
    except Exception:
        pass

def send_return_home():
    try:
        drone_id = int(drone_id_entry.get())
        send_control_command(drone_id, 1)
        print(f"Sending return home command to drone {drone_id}")
    except ValueError:
        print("Invalid drone ID")

def send_land():
    try:
        drone_id = int(drone_id_entry.get())
        send_control_command(drone_id, 2)
        print(f"Sending land command to drone {drone_id}")
    except ValueError:
        print("Invalid drone ID")

def send_emergency_landing():
    try:
        drone_id = int(drone_id_entry.get())
        send_control_command(drone_id, 3)
        print(f"Sending emergency landing command to drone {drone_id}")
    except ValueError:
        print("Invalid drone ID")

def send_custom_command():
    try:
        drone_id = int(drone_id_entry.get())
        command = int(custom_command_entry.get())
        send_control_command(drone_id, command)
        print(f"Sending custom command {command} to drone {drone_id}")
    except ValueError:
        print("Invalid drone ID or command")

def send_swarm_command(command): #Example swarm coordination.
    for drone_id in range(1, 10): # Example for drones 1-9
        send_control_command(drone_id, command)
    print(f"Sending swarm command {command}")

def switch_channel(channel_name):
    try:
        interface.set_channel(channel_name)
        print(f"Switched to channel: {channel_name}")
    except Exception as e:
        print(f"Error switching channel: {e}")

# GUI Setup
root = tk.Tk()
root.title("Drone Control")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

drone_id_label = ttk.Label(frame, text="Drone ID:")
drone_id_label.grid(row=0, column=0, sticky=tk.W)

drone_id_entry = ttk.Entry(frame)
drone_id_entry.grid(row=0, column=1, sticky=tk.W)

return_home_button = ttk.Button(frame, text="Return Home", command=send_return_home)
return_home_button.grid(row=1, column=0, pady=5, columnspan=2, sticky=tk.W + tk.E)

land_button = ttk.Button(frame, text="Land", command=send_land)
land_button.grid(row=2, column=0, pady=5, columnspan=2, sticky=tk.W + tk.E)

emergency_landing_button = ttk.Button(frame, text="Emergency Landing", command=send_emergency_landing)
emergency_landing_button.grid(row=3, column=0, pady=5, columnspan=2, sticky=tk.W + tk.E)

custom_command_label = ttk.Label(frame, text="Custom Command:")
custom_command_label.grid(row=4, column=0, sticky=tk.W)

custom_command_entry = ttk.Entry(frame)
custom_command_entry.grid(row=4, column=1, sticky=tk.W)

custom_command_button = ttk.Button(frame, text="Send Custom Command", command=send_custom_command)
custom_command_button.grid(row=5, column=0, pady=5, columnspan=2, sticky=tk.W + tk.E)

swarm_return_home_button = ttk.Button(frame, text="Swarm Return Home", command=lambda: send_swarm_command(1))
swarm_return_home_button.grid(row=6, column=0, pady=5, columnspan=2, sticky=tk.W + tk.E)

swarm_land_button = ttk.Button(frame, text="Swarm Land", command=lambda: send_swarm_command(2))
swarm_land_button.grid(row=7, column=0, pady=5, columnspan=2, sticky=tk.W + tk.E)

switch_channel_button = ttk.Button(frame, text="Switch Channel", command=lambda: switch_channel("MyNewChannel"))
switch_channel_button.grid(row=8, column=0, pady=5, columnspan=2, sticky=tk.W + tk.E)

if __name__ == "__main__":
    try:
        interface = meshtastic.serial_interface.SerialInterface()
        root.mainloop()

    except meshtastic.serial_interface.InterfaceError as e:
        print(f"Error connecting to Meshtastic device: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        if interface:
            interface.close()
