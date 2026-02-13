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

# AES-128 key (example). Must match the drone-side key.
KEY = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
# Override key from environment (hex) when provided
env = os.environ.get("MESHTASTIC_AES_KEY")
if env:
    try:
        k = bytes.fromhex(env)
        if len(k) == 16:
            KEY = k
        else:
            print("MESHTASTIC_AES_KEY must be 32 hex chars (16 bytes); using default key")
    except Exception as e:
        print(f"Invalid MESHTASTIC_AES_KEY: {e}; using default key")

DRONE_CONTROL_COMMAND_DATA_TYPE = 101
interface = None
SEQ_FILE = ".control_seq"

def load_seq():
    try:
        with open(SEQ_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return 0

def save_seq(seq):
    try:
        with open(SEQ_FILE, "w") as f:
            f.write(str(seq))
    except Exception as e:
        print(f"Warning: failed to persist seq: {e}")

def next_seq():
    s = load_seq() + 1
    save_seq(s)
    return s

def send_control_command(drone_id, command):
    global interface
    if interface is None:
        print("Meshtastic interface not connected")
        return
    try:
        seq = next_seq()
        payload = struct.pack("<IBi", int(seq), int(drone_id), int(command))
        if AESGCM is None:
            print("cryptography package required for AES-GCM encryption")
            return
        aesgcm = AESGCM(KEY)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)  # ciphertext || tag
        wire = nonce + ciphertext
        interface.sendData(wire, DRONE_CONTROL_COMMAND_DATA_TYPE)
    except Exception as e:
        print(f"Failed to send control command: {e}")

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
