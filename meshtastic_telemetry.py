import meshtastic
import meshtastic.serial_interface
import struct
import tkinter as tk
from tkinter import ttk, scrolledtext
import time
import json
import threading
import folium  # For map visualization
import webbrowser
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

DRONE_TELEMETRY_DATA_TYPE = 100
DRONE_CONTROL_COMMAND_DATA_TYPE = 101
interface = None
drone_data = {}
last_telemetry_seq = {}  # drone_id -> last seq received (replay protection)
geofence = [  # Example geofence (latitude, longitude)
    (40.7128, -74.0060),
    (40.7228, -74.0060),
    (40.7228, -74.0160),
    (40.7128, -74.0160),
]
log_file = "drone_telemetry.jsonl"
map_file = "drone_map.html"
map_obj = folium.Map(location=[40.7128, -74.0060], zoom_start=14)  # Initialize map
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

def on_receive(packet, interface):
    if packet['decoded']['data']['portnum'] == DRONE_TELEMETRY_DATA_TYPE:
        try:
            payload = packet['decoded']['data']['payload']
            if AESGCM is None:
                print("cryptography package required for AES-GCM decryption")
                return
            if len(payload) < 12 + 16:
                print("Telemetry payload too short")
                return
            nonce = payload[:12]
            ciphertext = payload[12:]
            try:
                plaintext = AESGCM(KEY).decrypt(nonce, ciphertext, None)
            except Exception as e:
                print(f"Telemetry decryption failed: {e}")
                return
            # plaintext: uint32_t seq | float lat | float lon | float alt | float battery | uint8_t drone_id
            seq, latitude, longitude, altitude, battery, drone_id = struct.unpack('<IffffB', plaintext)
            last = last_telemetry_seq.get(drone_id, 0)
            if seq <= last:
                print(f"Stale telemetry seq {seq} for drone {drone_id} (last {last}) — ignoring")
                return
            last_telemetry_seq[drone_id] = seq
            drone_data[drone_id] = {"latitude": latitude, "longitude": longitude, "altitude": altitude, "battery": battery}
            check_geofence(drone_id, latitude, longitude)
            log_telemetry(drone_id, latitude, longitude, altitude, battery)
            update_display()
            update_map(drone_id, latitude, longitude)
            analyze_telemetry(drone_id) # Example AI analysis per drone.
        except Exception as e:
            print(f"Error decoding telemetry: {e}")
    elif packet['decoded']['data']['portnum'] == DRONE_CONTROL_COMMAND_DATA_TYPE:
        try:
            payload = packet['decoded']['data']['payload']
            if AESGCM is None:
                print("cryptography package required for AES-GCM decryption")
                return
            if len(payload) < 12 + 16:
                print("Control payload too short")
                return
            nonce = payload[:12]
            ciphertext = payload[12:]
            try:
                plaintext = AESGCM(KEY).decrypt(nonce, ciphertext, None)
            except Exception as e:
                print(f"Control command decryption failed: {e}")
                return
            # control plaintext: uint32_t seq | uint8_t drone_id | int32_t command
            seq, drone_id, command = struct.unpack('<IBi', plaintext)
            print(f"Control command seq={seq} {command} received for drone: {drone_id}")
        except Exception as e:
            print(f"Error decoding control command: {e}")

def check_geofence(drone_id, latitude, longitude):
    inside = False
    n = len(geofence)
    p1x, p1y = geofence[0]
    for i in range(n + 1):
        p2x, p2y = geofence[i % n]
        if longitude > min(p1y, p2y):
            if longitude <= max(p1y, p2y):
                if latitude <= max(p1x, p2x):
                    if p1y != p2y:
                        xinters = (longitude - p1y) * (p2x - p1x) / (p2y - p1y) + p1x
                    if p1x == p2x or latitude <= xinters:
                        inside = not inside
        p1x, p1y = p2x, p2y
    if not inside:
        print(f"Drone {drone_id} outside geofence! Initiating emergency landing.")
        send_control_command(drone_id, 3)  # Emergency landing command

def log_telemetry(drone_id, latitude, longitude, altitude, battery):
    data = {
        "timestamp": time.time(),
        "drone_id": drone_id,
        "latitude": latitude,
        "longitude": longitude,
        "altitude": altitude,
        "battery": battery,
    }
    with open(log_file, "a") as f:
        f.write(json.dumps(data) + "\n")

def update_display():
    telemetry_text.delete(1.0, tk.END)
    for drone_id, data in drone_data.items():
        telemetry_text.insert(tk.END, f"Drone {drone_id}:\n")
        telemetry_text.insert(tk.END, f"  Latitude: {data['latitude']}\n")
        telemetry_text.insert(tk.END, f"  Longitude: {data['longitude']}\n")
        telemetry_text.insert(tk.END, f"  Altitude: {data['altitude']}\n")
        telemetry_text.insert(tk.END, f"  Battery: {data['battery']}\n\n")

def send_control_command(drone_id, command):
    global interface
    if interface is None:
        print("Meshtastic interface not connected")
        return
    try:
        seq = next_seq()
        payload = struct.pack('<IBi', int(seq), int(drone_id), int(command))
        if AESGCM is None:
            print("cryptography package required for AES-GCM encryption")
            return
        aesgcm = AESGCM(KEY)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        wire = nonce + ciphertext
        interface.sendData(wire, DRONE_CONTROL_COMMAND_DATA_TYPE)
    except Exception as e:
        print(f"Failed to send control command: {e}")

def send_emergency_landing():
    try:
        drone_id = int(drone_id_entry.get())
        send_control_command(drone_id, 3)  # 3 is the emergency landing command
    except ValueError:
        print("Invalid drone ID")

def update_map(drone_id, latitude, longitude):
    folium.Marker([latitude, longitude], popup=f"Drone {drone_id}").add_to(map_obj)
    map_obj.save(map_file)

def open_map():
    if os.path.exists(map_file):
        webbrowser.open("file://" + os.path.realpath(map_file))
    else:
        print("Map file not found.")

def switch_channel(channel_name):
    try:
        interface.set_channel(channel_name)
        print(f"Switched to channel: {channel_name}")
    except Exception as e:
        print(f"Error switching channel: {e}")

def analyze_telemetry(drone_id):
    # Placeholder for AI-based telemetry analysis
    if drone_id in drone_data:
        data = drone_data[drone_id]
        if data["battery"] < 20: #Example AI analysis.
            print(f"Warning: Drone {drone_id} battery low!")

# GUI Setup
root = tk.Tk()
root.title("Drone Swarm Telemetry")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

telemetry_text = scrolledtext.ScrolledText(frame, wrap=tk.WORD, width=40, height=15)
telemetry_text.grid(row=0, column=0, columnspan=2, pady=10)

drone_id_label = ttk.Label(frame, text="Drone ID:")
drone_id_label.grid(row=1, column=0, sticky=tk.W)

drone_id_entry = ttk.Entry(frame)
drone_id_entry.grid(row=1, column=1, sticky=tk.W)

emergency_landing_button = ttk.Button(frame, text="Emergency Landing", command=send_emergency_landing)
emergency_landing_button.grid(row=2, column=0, pady=5)

open_map_button = ttk.Button(frame, text="Open Map", command=open_map)
open_map_button.grid(row=2, column=1, pady=5)

switch_channel_button = ttk.Button(frame, text="Switch Channel", command=lambda: switch_channel("MyNewChannel"))
switch_channel_button.grid(row=3, column=0, pady=5)

try:
    interface = meshtastic.serial_interface.SerialInterface()
    # Register receive callback (SerialInterface invokes callbacks on its listener thread).
    try:
        interface.onReceive += on_receive
    except Exception:
        # Fallback: some versions use pubsub topics; the callback still works if registered elsewhere.
        pass
    # Run GUI on main thread; SerialInterface runs its own listener thread.
    root.mainloop()
except meshtastic.serial_interface.InterfaceError as e:
    print(f"Error connecting to Meshtastic device: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
finally:
    if interface:
        interface.close()
