import time
import struct
import json
import os
import threading
from flask import Flask, render_template, request, jsonify
import meshtastic
import meshtastic.serial_interface
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

from meshtastic_crypto import load_key, next_seq, pack_control_plaintext, unpack_telemetry_plaintext

app = Flask(__name__)

# Config
DEFAULT_KEY = bytes([0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C])
KEY = load_key(DEFAULT_KEY)
DRONE_TELEMETRY_DATA_TYPE = 100
DRONE_CONTROL_COMMAND_DATA_TYPE = 101

interface = None
drone_data = {}
last_telemetry_seq = {}

def on_receive(packet, interface):
    if not packet.get('decoded') or not packet['decoded'].get('data'):
        return
    portnum = packet['decoded']['data'].get('portnum')
    payload = packet['decoded']['data'].get('payload')
    
    if portnum == DRONE_TELEMETRY_DATA_TYPE:
        if AESGCM is None or len(payload) < 28:
            return
        nonce = payload[:12]
        ciphertext = payload[12:]
        try:
            plaintext = AESGCM(KEY).decrypt(nonce, ciphertext, None)
            seq, lat, lon, alt, bat, roll, pitch, yaw, drone_id = unpack_telemetry_plaintext(plaintext)
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
                "last_seen": time.time()
            }
        except Exception as e:
            print(f"Decryption failed: {e}")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/telemetry")
def get_telemetry():
    return jsonify(drone_data)

@app.route("/api/control", methods=["POST"])
def send_command():
    data = request.json
    drone_id = data.get("drone_id", 0)
    command = data.get("command", 0)
    
    if interface is None:
        return jsonify({"error": "Meshtastic not connected"}), 500
    try:
        seq = next_seq()
        payload = pack_control_plaintext(seq, int(drone_id), int(command))
        if AESGCM is None:
            return jsonify({"error": "Cryptography missing"}), 500
            
        aesgcm = AESGCM(KEY)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, payload, None)
        wire = nonce + ciphertext
        interface.sendData(wire, DRONE_CONTROL_COMMAND_DATA_TYPE)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def meshtastic_thread():
    global interface
    try:
        # Running in a background thread
        interface = meshtastic.serial_interface.SerialInterface()
        try:
            interface.onReceive += on_receive
        except Exception:
            pass # Fallback pubsub if needed
    except Exception as e:
        print(f"Meshtastic interface failed: {e}")

if __name__ == "__main__":
    t = threading.Thread(target=meshtastic_thread, daemon=True)
    t.start()
    app.run(host="0.0.0.0", port=5000, debug=False)
