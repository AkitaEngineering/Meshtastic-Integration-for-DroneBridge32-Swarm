import hmac
import os
import threading
from flask import Flask, render_template, request, jsonify
import meshtastic
import meshtastic.serial_interface

import meshtastic_control
import meshtastic_telemetry

app = Flask(__name__)

interface = None


def _configured_api_token():
    return os.environ.get("MESHTASTIC_API_TOKEN")


def _control_authorized():
    token = _configured_api_token()
    if not token:
        return True

    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        supplied = auth_header.removeprefix("Bearer ").strip()
    else:
        supplied = request.headers.get("X-API-Token", "")

    return hmac.compare_digest(supplied, token)


def on_receive(packet, interface):
    meshtastic_telemetry.on_receive(packet, interface)
    meshtastic_control._on_receive_control(packet, interface)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/telemetry")
def get_telemetry():
    return jsonify(meshtastic_telemetry.drone_data)


@app.route("/api/control", methods=["POST"])
def send_command():
    data = request.get_json(silent=True) or {}

    if not _control_authorized():
        return jsonify({"error": "unauthorized"}), 401

    if interface is None:
        return jsonify({"error": "Meshtastic not connected"}), 500

    try:
        drone_id = int(data.get("drone_id", 0))
        command = int(data.get("command", 0))
    except (TypeError, ValueError):
        return jsonify({"error": "drone_id and command must be integers"}), 400

    if not 0 <= drone_id <= 255:
        return jsonify({"error": "drone_id must be between 0 and 255"}), 400
    allowed_commands = {
        meshtastic_control.COMMAND_RTL,
        meshtastic_control.COMMAND_LAND,
        meshtastic_control.COMMAND_EMERGENCY_LAND,
        meshtastic_control.COMMAND_SYNC_REQUEST,
    }
    if command not in allowed_commands:
        return jsonify({"error": "unsupported command"}), 400

    try:
        seq = meshtastic_control.send_control_command(drone_id, command)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    return jsonify({"success": True, "seq": seq})


def meshtastic_thread():
    global interface
    try:
        # Running in a background thread
        if os.environ.get("MESHTASTIC_FAKE") == "1":
            from qa_simulator import SimulatedMeshtasticInterface

            interval = float(os.environ.get("MESHTASTIC_FAKE_INTERVAL", "1.0"))
            drone_id = int(os.environ.get("MESHTASTIC_FAKE_DRONE_ID", "1"))
            interface = SimulatedMeshtasticInterface(drone_id, interval)
        else:
            interface = meshtastic.serial_interface.SerialInterface()

        meshtastic_control.interface = interface
        try:
            interface.onReceive += on_receive
        except Exception:
            pass  # Fallback pubsub if needed.
        if hasattr(interface, "start"):
            interface.start()
    except Exception as exc:
        print(f"Meshtastic interface failed: {exc}")


if __name__ == "__main__":
    t = threading.Thread(target=meshtastic_thread, daemon=True)
    t.start()
    host = os.environ.get("MESHTASTIC_GCS_HOST", "127.0.0.1")
    port = int(os.environ.get("MESHTASTIC_GCS_PORT", "5000"))
    app.run(host=host, port=port, debug=False)
