# Meshtastic Drone Swarm Telemetry & Control

This project provides a comprehensive framework for integrating Meshtastic mesh networking with DroneBridge32 for telemetry and control of a drone swarm. It encompasses features like swarm coordination, geofencing, emergency landing, data logging, visualization, dynamic channel switching, AI integration (conceptual), encryption, and fail-safes.

## Features

* **Decentralized Control:** Operate your drone swarm over a resilient Meshtastic mesh network.
* **Encrypted Communication:** Secure communication using AES encryption.
* **Telemetry:** Real-time data including position, altitude, and battery voltage.
* **Control:** Commands for individual drones or the entire swarm.
* **MAVLink Integration:** Seamlessly works with MAVLink for flight controller communication.
* **Geofencing:** Prevents drones from entering restricted areas.
* **Emergency Landing:** Robust emergency landing protocol.
* **Data Logging:** Logs telemetry data for post-flight analysis.
* **Map Visualization:** Interactive map display of drone locations.
* **Dynamic Channel Switching:** Adapts to network conditions.
* **AI Integration (Conceptual):** Provides a framework for AI-driven insights.
* **Fail-Safes:** Signal loss and low battery protections.
* **Swarm Coordination:** Example of sending commands to the entire swarm.

## Components

1.  **Ground Control Station (Web App):**
    *   Unified Python Flask backend (`gcs_app.py`) for telemetry and control.
    *   Premium web frontend with live Leaflet maps and real-time dashboard.
    *   Includes geofencing checks, data logging, and single-serial connection stability.
3.  **DroneBridge32 (or Companion Process) - Node Firmware:**
    *   ESP-IDF (FreeRTOS) C++ application for handling telemetry and control.
    *   Native multi-tasking (Dedicated tasks for MAVLink parsing, Meshtastic radio, encryption).
    *   Secure AES-GCM integration and native NVS storage.

## Installation

1.  **ESP32 Firmware Integration (ESP-IDF):**
    *   Install the Espressif IoT Development Framework (ESP-IDF).
    *   Compile and flash the firmwware using `idf.py build` and `idf.py flash monitor`.
    *   Ensure MAVLink TX/RX is wired to `Serial2` (Pins 16/17) and Meshtastic to `Serial1` (Pins 4/5).
2.  **Meshtastic Node:**
    * Connect a Meshtastic-compatible device to your drone.
    * Configure the network settings.
3.  **Ground Control Station:**
    *   Install Python dependencies: `pip install -r requirements.txt`
    *   Start the server: `python gcs_app.py`

## Usage

1.  **Launch Web App:** Run `python gcs_app.py` in your terminal.
2.  **Open Dashboard:** Navigate to `http://localhost:5000` in your web browser.
3.  **Monitor & Control:** Observe real-time telemetry on the live map and use the control panels to send commands.

For app-level QA without radios or ESP-IDF hardware, run:

```bash
MESHTASTIC_FAKE=1 MESHTASTIC_API_TOKEN=qa-token python gcs_app.py
```

The fake interface emits encrypted telemetry and encrypted command ACKs through the same Python receive path as the real Meshtastic interface.

## Configuration

* **Drone IDs:** Set unique IDs for each drone in the `main.cpp` code.
* **MAVLink Settings:** Configure MAVLink baud rate and message IDs.
* **Meshtastic Settings:** Configure channel, encryption keys, and network settings.
* **Geofence:** Modify the geofence coordinates in the telemetry plugin.
* **Encryption Key:** The ground-control AES key can be provided in multiple ways (priority):
  - `MESHTASTIC_AES_KEY_FILE` — path to a file containing 32 hex chars (recommended for local deployments)
  - `MESHTASTIC_AES_KEY` — environment variable with 32 hex chars
  - system keyring (optional)
  - compiled default key (development fallback only)
  Set `MESHTASTIC_PRODUCTION=1` or `MESHTASTIC_REQUIRE_KEY=1` on the GCS to reject startup without a configured key.
  On the MCU, production provisioning uses signed USB serial commands:
  `SETKEYSIG:<32-hex-chars>:<ecdsa-der-signature-hex>`. Generate the line with
  `python scripts/provision_key.py --hex <32-hex-chars> --sign-pem /path/to/provisioning_private.pem`.
  Unsigned `SETKEY:<32-hex-chars>` is accepted only if the firmware is compiled with `ALLOW_INSECURE_SETKEY`.
  Ensure keys match between ground and drone.
* **Ground-control API access:** By default the Flask app binds to `127.0.0.1:5000`.
  Set `MESHTASTIC_GCS_HOST` and `MESHTASTIC_GCS_PORT` to expose it elsewhere.
  Set `MESHTASTIC_API_TOKEN` to require `Authorization: Bearer <token>` or
  `X-API-Token: <token>` for `/api/control`.
* **Provisioning public key:** Replace `provisioning_pubkey.h` and `scripts/provisioning_public.pem` with your production provisioning public key before deployment. Do not commit production private keys.
* **Replay protection:** Messages include a 32-bit sequence number and receivers reject stale/replayed packets. Sequence numbers are persisted for control on the drone (if supported) and for the ground control app stored locally in `.control_seq`. Replace with a secure counter sync if needed for distributed systems.
* **Testing & CI:** This repository includes unit tests (`tests/test_crypto.py`) and a GitHub Actions CI workflow at `.github/workflows/ci.yml` that runs tests on push/pull requests.

## Production Readiness Checklist

Before flight or field deployment:

1. Run `pip install -r requirements-dev.txt`, `flake8 --jobs=1 .`, `mypy --ignore-missing-imports .`, and `pytest -q`.
2. Install ESP-IDF, provide MAVLink headers/components, and verify `idf.py build` from a clean checkout.
3. Replace `provisioning_pubkey.h` and `scripts/provisioning_public.pem` with your production provisioning public key.
4. Keep the matching provisioning private key outside this repository and use it only to generate `SETKEYSIG` provisioning lines.
5. Configure a non-default AES key on the GCS and MCU; set `MESHTASTIC_PRODUCTION=1` or `MESHTASTIC_REQUIRE_KEY=1` on the GCS.
6. Set `MESHTASTIC_API_TOKEN` before exposing the GCS beyond localhost.
7. Bench-test command handling, replay rejection, lost-link behavior, and emergency landing/RTL behavior before any prop-on test.

## Disclaimer

This project is provided "as is," without warranty. Use at your own risk.
