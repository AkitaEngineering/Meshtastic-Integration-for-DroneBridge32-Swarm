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
    *   Install Python dependencies: `pip install meshtastic folium cryptography flask`
    *   Start the server: `python gcs_app.py`

## Usage

1.  **Launch Web App:** Run `python gcs_app.py` in your terminal.
2.  **Open Dashboard:** Navigate to `http://localhost:5000` in your web browser.
3.  **Monitor & Control:** Observe real-time telemetry on the live map and use the control panels to send commands.

## Configuration

* **Drone IDs:** Set unique IDs for each drone in the `main.cpp` code.
* **MAVLink Settings:** Configure MAVLink baud rate and message IDs.
* **Meshtastic Settings:** Configure channel, encryption keys, and network settings.
* **Geofence:** Modify the geofence coordinates in the telemetry plugin.
* **Encryption Key:** The AES key can be provided in multiple ways (priority):
  - `MESHTASTIC_AES_KEY_FILE` — path to a file containing 32 hex chars (recommended for local deployments)
  - `MESHTASTIC_AES_KEY` — environment variable with 32 hex chars
  - system keyring (optional)
  - compiled default key (fallback)
  On the MCU you can provision a runtime key via the USB serial console: send `SETKEY:<32-hex-chars>` to persist the key to NVS (ESP32). Ensure keys match between ground and drone.
* **Replay protection:** Messages include a 32-bit sequence number and receivers reject stale/replayed packets. Sequence numbers are persisted for control on the drone (if supported) and for the ground control app stored locally in `.control_seq`. Replace with a secure counter sync if needed for distributed systems.
* **Testing & CI:** This repository includes unit tests (`tests/test_crypto.py`) and a GitHub Actions CI workflow at `.github/workflows/ci.yml` that runs tests on push/pull requests.

## Disclaimer

This project is provided "as is," without warranty. Use at your own risk.
