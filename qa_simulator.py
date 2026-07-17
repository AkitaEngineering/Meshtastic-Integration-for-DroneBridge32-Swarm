"""In-process Meshtastic interface simulator for QA runs without hardware."""
import os
import struct
import threading

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import meshtastic_control as control
import meshtastic_crypto as crypto
import meshtastic_telemetry as telemetry


class EventHook:
    def __init__(self):
        self._handlers = []

    def __iadd__(self, handler):
        self._handlers.append(handler)
        return self

    def fire(self, packet):
        for handler in list(self._handlers):
            handler(packet, self)


class SimulatedMeshtasticInterface:
    def __init__(self, drone_id=1, telemetry_interval=1.0):
        self.drone_id = int(drone_id)
        self.telemetry_interval = float(telemetry_interval)
        self.onReceive = EventHook()
        self.sent = []
        self._stop = threading.Event()
        self._thread = None
        self._seq = 0

    def start(self):
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._telemetry_loop, daemon=True)
        self._thread.start()

    def close(self):
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=1.0)

    def sendData(
        self,
        data,
        destinationId="^all",
        portNum=256,
        wantAck=False,
        **kwargs,
    ):
        self.sent.append((data, destinationId, portNum, wantAck, kwargs))
        if portNum != control.DRONE_CONTROL_COMMAND_DATA_TYPE:
            return

        try:
            plaintext = AESGCM(control.KEY).decrypt(data[:12], data[12:], None)
            seq, drone_id, command = crypto.unpack_control_plaintext(plaintext)
        except Exception:
            return

        if drone_id not in {self.drone_id, 255}:
            return

        status = control.ACK_STATUS_ACCEPTED
        if command == control.COMMAND_SYNC_REQUEST:
            status = control.ACK_STATUS_SYNC
        elif command not in {
            control.COMMAND_RTL,
            control.COMMAND_LAND,
            control.COMMAND_EMERGENCY_LAND,
        }:
            status = control.ACK_STATUS_REJECTED

        ack_plaintext = struct.pack("<IBB", seq, self.drone_id, status)
        self.onReceive.fire(
            {
                "decoded": {
                    "data": {
                        "portnum": control.CONTROL_ACK_DATA_TYPE,
                        "payload": self._encrypt(control.KEY, ack_plaintext),
                    }
                }
            }
        )

    def _telemetry_loop(self):
        while not self._stop.wait(self.telemetry_interval):
            self.emit_telemetry()

    def emit_telemetry(self):
        self._seq += 1
        plaintext = crypto.pack_telemetry_plaintext(
            self._seq,
            40.7128 + self._seq * 0.0001,
            -74.0060 - self._seq * 0.0001,
            30.0 + self._seq,
            12.4,
            0.0,
            0.0,
            0.0,
            self.drone_id,
        )
        self.onReceive.fire(
            {
                "decoded": {
                    "data": {
                        "portnum": telemetry.DRONE_TELEMETRY_DATA_TYPE,
                        "payload": self._encrypt(telemetry.KEY, plaintext),
                    }
                }
            }
        )

    @staticmethod
    def _encrypt(key, plaintext):
        nonce = os.urandom(12)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, None)
