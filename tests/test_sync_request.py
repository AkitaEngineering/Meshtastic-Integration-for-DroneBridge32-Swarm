import os
import struct
import threading
import time
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import meshtastic_control as mc


class DummyInterface:
    def __init__(self):
        self.sent = []

    def sendData(
        self,
        data,
        destinationId="^all",
        portNum=256,
        wantAck=False,
        **kwargs,
    ):
        # record the last sent wire for inspection
        self.sent.append((data, destinationId, portNum, wantAck, kwargs))


def simulate_ack(seq, drone_id, status, key, delay=0.05):
    time.sleep(delay)
    plaintext = struct.pack("<IBB", int(seq), int(drone_id), int(status))
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    wire = nonce + ct
    pkt = {"decoded": {"data": {"portnum": mc.CONTROL_ACK_DATA_TYPE, "payload": wire}}}
    mc._on_receive_control(pkt, None)


def test_request_seq_sync_receives_sync_response(monkeypatch):
    # prepare dummy interface
    dummy = DummyInterface()
    mc.interface = dummy

    # ensure deterministic seq used by send_control_command
    monkeypatch.setattr(mc, "next_seq", lambda seq_file=".control_seq": 0xBEEF)

    # spawn simulator thread to deliver the sync-response after send
    t = threading.Thread(target=simulate_ack, args=(0xBEEF, 5, 2, mc.KEY, 0.02))
    t.start()

    # call the helper which should wait and return the reported seq
    res = mc.request_seq_sync(5, timeout=1.0)
    t.join()

    assert res == 0xBEEF
    assert dummy.sent[0][2] == mc.DRONE_CONTROL_COMMAND_DATA_TYPE
    assert dummy.sent[0][3] is True
