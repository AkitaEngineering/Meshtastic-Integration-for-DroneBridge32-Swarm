import os
import struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import meshtastic_telemetry as mt
import meshtastic_crypto as mc

KEY = mc.DEFAULT_KEY


def make_telemetry_wire(seq, lat, lon, alt, bat, drone_id):
    plaintext = mc.pack_telemetry_plaintext(seq, lat, lon, alt, bat, drone_id)
    aes = AESGCM(KEY)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, plaintext, None)
    return nonce + ct


def make_packet(portnum, wire):
    return {"decoded": {"data": {"portnum": portnum, "payload": wire}}}


def test_on_receive_accepts_and_rejects_stale():
    # fresh packet accepted
    wire = make_telemetry_wire(1, 1.0, 2.0, 3.0, 11.1, 5)
    pkt = make_packet(mt.DRONE_TELEMETRY_DATA_TYPE, wire)
    mt.on_receive(pkt, None)
    assert 5 in mt.drone_data
    last = mt.last_telemetry_seq.get(5)
    assert last == 1

    # same seq (replay) ignored
    mt.on_receive(pkt, None)
    assert mt.last_telemetry_seq.get(5) == 1

    # higher seq accepted
    wire2 = make_telemetry_wire(2, 1.1, 2.1, 3.1, 10.5, 5)
    pkt2 = make_packet(mt.DRONE_TELEMETRY_DATA_TYPE, wire2)
    mt.on_receive(pkt2, None)
    assert mt.last_telemetry_seq.get(5) == 2
    assert mt.drone_data[5]["latitude"] == 1.1