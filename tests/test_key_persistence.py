import os
import importlib
import tempfile
import sys

import meshtastic_crypto as mc


def test_save_and_load_key_file(tmp_path):
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    p = tmp_path / "k.hex"
    assert mc.save_key_to_file(key, str(p))
    loaded = mc.load_key(b"\x00"*16)
    # load_key checks MESHTASTIC_AES_KEY_FILE first -> set and test
    os.environ["MESHTASTIC_AES_KEY_FILE"] = str(p)
    try:
        k = mc.load_key(b"\x00"*16)
        assert k == key
    finally:
        del os.environ["MESHTASTIC_AES_KEY_FILE"]


def test_save_key_to_keyring_monkeypatch(monkeypatch):
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    class DummyKR:
        store = {}
        @staticmethod
        def set_password(svc, name, val):
            DummyKR.store[(svc, name)] = val
        @staticmethod
        def get_password(svc, name):
            return DummyKR.store.get((svc, name))
    monkeypatch.setitem(sys.modules, 'keyring', DummyKR)
    # reload module to pick up keyring
    importlib.reload(mc)
    assert mc.save_key_to_keyring(key) is True
    assert mc.load_key(b"\x00"*16) == key
