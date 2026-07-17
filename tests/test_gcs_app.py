from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pytest

pytest.importorskip("flask")
import gcs_app  # noqa: E402
import meshtastic_control  # noqa: E402
import meshtastic_crypto as crypto  # noqa: E402


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
        self.sent.append((data, destinationId, portNum, wantAck, kwargs))


def _install_dummy_interface(monkeypatch):
    dummy = DummyInterface()
    monkeypatch.setattr(gcs_app, "interface", dummy)
    monkeypatch.setattr(meshtastic_control, "interface", dummy)
    return dummy


def test_control_route_sends_encrypted_command(monkeypatch, tmp_path):
    dummy = _install_dummy_interface(monkeypatch)
    seq_file = tmp_path / "seq"
    monkeypatch.setattr(
        meshtastic_control,
        "next_seq",
        lambda seq_file=str(seq_file): 7,
    )

    client = gcs_app.app.test_client()
    response = client.post("/api/control", json={"drone_id": 3, "command": 1})

    assert response.status_code == 200
    assert response.get_json() == {"success": True, "seq": 7}
    assert len(dummy.sent) == 1

    wire, destination, port, want_ack, kwargs = dummy.sent[0]
    assert destination == "^all"
    assert port == meshtastic_control.DRONE_CONTROL_COMMAND_DATA_TYPE
    assert want_ack is True
    assert kwargs == {}
    plaintext = AESGCM(meshtastic_control.KEY).decrypt(wire[:12], wire[12:], None)
    assert crypto.unpack_control_plaintext(plaintext) == (7, 3, 1)


def test_control_route_rejects_invalid_command(monkeypatch):
    _install_dummy_interface(monkeypatch)

    client = gcs_app.app.test_client()
    response = client.post("/api/control", json={"drone_id": 3, "command": 99})

    assert response.status_code == 400
    assert response.get_json()["error"] == "unsupported command"


def test_control_route_requires_token_when_configured(monkeypatch):
    _install_dummy_interface(monkeypatch)
    monkeypatch.setenv("MESHTASTIC_API_TOKEN", "secret-token")

    client = gcs_app.app.test_client()
    response = client.post("/api/control", json={"drone_id": 3, "command": 1})

    assert response.status_code == 401

    authorized = client.post(
        "/api/control",
        json={"drone_id": 3, "command": 1},
        headers={"Authorization": "Bearer secret-token"},
    )
    assert authorized.status_code == 200
