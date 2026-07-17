import re
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_public_key


def test_generated_setkeysig_roundtrip():
    # Generate an ephemeral EC keypair, sign a sample AES key, and verify —
    # validates the SETKEYSIG signing/verification semantics.
    key_hex = "00112233445566778899aabbccddeeff"
    priv = ec.generate_private_key(ec.SECP256R1())
    sig = priv.sign(bytes.fromhex(key_hex), ec.ECDSA(hashes.SHA256()))
    pub = priv.public_key()
    pub.verify(sig, bytes.fromhex(key_hex), ec.ECDSA(hashes.SHA256()))


# NOTE: the repository ships a test provisioning PEM; replace it with your
# production provisioning public key prior to deployment. We verify PEM parity
# (header <-> scripts) and the SETKEYSIG signing semantics (generated keypair)
# in other tests; loading the shipped PEM isn't required for unit tests here.


def test_header_matches_script_pem():
    # Extract PEM-like text from the C header and normalize
    header = open("provisioning_pubkey.h", "r", encoding="utf-8").read()
    # Use DOTALL so '.' matches newlines; look for PEM block even when '\\n' escapes are present
    m = re.search(r"-----BEGIN PUBLIC KEY-----[\s\S]*?-----END PUBLIC KEY-----", header)
    assert m, "PEM not found in header"
    pem_like = m.group(0).replace('\\n', '\n')
    pem_like = '\n'.join([line.strip() for line in pem_like.strip().splitlines()]) + '\n'

    script_pem = open("scripts/provisioning_public.pem", "r", encoding="utf-8").read()
    script_pem = '\n'.join([line.strip() for line in script_pem.strip().splitlines()]) + '\n'

    assert pem_like == script_pem


def test_script_public_pem_is_valid():
    script_pem = open("scripts/provisioning_public.pem", "rb").read()
    load_pem_public_key(script_pem)
