from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pathlib import Path

k = ec.generate_private_key(ec.SECP256R1())
priv = k.private_bytes(encoding=serialization.Encoding.PEM,
                       format=serialization.PrivateFormat.TraditionalOpenSSL,
                       encryption_algorithm=serialization.NoEncryption())
pub = k.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                  format=serialization.PublicFormat.SubjectPublicKeyInfo)

p = Path(__file__).parent
(p / "provisioning_private.pem").write_bytes(priv)
(p / "provisioning_public.pem").write_bytes(pub)
print(f"Wrote {p / 'provisioning_private.pem'} and {p / 'provisioning_public.pem'}")
