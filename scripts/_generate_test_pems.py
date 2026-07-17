from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from pathlib import Path

k = ec.generate_private_key(ec.SECP256R1())
priv = k.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)
pub = k.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
)

p = Path(__file__).parent
(p / "provisioning_private.pem").write_bytes(priv)
(p / "provisioning_public.pem").write_bytes(pub)
escaped_pub = pub.decode("ascii").replace("\n", "\\n")
(p.parent / "provisioning_pubkey.h").write_text(
    "#ifndef PROVISIONING_PUBKEY_H\n"
    "#define PROVISIONING_PUBKEY_H\n\n"
    "// Provisioning public key (PEM). Replace this file with your production\n"
    "// provisioning public key (PEM) prior to deployment.\n"
    f'static const char PROVISIONING_PUBKEY_PEM[] = "{escaped_pub}";\n\n'
    "#endif // PROVISIONING_PUBKEY_H\n",
    encoding="utf-8",
)
print(f"Wrote gitignored test keypair under {p}")
