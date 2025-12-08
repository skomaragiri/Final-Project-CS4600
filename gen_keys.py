#!/usr/bin/env python3
"""
Generate RSA key pairs for two parties (Alice and Bob).

Each party gets:
  <name>_priv.pem  - RSA private key (keep secret)
  <name>_pub.pem   - RSA public key (share with others)
"""

from Crypto.PublicKey import RSA
from pathlib import Path

KEY_SIZE_BITS = 2048


def create_rsa_pair(label: str, bits: int = KEY_SIZE_BITS) -> None:
    """Create and store an RSA keypair for the given label."""
    key = RSA.generate(bits)

    priv_bytes = key.export_key()
    pub_bytes = key.publickey().export_key()

    Path(f"{label}_priv.pem").write_bytes(priv_bytes)
    Path(f"{label}_pub.pem").write_bytes(pub_bytes)

    print(f"[keys] Generated {bits}-bit RSA key pair for {label}")


def main() -> None:
    # One pair for each party in the system
    for who in ("alice", "bob"):
        create_rsa_pair(who)


if __name__ == "__main__":
    main()