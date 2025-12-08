#!/usr/bin/env python3
"""
Sender side of the secure communication system.

Steps:
  1. Load receiver's RSA public key.
  2. Read plaintext message from a .txt file.
  3. Generate a random AES key and IV.
  4. Encrypt the message with AES-256-CBC.
  5. Derive a MAC key from the AES key and compute HMAC-SHA256.
  6. Encrypt the AES key with RSA-OAEP.
  7. Write everything to a Transmitted_Data file.
"""

from base64 import b64encode
from pathlib import Path

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Configuration paths
PLAINTEXT_PATH = Path("message.txt")
RECEIVER_PUBLIC_KEY = Path("bob_pub.pem")
OUT_PACKET = Path("Transmitted_Data.txt")

BLOCK_SIZE = 16  # AES block size in bytes


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Apply PKCS#7 padding."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len


def derive_mac_key(aes_key: bytes) -> bytes:
    """
    Derive a MAC key from the AES key.

    We use HMAC-based derivation so the MAC key is related
    but not equal to the encryption key.
    """
    h = HMAC.new(aes_key, digestmod=SHA256)
    h.update(b"mac-derivation")
    return h.digest()


def make_packet(ek: bytes, iv: bytes, ct: bytes, tag: bytes) -> str:
    """
    Build a simple text-based packet.

    Each line has the form:
      LABEL:base64-data
    """
    lines = [
        "ENC_AES_KEY:" + b64encode(ek).decode("ascii"),
        "IV:" + b64encode(iv).decode("ascii"),
        "CIPHERTEXT:" + b64encode(ct).decode("ascii"),
        "MAC:" + b64encode(tag).decode("ascii"),
    ]
    return "\n".join(lines) + "\n"


def main() -> None:
    # 1. Load receiver's RSA public key
    pub_key_bytes = RECEIVER_PUBLIC_KEY.read_bytes()
    receiver_pub = RSA.import_key(pub_key_bytes)

    # 2. Read plaintext message from file
    plaintext = PLAINTEXT_PATH.read_bytes()

    # 3. Generate AES key and IV
    aes_key = get_random_bytes(32)  # 256-bit AES key
    iv = get_random_bytes(BLOCK_SIZE)

    # 4. Encrypt message with AES-256-CBC
    padded = pkcs7_pad(plaintext, BLOCK_SIZE)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = aes_cipher.encrypt(padded)

    # 5. Derive MAC key and compute HMAC over iv || ciphertext
    mac_key = derive_mac_key(aes_key)
    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(iv + ciphertext)
    tag = mac.digest()

    # 6. Encrypt AES key with receiver's RSA public key (RSA-OAEP)
    rsa_cipher = PKCS1_OAEP.new(receiver_pub, hashAlgo=SHA256)
    enc_aes_key = rsa_cipher.encrypt(aes_key)

    # 7. Write everything to the transmitted data file
    packet_text = make_packet(enc_aes_key, iv, ciphertext, tag)
    OUT_PACKET.write_text(packet_text, encoding="utf-8")

    print("[sender] Message encrypted and written to", OUT_PACKET)


if __name__ == "__main__":
    main()