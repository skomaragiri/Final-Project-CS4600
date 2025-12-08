#!/usr/bin/env python3
"""
Receiver side of the secure communication system.

Steps:
  1. Load receiver's RSA private key.
  2. Read Transmitted_Data packet file.
  3. Base64 decode the encrypted AES key, IV, ciphertext, and MAC.
  4. Decrypt the AES key with RSA-OAEP.
  5. Derive the MAC key and verify HMAC-SHA256.
  6. If valid, decrypt the ciphertext with AES-256-CBC and remove padding.
  7. Write the recovered plaintext to decrypted_message.txt.
"""

from base64 import b64decode
from pathlib import Path
from hmac import compare_digest

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA

# Configuration paths
IN_PACKET = Path("transmission.txt")
RECEIVER_PRIVATE_KEY = Path("bob_priv.pem")
OUTPUT_PATH = Path("decrypted_message.txt")

BLOCK_SIZE = 16  # AES block size


def pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 padding and validate it."""
    if not data:
        raise ValueError("Cannot unpad empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS#7 padding bytes")
    return data[:-pad_len]


def derive_mac_key(aes_key: bytes) -> bytes:
    """Same MAC key derivation as on the sender."""
    h = HMAC.new(aes_key, digestmod=SHA256)
    h.update(b"mac-derivation")
    return h.digest()


def parse_packet(text: str) -> dict:
    """
    Parse the text-based transmitted packet into its components.

    Expected format:
      LABEL:base64-data
    """
    result: dict[str, bytes] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        label, b64val = line.split(":", 1)
        result[label.strip()] = b64decode(b64val.strip())
    return result


def main() -> None:
    # 1. Load RSA private key
    priv_key_bytes = RECEIVER_PRIVATE_KEY.read_bytes()
    receiver_priv = RSA.import_key(priv_key_bytes)

    # 2. Read and parse packet file
    packet_text = IN_PACKET.read_text(encoding="utf-8")
    fields = parse_packet(packet_text)

    enc_aes_key = fields["ENC_AES_KEY"]
    iv = fields["IV"]
    ciphertext = fields["CIPHERTEXT"]
    mac_recv = fields["MAC"]

    # 3. Decrypt AES key using RSA-OAEP
    rsa_cipher = PKCS1_OAEP.new(receiver_priv, hashAlgo=SHA256)
    aes_key = rsa_cipher.decrypt(enc_aes_key)

    # 4. Recompute MAC and verify
    mac_key = derive_mac_key(aes_key)
    mac = HMAC.new(mac_key, digestmod=SHA256)
    mac.update(iv + ciphertext)
    mac_calc = mac.digest()

    if not compare_digest(mac_calc, mac_recv):
        print("[receiver] MAC verification FAILED. Data may be altered.")
        return

    print("[receiver] MAC verified successfully.")

    # 5. Decrypt ciphertext using AES-256-CBC
    aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = aes_cipher.decrypt(ciphertext)

    try:
        plaintext = pkcs7_unpad(padded_plaintext, BLOCK_SIZE)
    except ValueError as exc:
        print(f"[receiver] Padding error: {exc}")
        return

    # 6. Write recovered message
    OUTPUT_PATH.write_bytes(plaintext)
    print("[receiver] Message decrypted and written to", OUTPUT_PATH)


if __name__ == "__main__":
    main()
