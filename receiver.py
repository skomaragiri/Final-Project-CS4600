# receiver.py
import json
from base64 import b64decode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import HMAC, SHA256

TRANSMIT_FILE = "Transmitted_Data.json"
OUTPUT_FILE = "decrypted_message.txt"

RECEIVER_PRIVATE_KEY_FILE = "bob_private.pem"

def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise ValueError("Invalid padding: empty data")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def derive_mac_key(aes_key: bytes) -> bytes:
    hasher = SHA256.new()
    hasher.update(aes_key + b"mac")
    return hasher.digest()

def constant_time_compare(a: bytes, b: bytes) -> bool:
    # Use HMAC compare_digest for constant time comparison
    try:
        from hmac import compare_digest
        return compare_digest(a, b)
    except ImportError:
        # Fallback: manual constant time loop
        if len(a) != len(b):
            return False
        result = 0
        for x, y in zip(a, b):
            result |= x ^ y
        return result == 0

def main():
    # 1. Load receiver private key
    with open(RECEIVER_PRIVATE_KEY_FILE, "rb") as f:
        receiver_priv = RSA.import_key(f.read())

    # 2. Read transmitted data file
    with open(TRANSMIT_FILE, "r") as f:
        data_in = json.load(f)

    enc_aes_key = b64decode(data_in["enc_aes_key"])
    iv = b64decode(data_in["iv"])
    ciphertext = b64decode(data_in["ciphertext"])
    mac_recv = b64decode(data_in["mac"])

    # 3. Decrypt AES key with RSA-OAEP
    cipher_rsa = PKCS1_OAEP.new(receiver_priv, hashAlgo=SHA256)
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    # 4. Derive MAC key and verify MAC
    mac_key = derive_mac_key(aes_key)
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    mac_calc = h.digest()

    if not constant_time_compare(mac_calc, mac_recv):
        print("Receiver: MAC verification failed. Data may be tampered.")
        return

    print("Receiver: MAC verified successfully.")

    # 5. Decrypt ciphertext with AES-256-CBC and remove padding
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    padded_plaintext = cipher_aes.decrypt(ciphertext)
    try:
        plaintext = pkcs7_unpad(padded_plaintext, 16)
    except ValueError as e:
        print(f"Receiver: padding error - {e}")
        return

    # 6. Write plaintext to file
    with open(OUTPUT_FILE, "wb") as f:
        f.write(plaintext)

    print(f"Receiver: message decrypted and written to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()