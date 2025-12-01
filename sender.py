# sender.py
import json
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

TRANSMIT_FILE = "Transmitted_Data.json"
PLAINTEXT_FILE = "message.txt"

RECEIVER_PUBLIC_KEY_FILE = "bob_public.pem"

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)

def derive_mac_key(aes_key: bytes) -> bytes:
    hasher = SHA256.new()
    hasher.update(aes_key + b"mac")
    return hasher.digest()

def main():
    # 1. Load receiver public key
    with open(RECEIVER_PUBLIC_KEY_FILE, "rb") as f:
        receiver_pub = RSA.import_key(f.read())

    # 2. Read plaintext from file
    with open(PLAINTEXT_FILE, "rb") as f:
        plaintext = f.read()

    # 3. Generate AES key and IV
    aes_key = get_random_bytes(32)  # 256 bit
    iv = get_random_bytes(16)       # AES block size

    # 4. AES-CBC encrypt with PKCS7 padding
    padded_plaintext = pkcs7_pad(plaintext, 16)
    cipher_aes = AES.new(aes_key, AES.MODE_CBC, iv)
    ciphertext = cipher_aes.encrypt(padded_plaintext)

    # 5. Derive MAC key and compute HMAC over iv || ciphertext
    mac_key = derive_mac_key(aes_key)
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(iv + ciphertext)
    mac = h.digest()

    # 6. Encrypt AES key with receiver's RSA public key (RSA-OAEP)
    cipher_rsa = PKCS1_OAEP.new(receiver_pub, hashAlgo=SHA256)
    enc_aes_key = cipher_rsa.encrypt(aes_key)

    # 7. Base64 encode fields for JSON
    data_out = {
        "enc_aes_key": b64encode(enc_aes_key).decode("ascii"),
        "iv": b64encode(iv).decode("ascii"),
        "ciphertext": b64encode(ciphertext).decode("ascii"),
        "mac": b64encode(mac).decode("ascii"),
        "meta": {
            "rsa": "RSA-2048-OAEP-SHA256",
            "aes": "AES-256-CBC-256bit",
            "mac": "HMAC-SHA256",
            "padding": "PKCS7",
            "note": "Encrypt-then-MAC over iv||ciphertext"
        }
    }

    # 8. Write simulated network file
    with open(TRANSMIT_FILE, "w") as f:
        json.dump(data_out, f, indent=2)

    print("Sender: message encrypted and written to Transmitted_Data.json")

if __name__ == "__main__":
    main()
