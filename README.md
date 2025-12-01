Secure Communication System – README
Overview

This project implements a secure two-party communication system using a hybrid cryptographic design. Messages are encrypted with AES, the AES key is encrypted with RSA, and integrity is guaranteed with HMAC. Communication is simulated using local files instead of sockets.

This README explains the system design, algorithms used, data flow, file structure, and instructions for running the sender and receiver programs.

System Design
Parties and Keys

Each communicating party (Alice, Bob) has:

An RSA key pair:

2048-bit RSA

Public key stored as:
<party>_public.pem

Private key stored as:
<party>_private.pem

Each party learns the other’s public key by reading the corresponding .pem file.

Algorithms Used
Asymmetric Encryption

RSA-2048 with OAEP (SHA-256)

Purpose: Encrypt the AES session key before transmission.

Symmetric Encryption

AES-256 in CBC mode

AES key length: 32 bytes

IV length: 16 bytes

Message Authentication Code (MAC)

HMAC-SHA256

MAC key derived from AES key:
mac_key = SHA256(AES_key || "mac")

MAC computed over:
iv || ciphertext
(Encrypt-then-MAC design)

Sender Data Flow

Read plaintext from message.txt.

Generate a random AES-256 key and a 16-byte IV.

Encrypt plaintext using AES-256-CBC + PKCS7 padding.

Derive MAC key from the AES key.

Compute HMAC-SHA256 over iv || ciphertext.

Encrypt AES key using receiver’s RSA-2048-OAEP public key.

Base64-encode all binary fields.

Write the following fields into a single JSON file named Transmitted_Data.json:

{
  "enc_aes_key": "<base64>",
  "iv": "<base64>",
  "ciphertext": "<base64>",
  "mac": "<base64>",
  "meta": {
    "rsa": "RSA-2048-OAEP-SHA256",
    "aes": "AES-256-CBC",
    "mac": "HMAC-SHA256",
    "padding": "PKCS7"
  }
}

Receiver Data Flow

Read and parse Transmitted_Data.json.

Base64-decode encrypted AES key, IV, ciphertext, and MAC.

Decrypt AES key using the receiver’s RSA-2048-OAEP private key.

Derive the same MAC key.

Recompute HMAC-SHA256 over iv || ciphertext and compare with received MAC.

Reject the message if verification fails.

Decrypt ciphertext using AES-256-CBC and remove PKCS7 padding.

Output the recovered plaintext to decrypted_message.txt.

File Structure
secure_comm/
  gen_keys.py
  sender.py
  receiver.py
  message.txt
  decrypted_message.txt
  Transmitted_Data.json
  alice_private.pem
  alice_public.pem
  bob_private.pem
  bob_public.pem
  README.md

How to Run
1. Generate RSA Key Pairs
python gen_keys.py

2. Prepare a message

Edit or replace:

message.txt

3. Run the Sender
python sender.py


This creates:

Transmitted_Data.json

4. Run the Receiver
python receiver.py


Recovered plaintext will appear in:

decrypted_message.txt

Security Notes

RSA-OAEP protects the AES key against chosen-ciphertext attacks.

AES-256-CBC secures message confidentiality.

Encrypt-then-MAC with HMAC-SHA256 ensures message integrity.

MAC key derived from AES key ensures only the correct receiver can authenticate the data.

Possible Extensions

Add replay protection using timestamps or sequence numbers.

Add digital signatures for sender authentication.

Use AES-GCM (authenticated encryption) as an alternative design.
