# Secure Communication System – README

## Overview
This project implements a secure two-party communication system using a hybrid cryptographic design. Messages are encrypted with AES, the AES key is encrypted with RSA, and integrity is guaranteed with HMAC. Communication is simulated using a local file rather than network sockets.

This README explains the system design, algorithms used, data flow, file structure, and instructions for running the programs.

---

## System Design

### Parties and Keys
Each party (Alice and Bob) has:
- A **2048-bit RSA key pair**
- Public key stored as: `<party>_public.pem`
- Private key stored as: `<party>_private.pem`

Parties learn each other's public keys by reading the `.pem` files.

---

## Algorithms Used

### Asymmetric Encryption
- **RSA-2048 (OAEP + SHA-256)**
- Used only to encrypt the random AES session key

### Symmetric Encryption
- **AES-256 in CBC mode**
- AES key: 32 bytes  
- IV: 16 bytes (block size)

### Message Authentication Code (MAC)
- **HMAC-SHA256**
- MAC key derived as:  
  `mac_key = SHA256(AES_key || "mac")`
- MAC computed over:  
  `iv || ciphertext`  
  (Encrypt-then-MAC design)

---

## Sender Workflow

1. Read plaintext from `message.txt`
2. Generate AES-256 key and random 16-byte IV
3. Encrypt plaintext using AES-256-CBC + PKCS7 padding
4. Derive MAC key from AES key
5. Compute HMAC-SHA256 over `iv || ciphertext`
6. Encrypt AES key using receiver’s RSA-2048-OAEP public key
7. Base64-encode all binary fields
8. Write the following JSON structure to **`Transmitted_Data.txt`**:

```json
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
```

## Receiver Workflow

1. Read and parse `Transmitted_Data.txt`.
2. Base64-decode all fields (`enc_aes_key`, `iv`, `ciphertext`, `mac`).
3. Decrypt the AES key using the receiver’s RSA private key (RSA-OAEP, SHA-256).
4. Derive the MAC key using the same method as the sender.
5. Recompute HMAC-SHA256 over `iv || ciphertext` and compare to the received MAC.
   - If the MAC does not match, reject the message.
6. Decrypt the ciphertext using AES-256-CBC.
7. Remove PKCS7 padding from the decrypted data.
8. Write the recovered plaintext to `decrypted_message.txt`.

## File Structure
secure_comm/
  gen_keys.py
  sender.py
  receiver.py
  message.txt
  decrypted_message.txt
  Transmitted_Data.txt
  alice_private.pem
  alice_public.pem
  bob_private.pem
  bob_public.pem
  README.md

## How to Run

### 1. Generate RSA Keys
Run the key generation script to create RSA key pairs for both Alice and Bob:

```bash
python gen_keys.py
```

This produces:
- alice_private.pem
- alice_public.pem
- bob_private.pem
- bob_public.pem

### 2. Prepare the Message
Edit or replace the plaintext file:

```bash
echo "Hello world" > message.txt
```

This is the file that will be encrypted and sent.

### 3. Run the Sender
Execute the sender script:

```bash
python sender.py
```
This generates the simulated a .txt from transmitted data.

### 4. Run the Receiver
Execute the receiver script:

```bash
python receiver.py
```
After successful MAC verification and decryption, the output plaintext is written to:
```bash
cat decrypted_message.txt
```
