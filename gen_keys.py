# gen_keys.py
from Crypto.PublicKey import RSA

def generate_keypair(name: str, bits: int = 2048) -> None:
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open(f"{name}_private.pem", "wb") as f:
        f.write(private_key)

    with open(f"{name}_public.pem", "wb") as f:
        f.write(public_key)

    print(f"Generated {bits}-bit RSA key pair for {name}")

def main():
    generate_keypair("alice")
    generate_keypair("bob")

if __name__ == "__main__":
    main()
