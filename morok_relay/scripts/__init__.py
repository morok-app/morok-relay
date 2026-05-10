"""
Generate a fresh Ed25519 keypair for this relay.

Output is two hex strings to put in .env:
    MOROK_RELAY_PUBKEY_HEX=...
    MOROK_RELAY_PRIVKEY_HEX=...

Run: python -m morok_relay.scripts.generate_relay_keypair
"""
import sys

from morok_relay.crypto import Ed25519Keypair


def main() -> int:
    keypair = Ed25519Keypair.generate()

    print("# Add these to your .env file:")
    print()
    print(f"MOROK_RELAY_PUBKEY_HEX={keypair.public_key_hex}")
    print(f"MOROK_RELAY_PRIVKEY_HEX={keypair.private_key_hex}")
    print()
    print("# Keep MOROK_RELAY_PRIVKEY_HEX secret — it identifies your relay")
    print("# in the federation. If leaked, others can impersonate this relay.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
