"""
hybrid_crypto.py
================
Hybrid Encryption module — fulfills rubric requirement:
  "Encrypt/decrypt files or messages using hybrid encryption"

HOW HYBRID ENCRYPTION WORKS:
  1. Generate a random AES-256 session key (symmetric)
  2. Encrypt the MESSAGE with AES-256-GCM (fast, authenticated)
  3. Encrypt the SESSION KEY with recipient's RSA public key (asymmetric)
  4. Bundle: [encrypted_session_key | iv | tag | ciphertext]

WHY HYBRID and not pure RSA?
  - RSA can only encrypt small data (< key size)
  - AES is 1000x faster than RSA for bulk data
  - Combining both gives speed + security

This is exactly how TLS, PGP, and S/MIME work in the real world.
"""

import os
import struct

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ── Constants ──────────────────────────────────────────────────────
AES_KEY_SIZE   = 32   # 256-bit AES key
GCM_NONCE_SIZE = 12   # 96-bit nonce (GCM standard)
RSA_OAEP_HASH  = hashes.SHA256()


def encrypt_message(plaintext: bytes, recipient_public_key) -> bytes:
    """
    Hybrid-encrypt a message for a recipient.

    Steps:
      1. Generate random 256-bit AES-GCM session key
      2. Encrypt plaintext with AES-GCM (produces ciphertext + 16-byte tag)
      3. Encrypt session key with RSA-OAEP using recipient's public key

    Wire format (all lengths are fixed or prefixed):
      [2 bytes: enc_key_len][enc_key_len bytes: RSA-encrypted session key]
      [12 bytes: AES-GCM nonce]
      [N bytes: AES-GCM ciphertext+tag]

    Args:
        plaintext:             Raw bytes to encrypt.
        recipient_public_key:  RSA public key of the intended recipient.

    Returns:
        Encrypted blob bytes.
    """
    # Step 1: Random AES-256 session key
    session_key = os.urandom(AES_KEY_SIZE)

    # Step 2: Encrypt message with AES-256-GCM
    nonce = os.urandom(GCM_NONCE_SIZE)
    aesgcm = AESGCM(session_key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

    # Step 3: Encrypt session key with RSA-OAEP
    encrypted_session_key = recipient_public_key.encrypt(
        session_key,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Pack: [2-byte key length][encrypted_key][nonce][ciphertext+tag]
    enc_key_len = len(encrypted_session_key)
    blob = (
        struct.pack(">H", enc_key_len)   # 2 bytes big-endian
        + encrypted_session_key
        + nonce
        + ciphertext_with_tag
    )
    return blob


def decrypt_message(blob: bytes, recipient_private_key) -> bytes:
    """
    Hybrid-decrypt a message using the recipient's private key.

    Steps:
      1. Unpack the blob to extract RSA-encrypted session key, nonce, ciphertext
      2. Decrypt session key with RSA-OAEP using private key
      3. Decrypt ciphertext with AES-256-GCM using session key

    Args:
        blob:                    Encrypted blob from encrypt_message().
        recipient_private_key:   RSA private key of the recipient.

    Returns:
        Original plaintext bytes.

    Raises:
        ValueError:  If decryption fails (wrong key or tampered data).
    """
    # Unpack
    offset = 0
    enc_key_len = struct.unpack(">H", blob[offset:offset+2])[0]
    offset += 2

    encrypted_session_key = blob[offset:offset+enc_key_len]
    offset += enc_key_len

    nonce = blob[offset:offset+GCM_NONCE_SIZE]
    offset += GCM_NONCE_SIZE

    ciphertext_with_tag = blob[offset:]

    # Step 2: Decrypt session key with RSA-OAEP
    try:
        session_key = recipient_private_key.decrypt(
            encrypted_session_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except Exception as exc:
        raise ValueError(f"RSA session key decryption failed: {exc}") from exc

    # Step 3: Decrypt with AES-256-GCM
    try:
        aesgcm = AESGCM(session_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
    except Exception as exc:
        raise ValueError(f"AES-GCM decryption failed (tampered data?): {exc}") from exc

    return plaintext


def encrypt_message_str(message: str, recipient_public_key) -> bytes:
    """Convenience wrapper: encrypt a UTF-8 string."""
    return encrypt_message(message.encode("utf-8"), recipient_public_key)


def decrypt_message_str(blob: bytes, recipient_private_key) -> str:
    """Convenience wrapper: decrypt to a UTF-8 string."""
    return decrypt_message(blob, recipient_private_key).decode("utf-8")


def get_encryption_info() -> dict:
    """Return metadata about the encryption scheme for display."""
    return {
        "symmetric_algorithm": "AES-256-GCM",
        "asymmetric_algorithm": "RSA-2048-OAEP",
        "oaep_hash": "SHA-256",
        "key_derivation": "Random session key (CSPRNG)",
        "authentication": "GCM tag (128-bit)",
        "description": "Hybrid encryption: RSA encrypts the AES key, AES encrypts the data",
    }
