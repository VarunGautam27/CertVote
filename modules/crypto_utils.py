"""
crypto_utils.py
===============
Core cryptographic utilities for the CertVote PKI system.

Provides:
  - RSA 2048-bit key-pair generation
  - Private-key encryption/decryption with a PIN (AES-256-CBC via PKCS8)
  - SHA-256 hashing helpers
  - Vote payload construction and signing
  - Signature verification
  - Receipt hash computation

All cryptographic work is done with the `cryptography` library (pyca).
Private keys NEVER leave the voter's machine in plain-text form.
"""

import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    BestAvailableEncryption,
    NoEncryption,
)

# ------------------------------------------------------------------ #
#  RSA Key Generation                                                  #
# ------------------------------------------------------------------ #

def generate_rsa_keypair(key_bits: int = 2048):
    """
    Generate an RSA key pair.

    Args:
        key_bits: Key size in bits (default 2048).

    Returns:
        (private_key, public_key) as cryptography objects.
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_bits,
    )
    public_key = private_key.public_key()
    return private_key, public_key


# ------------------------------------------------------------------ #
#  Private Key Serialisation (PEM, encrypted with PIN)                #
# ------------------------------------------------------------------ #

def serialize_private_key_encrypted(private_key, pin: str) -> bytes:
    """
    Serialize a private key to PEM format, encrypted with the voter's PIN.

    Uses PKCS8 format with AES-256-CBC encryption (BestAvailableEncryption).
    The PIN is used as the passphrase.

    Args:
        private_key: RSA private key object.
        pin: Voter-chosen PIN/passphrase (str).

    Returns:
        Encrypted PEM bytes.
    """
    pin_bytes = pin.encode("utf-8")
    pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=BestAvailableEncryption(pin_bytes),
    )
    return pem


def deserialize_private_key_encrypted(pem_bytes: bytes, pin: str):
    """
    Load and decrypt an encrypted PEM private key using the voter's PIN.

    Args:
        pem_bytes: Encrypted PEM bytes from disk.
        pin: Voter PIN used during encryption.

    Returns:
        Decrypted RSA private key object.

    Raises:
        ValueError: If the PIN is wrong or the data is corrupt.
    """
    pin_bytes = pin.encode("utf-8")
    try:
        private_key = serialization.load_pem_private_key(
            pem_bytes,
            password=pin_bytes,
        )
    except (ValueError, TypeError) as exc:
        raise ValueError("Failed to decrypt private key. Wrong PIN?") from exc
    return private_key


def serialize_public_key(public_key) -> bytes:
    """Serialize a public key to PEM bytes (SubjectPublicKeyInfo)."""
    return public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )


def deserialize_public_key(pem_bytes: bytes):
    """Load a public key from PEM bytes."""
    return serialization.load_pem_public_key(pem_bytes)


# ------------------------------------------------------------------ #
#  SHA-256 Helpers                                                     #
# ------------------------------------------------------------------ #

def sha256_hex(data: bytes) -> str:
    """Return the hex-encoded SHA-256 digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def sha256_of_string(text: str) -> str:
    """Return SHA-256 hex digest of a UTF-8 string."""
    return sha256_hex(text.encode("utf-8"))


# ------------------------------------------------------------------ #
#  Vote Payload                                                        #
# ------------------------------------------------------------------ #

def build_vote_payload(election_id: str, choice: str, nonce: str = None) -> dict:
    """
    Construct a structured vote payload dictionary.

    Args:
        election_id: The election identifier (e.g. "ITC_ELEC_2026").
        choice: Candidate name chosen by voter.
        nonce: Optional nonce; one is generated if not supplied.

    Returns:
        dict with keys: election_id, choice, timestamp, nonce.
    """
    if nonce is None:
        nonce = secrets.token_hex(16)
    return {
        "election_id": election_id,
        "choice": choice,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": nonce,
    }


def payload_to_bytes(payload: dict) -> bytes:
    """Deterministically serialise a payload dict to UTF-8 bytes for signing."""
    return json.dumps(payload, sort_keys=True, ensure_ascii=True).encode("utf-8")


def hash_payload(payload: dict) -> str:
    """SHA-256 hash the canonical JSON form of a payload. Returns hex string."""
    return sha256_hex(payload_to_bytes(payload))


# ------------------------------------------------------------------ #
#  Signing & Verification                                              #
# ------------------------------------------------------------------ #

def sign_payload(private_key, payload: dict) -> bytes:
    """
    Sign a vote payload with the voter's RSA private key.

    Process:
      1. Canonicalise payload → JSON bytes.
      2. Compute SHA-256 digest.
      3. Sign digest with RSA-PSS (SHA-256, MGF1).

    Args:
        private_key: Decrypted RSA private key.
        payload: Vote payload dict.

    Returns:
        Raw signature bytes.
    """
    data_bytes = payload_to_bytes(payload)
    signature = private_key.sign(
        data_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(public_key, payload: dict, signature: bytes) -> bool:
    """
    Verify an RSA-PSS signature against the canonical payload bytes.

    Args:
        public_key: Voter's RSA public key.
        payload: Original vote payload dict (must match what was signed).
        signature: Raw signature bytes.

    Returns:
        True if valid, False if invalid.
    """
    from cryptography.exceptions import InvalidSignature

    data_bytes = payload_to_bytes(payload)
    try:
        public_key.verify(
            signature,
            data_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


# ------------------------------------------------------------------ #
#  Receipt Hash                                                        #
# ------------------------------------------------------------------ #

def compute_receipt_hash(vote_hash: str, server_salt: str, nonce: str) -> str:
    """
    Compute a receipt hash for the voter.

    Formula: SHA256(vote_hash + SERVER_SALT + nonce)

    The receipt lets a voter prove their vote was counted (inclusion proof)
    without revealing their identity to the tally board.

    Args:
        vote_hash: Hex SHA-256 hash of the signed payload.
        server_salt: Secret salt from config.json.
        nonce: Same nonce that was embedded in the vote payload.

    Returns:
        Hex SHA-256 receipt hash string.
    """
    combined = f"{vote_hash}{server_salt}{nonce}"
    return sha256_of_string(combined)


# ------------------------------------------------------------------ #
#  used_tag Computation                                                #
# ------------------------------------------------------------------ #

def compute_used_tag(cert_serial: str, election_id: str) -> str:
    """
    Compute the anonymised double-vote-prevention tag.

    Formula: SHA256(cert_serial + "|" + election_id)

    Stored in the used_credentials table instead of the cert serial or
    membership_id, so the vote cannot be traced back to the voter.

    Args:
        cert_serial: Certificate serial number (hex string).
        election_id: Election identifier.

    Returns:
        Hex SHA-256 tag string.
    """
    raw = f"{cert_serial}|{election_id}"
    return sha256_of_string(raw)


# ------------------------------------------------------------------ #
#  Key Metadata Helper                                                 #
# ------------------------------------------------------------------ #

def describe_key(private_key) -> str:
    """Return a human-readable string describing a private key."""
    key_size = private_key.key_size
    pub = private_key.public_key()
    pub_nums = pub.public_numbers()
    # Show only the first 20 hex chars of the modulus as a fingerprint
    modulus_hex = hex(pub_nums.n)[2:22]
    return f"RSA-{key_size} | modulus prefix: {modulus_hex}..."
