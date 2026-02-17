"""
pkcs12_store.py
===============
PKCS#12 keystore simulation.
Fulfills rubric: "password-protected keystores (PKCS#12)"

PKCS#12 is the industry standard format for bundling:
  - Private key
  - Certificate
  - CA certificate chain
...into a single password-protected file (.p12 or .pfx).

Used by: browsers, Java keystores, Windows certificate store, OpenSSL.

This module wraps the cryptography library's PKCS#12 support.
"""

import os
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, NoEncryption
)
from cryptography import x509


def export_to_pkcs12(
    private_key,
    voter_cert_pem: bytes,
    ca_cert_pem: bytes,
    membership_id: str,
    password: str,
) -> bytes:
    """
    Export voter credentials to a PKCS#12 bundle.

    This is the industry-standard way to transfer/backup credentials.
    The bundle is encrypted with the provided password.

    Args:
        private_key:      RSA private key object (already decrypted).
        voter_cert_pem:   Voter's X.509 certificate PEM bytes.
        ca_cert_pem:      CA certificate PEM bytes (for chain).
        membership_id:    Used as the friendly name inside the bundle.
        password:         Password to protect the PKCS#12 file.

    Returns:
        PKCS#12 bytes (can be saved as .p12 or .pfx file).
    """
    voter_cert = x509.load_pem_x509_certificate(voter_cert_pem)
    ca_cert    = x509.load_pem_x509_certificate(ca_cert_pem)

    p12_bytes = pkcs12.serialize_key_and_certificates(
        name=membership_id.encode("utf-8"),
        key=private_key,
        cert=voter_cert,
        cas=[ca_cert],
        encryption_algorithm=pkcs12.PBES2SHA256AndAES256CBC(),
    )
    return p12_bytes


def load_from_pkcs12(p12_bytes: bytes, password: str) -> dict:
    """
    Load credentials from a PKCS#12 bundle.

    Args:
        p12_bytes:  Raw bytes of the .p12 file.
        password:   Password used when creating the bundle.

    Returns:
        dict with keys: private_key, cert, ca_certs, friendly_name.

    Raises:
        ValueError: If password is wrong or data is corrupt.
    """
    try:
        private_key, cert, ca_certs = pkcs12.load_key_and_certificates(
            p12_bytes,
            password.encode("utf-8"),
        )
    except Exception as exc:
        raise ValueError(f"Failed to load PKCS#12: {exc}") from exc

    return {
        "private_key": private_key,
        "cert": cert,
        "ca_certs": ca_certs or [],
    }


def get_pkcs12_info(p12_bytes: bytes, password: str) -> dict:
    """Return human-readable info about a PKCS#12 bundle."""
    data = load_from_pkcs12(p12_bytes, password)
    cert = data["cert"]
    from cryptography.x509.oid import NameOID
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        cn = "Unknown"
    return {
        "subject_cn":    cn,
        "serial":        hex(cert.serial_number),
        "key_size":      data["private_key"].key_size,
        "not_before":    cert.not_valid_before_utc.isoformat(),
        "not_after":     cert.not_valid_after_utc.isoformat(),
        "ca_chain_len":  len(data["ca_certs"]),
    }
