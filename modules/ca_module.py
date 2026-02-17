"""
ca_module.py  —  Certificate Authority for CertVote PKI system.
Generates CA keypair, issues X.509 voter certificates, verifies certs.
"""

import datetime
import json
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key,
)
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature

from modules.paths import CONFIG_PATH, CA_DIR, CA_KEY_PATH, CA_CERT_PATH


def _load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def ca_exists() -> bool:
    return os.path.exists(CA_KEY_PATH) and os.path.exists(CA_CERT_PATH)


def initialize_ca(log_fn=None) -> dict:
    def _log(msg):
        if log_fn: log_fn(msg)

    os.makedirs(CA_DIR, exist_ok=True)
    cfg = _load_config()
    ca_cfg = cfg["ca"]
    key_bits = cfg["key_bits"]

    if ca_exists():
        _log("CA already initialised. Loading existing CA.")
        ca_cert = _load_ca_cert()
        return {
            "ca_cert_pem": ca_cert.public_bytes(Encoding.PEM).decode(),
            "ca_serial": hex(ca_cert.serial_number),
            "ca_subject": ca_cert.subject.rfc4514_string(),
            "key_size": key_bits,
            "already_existed": True,
        }

    _log(f"Generating CA RSA-{key_bits} key pair ...")
    ca_private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, ca_cfg["country"]),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ca_cfg["state"]),
        x509.NameAttribute(NameOID.LOCALITY_NAME, ca_cfg["locality"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_cfg["organization"]),
        x509.NameAttribute(NameOID.COMMON_NAME, ca_cfg["common_name"]),
    ])

    validity_days = cfg["cert_validity_days"]
    now = datetime.datetime.now(datetime.timezone.utc)

    _log("Building self-signed CA certificate ...")
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days * 12))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    _log(f"Writing CA private key -> {CA_KEY_PATH}")
    with open(CA_KEY_PATH, "wb") as fh:
        fh.write(ca_private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))

    _log(f"Writing CA certificate -> {CA_CERT_PATH}")
    with open(CA_CERT_PATH, "wb") as fh:
        fh.write(ca_cert.public_bytes(Encoding.PEM))

    serial_hex = hex(ca_cert.serial_number)
    _log(f"CA initialised. Serial: {serial_hex}")
    _log(f"Key size: RSA-{key_bits}")

    return {
        "ca_cert_pem": ca_cert.public_bytes(Encoding.PEM).decode(),
        "ca_serial": serial_hex,
        "ca_subject": ca_cert.subject.rfc4514_string(),
        "key_size": key_bits,
        "already_existed": False,
    }


def _load_ca_private_key():
    if not os.path.exists(CA_KEY_PATH):
        raise FileNotFoundError("CA private key not found. Please initialise the CA first.")
    with open(CA_KEY_PATH, "rb") as fh:
        return load_pem_private_key(fh.read(), password=None)


def _load_ca_cert():
    if not os.path.exists(CA_CERT_PATH):
        raise FileNotFoundError("CA certificate not found. Please initialise the CA first.")
    with open(CA_CERT_PATH, "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read())


def load_ca_cert_pem() -> bytes:
    with open(CA_CERT_PATH, "rb") as fh:
        return fh.read()


def issue_voter_certificate(voter_public_key, election_id: str, membership_id: str, log_fn=None) -> tuple:
    def _log(msg):
        if log_fn: log_fn(msg)

    cfg = _load_config()
    ca_cfg = cfg["ca"]
    validity_days = cfg["cert_validity_days"]

    ca_private_key = _load_ca_private_key()
    ca_cert = _load_ca_cert()
    now = datetime.datetime.now(datetime.timezone.utc)

    subject_cn = f"{election_id}:{membership_id}"
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, ca_cfg["country"]),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ca_cfg["organization"]),
        x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
    ])

    _log(f"Issuing certificate for {membership_id} ...")
    voter_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(voter_public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(election_id)]), critical=False
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    cert_pem = voter_cert.public_bytes(Encoding.PEM)
    serial_hex = hex(voter_cert.serial_number)
    _log(f"Certificate issued. Serial: {serial_hex}")
    return cert_pem, serial_hex


def verify_voter_certificate(cert_pem: bytes, election_id: str, log_fn=None) -> dict:
    def _log(msg):
        if log_fn: log_fn(msg)

    result = {
        "valid": False, "cert_serial": None, "subject_cn": None,
        "issuer": None, "election_id_match": False,
        "message": "", "voter_public_key": None,
    }

    try:
        voter_cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = _load_ca_cert()
    except Exception as exc:
        result["message"] = f"Failed to parse certificate: {exc}"
        _log(result["message"])
        return result

    result["cert_serial"] = hex(voter_cert.serial_number)
    try:
        result["subject_cn"] = voter_cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        result["subject_cn"] = "Unknown"

    result["issuer"] = voter_cert.issuer.rfc4514_string()
    _log(f"Certificate serial  : {result['cert_serial']}")
    _log(f"Subject CN          : {result['subject_cn']}")
    _log(f"Issuer              : {result['issuer']}")

    try:
        ca_cert.public_key().verify(
            voter_cert.signature,
            voter_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            voter_cert.signature_hash_algorithm,
        )
        _log("Certificate signature verification PASS ✓")
    except InvalidSignature:
        result["message"] = "Certificate signature verification FAIL ✗"
        _log(result["message"])
        return result
    except Exception as exc:
        result["message"] = f"Certificate verification error: {exc}"
        _log(result["message"])
        return result

    cn = result["subject_cn"] or ""
    san_election_id = None
    try:
        san_ext = voter_cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san_ext.value.get_values_for_type(x509.DNSName)
        if dns_names:
            san_election_id = dns_names[0]
    except Exception:
        pass

    election_id_in_cn = cn.startswith(f"{election_id}:")
    election_id_in_san = san_election_id == election_id
    result["election_id_match"] = election_id_in_cn or election_id_in_san

    if not result["election_id_match"]:
        result["message"] = f"Election ID mismatch. CN='{cn}', Expected='{election_id}'"
        _log(result["message"])
        return result

    _log(f"Election ID verification PASS ✓ ({election_id})")

    now = datetime.datetime.now(datetime.timezone.utc)
    if now > voter_cert.not_valid_after_utc:
        result["message"] = "Certificate has expired."
        _log(result["message"])
        return result

    result["valid"] = True
    result["voter_public_key"] = voter_cert.public_key()
    result["message"] = "Certificate verification PASS ✓"
    _log(result["message"])
    return result


def get_cert_info(cert_pem: bytes) -> dict:
    cert = x509.load_pem_x509_certificate(cert_pem)
    cn = ""
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except Exception:
        pass
    election_id_parsed = membership_id_parsed = ""
    if ":" in cn:
        parts = cn.split(":", 1)
        election_id_parsed, membership_id_parsed = parts[0], parts[1]
    return {
        "serial": hex(cert.serial_number),
        "subject_cn": cn,
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "election_id": election_id_parsed,
        "membership_id": membership_id_parsed,
    }
