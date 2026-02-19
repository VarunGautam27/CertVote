"""
storage.py  —  Local credential storage for CertVote.

Stores voter keys in:
  Windows : %APPDATA%\\CertVote\\credentials\\<election_id>\\<membership_id>\\
  Linux/Mac: ~/.itclubvote/credentials/<election_id>/<membership_id>/

Files stored per voter:
  private_key.pem.enc  (AES-encrypted PKCS8 private key)
  voter_cert.pem       (X.509 voter certificate)
  meta.json            (key metadata)
"""

import json
import os
import platform
import shutil


def _get_root_dir() -> str:
    if platform.system() == "Windows":
        appdata = os.environ.get("APPDATA", os.path.expanduser("~"))
        root = os.path.join(appdata, "CertVote", "credentials")
    else:
        root = os.path.join(os.path.expanduser("~"), ".certvote", "credentials")
    os.makedirs(root, exist_ok=True)
    return root


def get_voter_dir(election_id: str, membership_id: str) -> str:
    root = _get_root_dir()
    voter_dir = os.path.join(root, election_id, membership_id)
    os.makedirs(voter_dir, exist_ok=True)
    return voter_dir


def _private_key_path(election_id, membership_id):
    return os.path.join(get_voter_dir(election_id, membership_id), "private_key.pem.enc")

def _cert_path(election_id, membership_id):
    return os.path.join(get_voter_dir(election_id, membership_id), "voter_cert.pem")

def _meta_path(election_id, membership_id):
    return os.path.join(get_voter_dir(election_id, membership_id), "meta.json")


def save_private_key(election_id, membership_id, encrypted_pem: bytes) -> None:
    with open(_private_key_path(election_id, membership_id), "wb") as fh:
        fh.write(encrypted_pem)

def save_certificate(election_id, membership_id, cert_pem: bytes) -> None:
    with open(_cert_path(election_id, membership_id), "wb") as fh:
        fh.write(cert_pem)

def save_meta(election_id, membership_id, username, key_size, cert_serial) -> None:
    meta = {
        "election_id": election_id,
        "membership_id": membership_id,
        "username": username,
        "key_size": key_size,
        "cert_serial": cert_serial,
    }
    with open(_meta_path(election_id, membership_id), "w", encoding="utf-8") as fh:
        json.dump(meta, fh, indent=2)

def load_private_key_bytes(election_id, membership_id) -> bytes:
    path = _private_key_path(election_id, membership_id)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"No private key found for {membership_id} in election {election_id}.\n"
            f"Expected at: {path}\nPlease register first."
        )
    with open(path, "rb") as fh:
        return fh.read()

def load_certificate_bytes(election_id, membership_id) -> bytes:
    path = _cert_path(election_id, membership_id)
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"No certificate found for {membership_id} in election {election_id}.\n"
            f"Expected at: {path}\nPlease register first."
        )
    with open(path, "rb") as fh:
        return fh.read()

def load_meta(election_id, membership_id) -> dict:
    path = _meta_path(election_id, membership_id)
    if not os.path.exists(path):
        raise FileNotFoundError(f"No meta file found at: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)

def delete_voter_credentials(election_id, membership_id) -> None:
    voter_dir = get_voter_dir(election_id, membership_id)
    if os.path.isdir(voter_dir):
        shutil.rmtree(voter_dir, ignore_errors=True)

def credentials_exist(election_id, membership_id) -> bool:
    return (
        os.path.exists(_private_key_path(election_id, membership_id))
        and os.path.exists(_cert_path(election_id, membership_id))
        and os.path.exists(_meta_path(election_id, membership_id))
    )
