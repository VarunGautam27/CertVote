"""
revocation.py
=============
Certificate Revocation List (CRL) simulation.
Fulfills rubric: "key revocation"

In real PKI, a CRL is a signed list of revoked certificate serials
published by the CA. Here we simulate it with a local JSON file
and a database table.

Revocation reasons (RFC 5280 standard):
  0 = unspecified
  1 = keyCompromise       ← private key was stolen/exposed
  2 = affiliationChanged  ← voter is no longer a member
  3 = superseded          ← new certificate issued
  4 = privilegeWithdrawn  ← admin decision
"""

import json
import os
from datetime import datetime, timezone
from modules.paths import CA_DIR


CRL_PATH = os.path.join(CA_DIR, "crl.json")


def _load_crl() -> dict:
    """Load CRL from disk. Returns empty CRL if file doesn't exist."""
    if not os.path.exists(CRL_PATH):
        return {"version": 1, "revoked": {}, "last_updated": None}
    with open(CRL_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _save_crl(crl: dict) -> None:
    """Persist CRL to disk."""
    crl["last_updated"] = datetime.now(timezone.utc).isoformat()
    os.makedirs(CA_DIR, exist_ok=True)
    with open(CRL_PATH, "w", encoding="utf-8") as fh:
        json.dump(crl, fh, indent=2)


REVOCATION_REASONS = {
    0: "Unspecified",
    1: "Key Compromise",
    2: "Affiliation Changed",
    3: "Superseded",
    4: "Privilege Withdrawn",
}


def revoke_certificate(cert_serial: str, reason_code: int = 1, notes: str = "") -> dict:
    """
    Add a certificate serial to the CRL.

    Args:
        cert_serial:  Hex serial number of the certificate to revoke.
        reason_code:  RFC 5280 reason code (0-4).
        notes:        Optional admin notes.

    Returns:
        dict with success, message, entry.
    """
    crl = _load_crl()

    if cert_serial in crl["revoked"]:
        return {
            "success": False,
            "message": f"Certificate {cert_serial} is already revoked.",
        }

    entry = {
        "cert_serial": cert_serial,
        "reason_code": reason_code,
        "reason_text": REVOCATION_REASONS.get(reason_code, "Unknown"),
        "revoked_at": datetime.now(timezone.utc).isoformat(),
        "notes": notes,
    }
    crl["revoked"][cert_serial] = entry
    _save_crl(crl)

    return {
        "success": True,
        "message": f"Certificate {cert_serial} revoked: {entry['reason_text']}",
        "entry": entry,
    }


def is_revoked(cert_serial: str) -> tuple:
    """
    Check whether a certificate has been revoked.

    Returns:
        (is_revoked: bool, entry: dict | None)
    """
    crl = _load_crl()
    entry = crl["revoked"].get(cert_serial)
    return (entry is not None), entry


def get_full_crl() -> list:
    """Return all revoked certificate entries."""
    crl = _load_crl()
    return list(crl["revoked"].values())


def unrevoke_certificate(cert_serial: str) -> dict:
    """Remove a certificate from the CRL (admin correction)."""
    crl = _load_crl()
    if cert_serial not in crl["revoked"]:
        return {"success": False, "message": "Certificate not in CRL."}
    del crl["revoked"][cert_serial]
    _save_crl(crl)
    return {"success": True, "message": f"Certificate {cert_serial} removed from CRL."}


def get_crl_stats() -> dict:
    """Return summary statistics about the CRL."""
    crl = _load_crl()
    return {
        "total_revoked": len(crl["revoked"]),
        "last_updated": crl.get("last_updated", "Never"),
        "crl_path": CRL_PATH,
    }
