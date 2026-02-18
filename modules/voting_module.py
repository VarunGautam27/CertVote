"""
voting_module.py  —  Registration and voting workflows for CertVote.
"""

import csv
import json
import os
import secrets
import traceback

from modules import crypto_utils, ca_module, db, storage
from modules.paths import CONFIG_PATH, MEMBERS_CSV, CANDIDATES_CSV


def _load_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


# ── CSV Utilities ────────────────────────────────────────────────────

def load_members_csv(csv_path: str = None) -> list:
    path = csv_path or MEMBERS_CSV
    members = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            members.append({
                "election_id":   row.get("election_id", "").strip(),
                "membership_id": row["membership_id"].strip(),
                "student_id":    row["student_id"].strip(),
                "username":      row["username"].strip(),
                "status":        row["status"].strip(),
            })
    return members


def get_active_members(csv_path: str = None) -> list:
    return [m for m in load_members_csv(csv_path) if m["status"] == "ACTIVE"]


def get_candidates(candidates_path: str = None) -> list:
    path = candidates_path or CANDIDATES_CSV
    candidates = []
    with open(path, newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            candidates.append({
                "election_id":  row.get("election_id", "").strip(),
                "candidate_id": row.get("candidate_id", "").strip(),
                "name":         row["name"].strip(),
                "roll_number":  row.get("roll_number", "").strip(),
                "position":     row.get("position", "").strip(),
            })
    return candidates

def get_candidate_names(candidates_path: str = None) -> list:
    """Return just the candidate names for display."""
    return [c["name"] for c in get_candidates(candidates_path)]


# ── Eligibility Verification ─────────────────────────────────────────

def check_eligibility(membership_id, student_id, username, election_id, log_fn=None) -> dict:
    def _log(msg):
        if log_fn: log_fn(msg)

    try:
        members = load_members_csv()
    except FileNotFoundError:
        return {"eligible": False, "reason": f"Members CSV not found at: {MEMBERS_CSV}", "member_record": None}

    record = next((m for m in members if m["membership_id"] == membership_id), None)

    if record is None:
        _log(f"Eligibility FAIL: '{membership_id}' not in CSV.")
        return {"eligible": False, "reason": f"Membership ID '{membership_id}' not found.", "member_record": None}

    if record["student_id"] != student_id:
        _log(f"Eligibility FAIL: student_id mismatch.")
        return {"eligible": False, "reason": "Student ID does not match records.", "member_record": None}

    if record["username"] != username:
        _log(f"Eligibility FAIL: username mismatch.")
        return {"eligible": False, "reason": "Username does not match records.", "member_record": None}

    if record["status"] != "ACTIVE":
        _log(f"Eligibility FAIL: status='{record['status']}'")
        return {"eligible": False, "reason": f"Membership status is '{record['status']}'. Only ACTIVE members may vote.", "member_record": None}

    try:
        if db.has_certificate(election_id, membership_id):
            _log(f"Eligibility FAIL: cert already issued for {membership_id}.")
            return {"eligible": False, "reason": "A certificate has already been issued for this membership ID.", "member_record": None}
    except RuntimeError as exc:
        _log(f"DB error: {exc}")
        return {"eligible": False, "reason": f"Database error: {exc}", "member_record": None}

    _log(f"Eligibility PASS for {membership_id} ({username}).")
    return {"eligible": True, "reason": "Eligible.", "member_record": record}


# ── Registration Workflow ─────────────────────────────────────────────

def register_voter(election_id, membership_id, student_id, username, pin, log_fn=None) -> dict:
    def _log(msg):
        if log_fn: log_fn(msg)

    cfg = _load_config()
    key_bits = cfg["key_bits"]
    files_written = False

    if not ca_module.ca_exists():
        return {"success": False, "message": "CA is not initialised. Please initialise the CA first (CA/Admin tab)."}

    _log("Checking eligibility ...")
    eligibility = check_eligibility(membership_id, student_id, username, election_id, log_fn)
    if not eligibility["eligible"]:
        return {"success": False, "message": eligibility["reason"]}

    try:
        _log(f"Generating RSA-{key_bits} key pair ...")
        private_key, public_key = crypto_utils.generate_rsa_keypair(key_bits)
        _log(f"Key pair generated. {crypto_utils.describe_key(private_key)}")

        _log("Encrypting private key with PIN ...")
        encrypted_pem = crypto_utils.serialize_private_key_encrypted(private_key, pin)

        _log("Saving encrypted private key to AppData ...")
        storage.save_private_key(election_id, membership_id, encrypted_pem)
        files_written = True

        _log("Requesting certificate from CA ...")
        cert_pem, cert_serial = ca_module.issue_voter_certificate(
            public_key, election_id, membership_id, log_fn
        )

        _log("Saving voter certificate to AppData ...")
        storage.save_certificate(election_id, membership_id, cert_pem)

        storage.save_meta(
            election_id=election_id,
            membership_id=membership_id,
            username=username,
            key_size=key_bits,
            cert_serial=cert_serial,
        )
        voter_dir = storage.get_voter_dir(election_id, membership_id)
        _log(f"Credentials saved to: {voter_dir}")

        _log("Recording issued certificate in database ...")
        db.insert_issued_certificate(election_id, membership_id, cert_serial)

        _log("=" * 50)
        _log(f"Registration COMPLETE for {membership_id} ({username})")
        _log(f"Certificate Serial: {cert_serial}")
        _log(f"Key Size: RSA-{key_bits}")
        _log("=" * 50)

        return {
            "success": True,
            "message": f"Registration successful. Certificate serial: {cert_serial}",
            "cert_serial": cert_serial,
            "voter_dir": voter_dir,
        }

    except Exception as exc:
        err_detail = traceback.format_exc()
        _log(f"Registration FAILED: {exc}")
        _log(err_detail)
        if files_written:
            _log(f"Cleaning up key files for {membership_id} ...")
            storage.delete_voter_credentials(election_id, membership_id)
        return {"success": False, "message": f"{exc}\n\nCheck the log for full details."}


# ── Voting Workflow ───────────────────────────────────────────────────

def cast_vote(election_id, membership_id, pin, choice, log_fn=None) -> dict:
    def _log(msg):
        if log_fn: log_fn(msg)

    cfg = _load_config()
    server_salt = cfg["server_salt"]

    try:
        _log("Loading encrypted private key from AppData ...")
        encrypted_pem = storage.load_private_key_bytes(election_id, membership_id)

        _log("Decrypting private key with PIN ...")
        private_key = crypto_utils.deserialize_private_key_encrypted(encrypted_pem, pin)
        _log(f"Private key loaded. {crypto_utils.describe_key(private_key)}")

        _log("Loading voter certificate ...")
        cert_pem = storage.load_certificate_bytes(election_id, membership_id)
        meta = storage.load_meta(election_id, membership_id)
        cert_serial = meta["cert_serial"]
        _log(f"Certificate serial: {cert_serial}")

        _log("Verifying voter certificate ...")
        cert_result = ca_module.verify_voter_certificate(cert_pem, election_id, log_fn)
        if not cert_result["valid"]:
            return {"success": False, "message": f"Certificate verification failed: {cert_result['message']}"}
        _log("Certificate verification PASS ✓")

        nonce = secrets.token_hex(16)
        payload = crypto_utils.build_vote_payload(election_id, choice, nonce)
        _log(f"Vote payload built. Nonce: {nonce}")
        _log(f"Candidate: {choice}")

        _log("Signing vote payload with private key ...")
        signature = crypto_utils.sign_payload(private_key, payload)
        _log(f"Signature generated ({len(signature)} bytes).")

        voter_pub_key = cert_result["voter_public_key"]
        sig_valid = crypto_utils.verify_signature(voter_pub_key, payload, signature)
        if not sig_valid:
            return {"success": False, "message": "INTERNAL ERROR: Self-signature verification failed."}
        _log("Signature verification PASS ✓")

        used_tag = crypto_utils.compute_used_tag(cert_serial, election_id)
        _log(f"Used tag computed (anonymised): {used_tag[:20]}...")

        if db.has_voted(used_tag):
            _log("DOUBLE VOTE DETECTED.")
            return {"success": False, "message": "You have already voted in this election. Each voter may only vote once."}

        _log("Recording used credential ...")
        db.insert_used_credential(election_id, used_tag)

        vote_hash = crypto_utils.hash_payload(payload)
        receipt_hash = crypto_utils.compute_receipt_hash(vote_hash, server_salt, nonce)
        _log("Recording anonymous vote ...")
        db.insert_anonymous_vote(election_id, choice, receipt_hash)

        _log("=" * 50)
        _log(f"Vote CAST successfully for: {choice}")
        _log(f"Vote hash    : {vote_hash}")
        _log(f"Receipt hash : {receipt_hash}")
        _log("Keep your receipt hash to verify your vote was counted.")
        _log("=" * 50)

        return {
            "success": True,
            "message": f"Vote cast successfully for '{choice}'.",
            "receipt_hash": receipt_hash,
            "vote_hash": vote_hash,
            "nonce": nonce,
        }

    except FileNotFoundError as exc:
        return {"success": False, "message": str(exc)}
    except ValueError as exc:
        return {"success": False, "message": f"Decryption error: {exc}"}
    except Exception as exc:
        _log(f"Vote casting FAILED: {exc}")
        _log(traceback.format_exc())
        return {"success": False, "message": str(exc)}


# ── Tamper Test ───────────────────────────────────────────────────────

def tamper_test(election_id, membership_id, pin, choice, log_fn=None) -> dict:
    def _log(msg):
        if log_fn: log_fn(msg)

    try:
        encrypted_pem = storage.load_private_key_bytes(election_id, membership_id)
        private_key = crypto_utils.deserialize_private_key_encrypted(encrypted_pem, pin)
        cert_pem = storage.load_certificate_bytes(election_id, membership_id)
        cert_result = ca_module.verify_voter_certificate(cert_pem, election_id, log_fn)
        if not cert_result["valid"]:
            return {"success": False, "message": "Certificate invalid. Cannot run tamper test."}

        voter_pub_key = cert_result["voter_public_key"]
        nonce = secrets.token_hex(16)
        original_payload = crypto_utils.build_vote_payload(election_id, choice, nonce)
        signature = crypto_utils.sign_payload(private_key, original_payload)
        original_valid = crypto_utils.verify_signature(voter_pub_key, original_payload, signature)

        _log(f"ORIGINAL payload choice: '{choice}'")
        _log(f"Signature on ORIGINAL: {'PASS' if original_valid else 'FAIL'}")

        candidates = get_candidate_names()
        tampered_choice = next((c for c in candidates if c != choice), "TAMPERED_CANDIDATE")
        tampered_payload = dict(original_payload)
        tampered_payload["choice"] = tampered_choice

        tampered_valid = crypto_utils.verify_signature(voter_pub_key, tampered_payload, signature)
        _log(f"TAMPERED payload choice: '{tampered_choice}'")
        _log(f"Signature on TAMPERED: {'PASS' if tampered_valid else 'FAIL (Expected)'}")

        if not tampered_valid:
            _log("SECURITY DEMONSTRATION: Tampering detected! Signature is INVALID.")

        return {
            "success": True,
            "original_choice": choice,
            "tampered_choice": tampered_choice,
            "original_sig_valid": original_valid,
            "tampered_sig_valid": tampered_valid,
            "message": "Tamper test complete.",
        }

    except Exception as exc:
        return {"success": False, "message": str(exc)}
