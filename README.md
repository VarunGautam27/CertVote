# ITClubVote — PKI-Powered Electronic Voting System

> A complete Public Key Infrastructure (PKI) demonstration system built in Python.
> Implements digital signatures, hybrid encryption, certificate management, revocation,
> attack simulations, and unit tests — covering all five rubric categories.

---

## Why Public Key / Private Key / PIN — The Core Explanation

### RSA Key Pair

RSA generates two mathematically linked keys:

    PRIVATE KEY  — kept secret, used to SIGN or DECRYPT
    PUBLIC KEY   — shared openly, used to VERIFY signatures or ENCRYPT

The keys are a matched pair. You cannot derive the private key from the public key
(that would require factoring a 2048-bit number — computationally infeasible).

### Where Each Key Is Used

    REGISTRATION:
      generate_rsa_keypair() → (private_key, public_key)
      public_key  → embedded into X.509 certificate, signed by CA
      private_key → encrypted with your PIN (AES-256), saved to AppData

    VOTING:
      private_key → SIGNS the vote payload   (proves you wrote it)
      public_key  → VERIFIES the signature   (proves nobody tampered)

    HYBRID ENCRYPTION DEMO:
      public_key  → ENCRYPTS the AES session key  (only you can decrypt)
      private_key → DECRYPTS the AES session key  (uses your RSA identity)

### Why the PIN?

The PIN is NOT a system password. It is the AES-256 encryption passphrase
that protects your private key file on disk.

    PROBLEM:  Storing private_key.pem in plain text = anyone with file access can steal it
    SOLUTION: Encrypt it with PIN using AES-256-CBC (PKCS#8 standard format)

    Registration:  PIN ──AES-256──► encrypts private_key.pem ► private_key.pem.enc
    Voting:        PIN ──AES-256──► decrypts private_key.pem.enc ► RSA private key

The PIN is NEVER stored anywhere. It only lives in RAM for the fraction of a second
needed to decrypt the key. This is exactly how macOS Keychain, Windows Certificate
Store, and PKCS#12 (.pfx) files protect private keys.

---

## Why Admin and Voter Are Separate Windows

In real PKI, the Certificate Authority and end-users are completely separate entities.
Mixing them in one interface violates the Principle of Least Privilege.

    BAD (single window):  Admin CA controls visible and accessible to voters
    GOOD (separate):      Admin Portal (orange) — CA, certs, revocation, attack demos
                          Voter Portal (blue)   — register, vote, tally, encryption demo

Benefits: role separation, audit isolation, mirrors real PKI architecture,
principle of least privilege, professional presentation.

---

## Rubric Coverage

### 1. Core Cryptographic Features

| Requirement | Implementation | File |
|---|---|---|
| Generate/store key pairs | RSA-2048, AES-256 PKCS#8 | crypto_utils.py, storage.py |
| Issue digital certificates | X.509 v3, CA-signed | ca_module.py |
| Validate certificates | CA chain + election ID + expiry | ca_module.py |
| Key revocation | CRL (ca/crl.json) | revocation.py |
| Sign messages | RSA-PSS + SHA-256 | crypto_utils.py |
| Verify signatures | Public key verification | crypto_utils.py |
| Hybrid encryption | AES-256-GCM + RSA-OAEP | hybrid_crypto.py |

### 2. Security Best Practices

| Requirement | Implementation | File |
|---|---|---|
| PKCS#12 keystore | Full export/import | pkcs12_store.py |
| Password-protected keys | AES-256 per voter | storage.py |
| MITM prevention | RSA-PSS signature | attack_demos.py |
| Replay attack prevention | Nonce + DB used_tag | attack_demos.py |
| Signature forgery prevention | CA cert chain | attack_demos.py |
| Certificate forgery prevention | CA signature check | attack_demos.py |

### 3. Open-Source Best Practices

| Requirement | Implementation |
|---|---|
| Code comments | Docstring in every function explaining WHY |
| Unit tests | tests/test_crypto.py — 30+ tests, 9 classes |
| Test runner | python -m pytest tests/ -v |
| Dependencies | requirements.txt |
| Diagnostics | diagnose.py |
| Documentation | This README |

### 4. Use Case Demonstrations

Three real-world use cases documented in detail — see section below.

### 5. Testing and Validation

9 test classes covering: RSA keygen, PIN encryption, SHA-256, vote payload,
digital signatures (sign/verify/tamper/wrong-key), receipt hash, used tag,
hybrid encryption, and certificate revocation.

---

## Architecture

    ITClubVote/
    ├── app.py                    GUI: EntryScreen + AdminPortal + VoterPortal
    ├── modules/
    │   ├── crypto_utils.py       RSA, PSS signing, SHA-256, receipts
    │   ├── ca_module.py          CA init, X.509 issuance, verification
    │   ├── hybrid_crypto.py      AES-256-GCM + RSA-OAEP hybrid encryption
    │   ├── revocation.py         Certificate Revocation List
    │   ├── pkcs12_store.py       PKCS#12 keystore export/import
    │   ├── attack_demos.py       Replay/MITM/Forgery simulations
    │   ├── voting_module.py      Registration + voting workflows
    │   ├── db.py                 MySQL operations
    │   ├── storage.py            AppData file I/O
    │   └── paths.py              Absolute path resolution
    ├── tests/
    │   └── test_crypto.py        Unit tests (pytest-compatible)
    ├── data/                     Members CSV, candidates CSV
    ├── ca/                       CA keys + CRL (created at runtime)
    ├── sql/schema.sql            3-table anonymity database design
    └── config.json               DB credentials, election settings

### Database Anonymity Design

    Table 1: issued_certificates  — "Did this member register?"     (has identity)
    Table 2: used_credentials     — "Did this cert vote?"           (NO identity — only SHA-256 hash)
    Table 3: anonymous_votes      — "What are the results?"         (NO identity whatsoever)

    used_tag = SHA256(cert_serial + "|" + election_id)
    Cannot be reversed to find membership_id — anonymity guaranteed by design.

---

## Three Real-World Use Cases

### Use Case 1 — Student Union Elections

Problem: Traditional polls cannot prove eligibility, prevent double-voting, or
guarantee anonymity while still being verifiable.

Solution:
- X.509 certificates issued only to CSV-verified ACTIVE members (eligibility)
- RSA-PSS signature on every vote (integrity — cannot be changed)
- SHA-256 used_tag blocks double voting (uniqueness)
- anonymous_votes table has zero identity columns (anonymity)
- SHA-256 receipt hash lets voter verify their vote was counted (verifiability)

### Use Case 2 — Secure Document Signing

Problem: A department needs to sign official documents with proof of authorship
and integrity, verifiable by anyone without access to secrets.

Solution: The signing workflow in crypto_utils.py can be applied to any document:
- sign_payload(private_key, document) → signature
- verify_signature(public_key, document, signature) → True/False
The signer's public key is in their CA-signed certificate. Anyone can verify.
This mirrors how DocuSign, Adobe Sign, and eIDAS qualified signatures work.

### Use Case 3 — Encrypted Confidential Messaging

Problem: Two parties need to exchange sensitive information where only the
intended recipient can read it, and interception reveals nothing.

Solution: Hybrid encryption (Voter Portal → Hybrid Encryption Demo tab):
1. Random AES-256-GCM session key generated per message
2. Message encrypted with AES-256-GCM (authenticated, fast)
3. Session key encrypted with recipient's RSA PUBLIC KEY (OAEP)
4. Recipient uses their RSA PRIVATE KEY to recover session key
5. AES-GCM tag verifies the message was not tampered in transit
This is the exact mechanism used by TLS, PGP, Signal, and WhatsApp.

---

## Attack Simulations (Admin Portal → Attack Demos)

| Attack | Method | Defense | Result |
|---|---|---|---|
| Replay Attack | Resubmit captured signed vote | used_tag DB uniqueness | BLOCKED |
| MITM Tampering | Change candidate in transit | RSA-PSS signature invalidated | BLOCKED |
| Signature Forgery | Sign with attacker's own key | CA cert public key mismatch | BLOCKED |
| Certificate Forgery | Self-signed certificate | CA chain signature check fails | BLOCKED |

---

## Setup

    # 1. Start MySQL (XAMPP → Start MySQL)
    # 2. Create tables
    mysql -u root -p < sql/schema.sql
    # 3. Set MySQL password in config.json
    # 4. Run diagnostic
    python diagnose.py
    # 5. Launch
    python app.py

### Demo Voters

    ITC001 / STU2026001 / alice_k    / PIN: 1234
    ITC002 / STU2026002 / bob_rai    / PIN: 5678
    ITC003 / STU2026003 / carol_bist / PIN: 9999
    ITC004 / STU2026004 / david_pant / PIN: 4321

---

## Running Tests

    python -m pytest tests/ -v          # using pytest
    python tests/test_crypto.py         # direct run
    # Or: Admin Portal → Run Tests tab

---

## Academic Limitations vs. Production

| This System | Production Equivalent |
|---|---|
| CA key plain text | HSM (Hardware Security Module) |
| PIN-based key protection | Smart card / hardware token |
| Local CRL JSON | OCSP (Online Certificate Status Protocol) |
| Single CA | Root → Intermediate → Leaf CA hierarchy |
| SHA-256 used_tag | Zero-knowledge proof |

These limitations are appropriate for an academic project. Every algorithm used
(RSA-2048, AES-256-GCM, SHA-256, X.509 v3) is production-grade.

---

## License

MIT License — free to use, modify, and distribute with attribution.
