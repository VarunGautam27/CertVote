"""
tests/test_crypto.py
====================
Unit tests for all cryptographic components.
Fulfills rubric: "Testing and Validation"

Run with:  python -m pytest tests/ -v
       or: python tests/test_crypto.py
"""

import os, sys, json, secrets, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.crypto_utils import (
    generate_rsa_keypair, serialize_private_key_encrypted,
    deserialize_private_key_encrypted, serialize_public_key,
    deserialize_public_key, sha256_hex, sha256_of_string,
    build_vote_payload, payload_to_bytes, hash_payload,
    sign_payload, verify_signature, compute_receipt_hash,
    compute_used_tag, describe_key,
)
from modules.hybrid_crypto import (
    encrypt_message, decrypt_message,
    encrypt_message_str, decrypt_message_str,
)
from modules.revocation import (
    revoke_certificate, is_revoked, unrevoke_certificate, get_full_crl,
)


class TestRSAKeyGeneration(unittest.TestCase):
    """Test RSA key pair generation."""

    def test_key_size_2048(self):
        priv, pub = generate_rsa_keypair(2048)
        self.assertEqual(priv.key_size, 2048)
        self.assertEqual(pub.key_size, 2048)

    def test_keys_are_unique(self):
        priv1, _ = generate_rsa_keypair(2048)
        priv2, _ = generate_rsa_keypair(2048)
        n1 = priv1.public_key().public_numbers().n
        n2 = priv2.public_key().public_numbers().n
        self.assertNotEqual(n1, n2, "Two key pairs should never be identical")

    def test_public_exponent(self):
        priv, pub = generate_rsa_keypair(2048)
        self.assertEqual(pub.public_numbers().e, 65537)

    def test_describe_key(self):
        priv, _ = generate_rsa_keypair(2048)
        desc = describe_key(priv)
        self.assertIn("RSA-2048", desc)


class TestPrivateKeyEncryption(unittest.TestCase):
    """Test PIN-based private key encryption/decryption."""

    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)
        self.pin = "testpin123"

    def test_encrypt_decrypt_roundtrip(self):
        enc = serialize_private_key_encrypted(self.priv, self.pin)
        dec = deserialize_private_key_encrypted(enc, self.pin)
        self.assertEqual(
            self.priv.public_key().public_numbers().n,
            dec.public_key().public_numbers().n,
        )

    def test_wrong_pin_raises(self):
        enc = serialize_private_key_encrypted(self.priv, self.pin)
        with self.assertRaises(ValueError):
            deserialize_private_key_encrypted(enc, "wrongpin")

    def test_encrypted_pem_is_not_plain(self):
        enc = serialize_private_key_encrypted(self.priv, self.pin)
        self.assertIn(b"ENCRYPTED", enc)
        self.assertNotIn(b"BEGIN PRIVATE KEY\n", enc)

    def test_public_key_serialization(self):
        pem = serialize_public_key(self.pub)
        loaded = deserialize_public_key(pem)
        self.assertEqual(
            self.pub.public_numbers().n,
            loaded.public_numbers().n,
        )


class TestSHA256(unittest.TestCase):
    """Test SHA-256 hashing."""

    def test_known_hash(self):
        result = sha256_of_string("hello")
        self.assertEqual(
            result,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        )

    def test_empty_string(self):
        result = sha256_of_string("")
        self.assertEqual(len(result), 64)

    def test_different_inputs_differ(self):
        h1 = sha256_of_string("vote1")
        h2 = sha256_of_string("vote2")
        self.assertNotEqual(h1, h2)

    def test_deterministic(self):
        h1 = sha256_of_string("test")
        h2 = sha256_of_string("test")
        self.assertEqual(h1, h2)


class TestVotePayload(unittest.TestCase):
    """Test vote payload construction."""

    def test_payload_structure(self):
        p = build_vote_payload("ITC_ELEC_2026", "Abhisek Sharma")
        self.assertIn("election_id", p)
        self.assertIn("choice", p)
        self.assertIn("timestamp", p)
        self.assertIn("nonce", p)

    def test_nonce_is_unique(self):
        p1 = build_vote_payload("ITC_ELEC_2026", "Abhisek Sharma")
        p2 = build_vote_payload("ITC_ELEC_2026", "Abhisek Sharma")
        self.assertNotEqual(p1["nonce"], p2["nonce"])

    def test_custom_nonce(self):
        p = build_vote_payload("ITC_ELEC_2026", "Abhisek Sharma", nonce="fixed")
        self.assertEqual(p["nonce"], "fixed")

    def test_payload_bytes_deterministic(self):
        p = build_vote_payload("ITC_ELEC_2026", "Abhisek Sharma", nonce="abc")
        b1 = payload_to_bytes(p)
        b2 = payload_to_bytes(p)
        self.assertEqual(b1, b2)

    def test_hash_payload(self):
        p = build_vote_payload("ITC_ELEC_2026", "Abhisek Sharma", nonce="abc")
        h = hash_payload(p)
        self.assertEqual(len(h), 64)


class TestDigitalSignatures(unittest.TestCase):
    """
    Test RSA-PSS digital signatures.
    This is the core crypto demo — public key / private key usage.
    """

    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)
        self.payload = build_vote_payload("ITC_ELEC_2026", "Abhisek Sharma", "nonce123")

    def test_sign_and_verify(self):
        """Private key signs → public key verifies → PASS"""
        sig = sign_payload(self.priv, self.payload)
        valid = verify_signature(self.pub, self.payload, sig)
        self.assertTrue(valid, "Valid signature should verify correctly")

    def test_tampered_payload_fails(self):
        """Core security test: any change to payload breaks signature"""
        sig = sign_payload(self.priv, self.payload)
        tampered = dict(self.payload)
        tampered["choice"] = "Different Candidate"
        valid = verify_signature(self.pub, tampered, sig)
        self.assertFalse(valid, "Tampered payload MUST fail verification")

    def test_wrong_public_key_fails(self):
        """Attacker's public key cannot verify legitimate voter's signature"""
        sig = sign_payload(self.priv, self.payload)
        _, attacker_pub = generate_rsa_keypair(2048)
        valid = verify_signature(attacker_pub, self.payload, sig)
        self.assertFalse(valid, "Wrong public key MUST fail")

    def test_wrong_private_key_fails(self):
        """Attacker signing with their own key fails CA cert verification"""
        attacker_priv, _ = generate_rsa_keypair(2048)
        sig = sign_payload(attacker_priv, self.payload)
        valid = verify_signature(self.pub, self.payload, sig)
        self.assertFalse(valid, "Signature from wrong private key MUST fail")

    def test_signature_is_256_bytes(self):
        sig = sign_payload(self.priv, self.payload)
        self.assertEqual(len(sig), 256, "RSA-2048 signature must be 256 bytes")

    def test_signatures_are_probabilistic(self):
        """RSA-PSS is probabilistic — same input gives different signatures"""
        sig1 = sign_payload(self.priv, self.payload)
        sig2 = sign_payload(self.priv, self.payload)
        self.assertNotEqual(sig1, sig2, "PSS signatures should be different each time")
        # But both should verify correctly
        self.assertTrue(verify_signature(self.pub, self.payload, sig1))
        self.assertTrue(verify_signature(self.pub, self.payload, sig2))


class TestReceiptHash(unittest.TestCase):
    """Test receipt hash computation."""

    def test_receipt_deterministic(self):
        rh1 = compute_receipt_hash("votehash", "salt", "nonce")
        rh2 = compute_receipt_hash("votehash", "salt", "nonce")
        self.assertEqual(rh1, rh2)

    def test_different_nonce_different_receipt(self):
        rh1 = compute_receipt_hash("votehash", "salt", "nonce1")
        rh2 = compute_receipt_hash("votehash", "salt", "nonce2")
        self.assertNotEqual(rh1, rh2)

    def test_receipt_is_64_hex_chars(self):
        rh = compute_receipt_hash("a", "b", "c")
        self.assertEqual(len(rh), 64)


class TestUsedTag(unittest.TestCase):
    """Test anonymised double-vote tag."""

    def test_used_tag_deterministic(self):
        t1 = compute_used_tag("0xABC", "ITC_ELEC_2026")
        t2 = compute_used_tag("0xABC", "ITC_ELEC_2026")
        self.assertEqual(t1, t2)

    def test_different_serials_differ(self):
        t1 = compute_used_tag("0xABC", "ITC_ELEC_2026")
        t2 = compute_used_tag("0xDEF", "ITC_ELEC_2026")
        self.assertNotEqual(t1, t2)

    def test_different_elections_differ(self):
        t1 = compute_used_tag("0xABC", "ELEC_2026")
        t2 = compute_used_tag("0xABC", "ELEC_2027")
        self.assertNotEqual(t1, t2)


class TestHybridEncryption(unittest.TestCase):
    """
    Test hybrid encryption (AES-256-GCM + RSA-OAEP).
    Fulfills: "Encrypt/decrypt files or messages using hybrid encryption"
    """

    def setUp(self):
        self.priv, self.pub = generate_rsa_keypair(2048)

    def test_encrypt_decrypt_bytes(self):
        msg = b"Secret message for the voter"
        blob = encrypt_message(msg, self.pub)
        plain = decrypt_message(blob, self.priv)
        self.assertEqual(plain, msg)

    def test_encrypt_decrypt_string(self):
        msg = "Hello, this is a confidential message!"
        blob = encrypt_message_str(msg, self.pub)
        plain = decrypt_message_str(blob, self.priv)
        self.assertEqual(plain, msg)

    def test_wrong_private_key_fails(self):
        msg = b"Secret"
        blob = encrypt_message(msg, self.pub)
        wrong_priv, _ = generate_rsa_keypair(2048)
        with self.assertRaises(ValueError):
            decrypt_message(blob, wrong_priv)

    def test_tampered_ciphertext_fails(self):
        msg = b"Secret"
        blob = bytearray(encrypt_message(msg, self.pub))
        blob[-1] ^= 0xFF  # flip last byte
        with self.assertRaises(ValueError):
            decrypt_message(bytes(blob), self.priv)

    def test_ciphertext_differs_each_time(self):
        msg = b"Same message"
        b1 = encrypt_message(msg, self.pub)
        b2 = encrypt_message(msg, self.pub)
        self.assertNotEqual(b1, b2, "Random session key means different ciphertext")

    def test_large_message(self):
        msg = os.urandom(100_000)  # 100KB
        blob = encrypt_message(msg, self.pub)
        plain = decrypt_message(blob, self.priv)
        self.assertEqual(plain, msg)


class TestRevocation(unittest.TestCase):
    """Test certificate revocation."""

    def setUp(self):
        # Use a unique serial per test run
        self.serial = f"0x{secrets.token_hex(8)}"

    def test_revoke_and_check(self):
        result = revoke_certificate(self.serial, reason_code=1)
        self.assertTrue(result["success"])
        revoked, entry = is_revoked(self.serial)
        self.assertTrue(revoked)
        self.assertEqual(entry["reason_code"], 1)

    def test_not_revoked_initially(self):
        fresh_serial = f"0x{secrets.token_hex(8)}"
        revoked, _ = is_revoked(fresh_serial)
        self.assertFalse(revoked)

    def test_double_revoke_fails(self):
        revoke_certificate(self.serial, reason_code=1)
        result2 = revoke_certificate(self.serial, reason_code=1)
        self.assertFalse(result2["success"])

    def test_unrevoke(self):
        revoke_certificate(self.serial, reason_code=1)
        unrevoke_certificate(self.serial)
        revoked, _ = is_revoked(self.serial)
        self.assertFalse(revoked)

    def tearDown(self):
        unrevoke_certificate(self.serial)


if __name__ == "__main__":
    print("=" * 60)
    print("CertVote — Cryptographic Unit Tests")
    print("=" * 60)
    unittest.main(verbosity=2)
