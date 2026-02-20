"""
db.py  —  Database access layer for CertVote.
All MySQL interactions centralised here.
"""

import json
import mysql.connector
from mysql.connector import Error as MySQLError
from modules.paths import CONFIG_PATH


def _load_db_config() -> dict:
    with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)["db"]


def get_connection():
    cfg = _load_db_config()
    try:
        conn = mysql.connector.connect(
            host=cfg["host"],
            port=int(cfg["port"]),
            user=cfg["user"],
            password=cfg["password"],
            database=cfg["database"],
            autocommit=False,
            charset="utf8mb4",
            collation="utf8mb4_unicode_ci",
        )
        return conn
    except MySQLError as exc:
        raise RuntimeError(f"Database connection failed: {exc}") from exc


def test_connection() -> bool:
    try:
        conn = get_connection()
        conn.close()
        return True
    except RuntimeError:
        return False


# ── issued_certificates ─────────────────────────────────────────────

def has_certificate(election_id: str, membership_id: str) -> bool:
    sql = ("SELECT id FROM issued_certificates "
           "WHERE election_id=%s AND membership_id=%s LIMIT 1")
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, (election_id, membership_id))
        return cur.fetchone() is not None
    finally:
        conn.close()


def insert_issued_certificate(election_id: str, membership_id: str, cert_serial: str) -> None:
    sql = ("INSERT INTO issued_certificates (election_id, membership_id, cert_serial) "
           "VALUES (%s, %s, %s)")
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, (election_id, membership_id, cert_serial))
        conn.commit()
    except MySQLError as exc:
        conn.rollback()
        raise RuntimeError(f"Failed to record certificate: {exc}") from exc
    finally:
        conn.close()


def get_all_issued_certificates(election_id: str) -> list:
    sql = ("SELECT id, election_id, membership_id, cert_serial, issued_at "
           "FROM issued_certificates WHERE election_id=%s ORDER BY issued_at DESC")
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, (election_id,))
        return cur.fetchall()
    finally:
        conn.close()


# ── used_credentials ────────────────────────────────────────────────

def has_voted(used_tag: str) -> bool:
    sql = "SELECT id FROM used_credentials WHERE used_tag=%s LIMIT 1"
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, (used_tag,))
        return cur.fetchone() is not None
    finally:
        conn.close()


def insert_used_credential(election_id: str, used_tag: str) -> None:
    sql = "INSERT INTO used_credentials (election_id, used_tag) VALUES (%s, %s)"
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, (election_id, used_tag))
        conn.commit()
    except MySQLError as exc:
        conn.rollback()
        raise RuntimeError(f"Failed to record used credential: {exc}") from exc
    finally:
        conn.close()


# ── anonymous_votes ─────────────────────────────────────────────────

def insert_anonymous_vote(election_id: str, choice: str, receipt_hash: str) -> None:
    sql = ("INSERT INTO anonymous_votes (election_id, choice, receipt_hash) "
           "VALUES (%s, %s, %s)")
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, (election_id, choice, receipt_hash))
        conn.commit()
    except MySQLError as exc:
        conn.rollback()
        raise RuntimeError(f"Failed to record vote: {exc}") from exc
    finally:
        conn.close()


def get_vote_tally(election_id: str) -> list:
    sql = ("SELECT choice, COUNT(*) AS total_votes FROM anonymous_votes "
           "WHERE election_id=%s GROUP BY choice ORDER BY total_votes DESC")
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, (election_id,))
        return cur.fetchall()
    finally:
        conn.close()


def get_receipt_hashes(election_id: str) -> list:
    sql = ("SELECT receipt_hash, created_at FROM anonymous_votes "
           "WHERE election_id=%s ORDER BY created_at ASC")
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql, (election_id,))
        return cur.fetchall()
    finally:
        conn.close()


def verify_receipt_exists(election_id: str, receipt_hash: str) -> bool:
    sql = ("SELECT id FROM anonymous_votes "
           "WHERE election_id=%s AND receipt_hash=%s LIMIT 1")
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, (election_id, receipt_hash))
        return cur.fetchone() is not None
    finally:
        conn.close()


# ── Cross-election queries (for tally board & admin — all election IDs) ─

def get_all_issued_certificates_all() -> list:
    """Return all issued certificates across all election IDs."""
    sql = ("SELECT id, election_id, membership_id, cert_serial, issued_at "
           "FROM issued_certificates ORDER BY issued_at DESC")
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql)
        return cur.fetchall()
    finally:
        conn.close()


def get_vote_tally_all() -> list:
    """Tally votes across ALL election IDs (since each voter has unique election ID)."""
    sql = ("SELECT choice, COUNT(*) AS total_votes FROM anonymous_votes "
           "GROUP BY choice ORDER BY total_votes DESC")
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql)
        return cur.fetchall()
    finally:
        conn.close()


def get_receipt_hashes_all() -> list:
    """Return all receipt hashes across all election IDs."""
    sql = ("SELECT receipt_hash, created_at FROM anonymous_votes "
           "ORDER BY created_at ASC")
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(sql)
        return cur.fetchall()
    finally:
        conn.close()


def verify_receipt_exists_any(receipt_hash: str) -> bool:
    """Check if a receipt hash exists in ANY election."""
    sql = "SELECT id FROM anonymous_votes WHERE receipt_hash=%s LIMIT 1"
    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(sql, (receipt_hash,))
        return cur.fetchone() is not None
    finally:
        conn.close()
