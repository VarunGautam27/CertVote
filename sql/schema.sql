-- ============================================================
-- ITClubVote PKI Voting System - Database Schema
-- Election: ITC_ELEC_2026
-- ============================================================

CREATE DATABASE IF NOT EXISTS itclub_vote
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE itclub_vote;

-- ============================================================
-- Table 1: issued_certificates
-- Tracks every certificate issued by the CA.
-- Prevents a voter from registering more than once.
-- ============================================================
CREATE TABLE IF NOT EXISTS issued_certificates (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    election_id     VARCHAR(50)     NOT NULL,
    membership_id   VARCHAR(20)     NOT NULL,
    cert_serial     VARCHAR(100)    NOT NULL UNIQUE,
    issued_at       TIMESTAMP       DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_election_member (election_id, membership_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table 2: used_credentials
-- Marks that a certificate has been used to cast a vote.
-- used_tag = SHA256(cert_serial + "|" + election_id)
-- This is the anonymity firewall: no membership data stored.
-- ============================================================
CREATE TABLE IF NOT EXISTS used_credentials (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    election_id VARCHAR(50)     NOT NULL,
    used_tag    VARCHAR(255)    NOT NULL UNIQUE,
    used_at     TIMESTAMP       DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Table 3: anonymous_votes
-- Stores only the candidate choice and receipt hash.
-- NO membership_id, NO student_id, NO username stored here.
-- ============================================================
CREATE TABLE IF NOT EXISTS anonymous_votes (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    election_id  VARCHAR(50)     NOT NULL,
    choice       VARCHAR(100)    NOT NULL,
    receipt_hash VARCHAR(255)    NOT NULL UNIQUE,
    created_at   TIMESTAMP       DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- ============================================================
-- Verify structure
-- ============================================================
SHOW TABLES;
DESCRIBE issued_certificates;
DESCRIBE used_credentials;
DESCRIBE anonymous_votes;
