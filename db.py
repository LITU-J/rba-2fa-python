"""
db.py — SQLite database schema and connection helpers.
"""

import os
import sqlite3
from flask import g

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "app.sqlite")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT UNIQUE NOT NULL,
    email           TEXT UNIQUE NOT NULL,
    phone           TEXT,
    password_hash   TEXT NOT NULL,
    totp_secret     TEXT,
    totp_enabled    INTEGER DEFAULT 0,
    created_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS known_devices (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_hash  TEXT NOT NULL,
    first_seen   TEXT DEFAULT (datetime('now')),
    last_seen    TEXT DEFAULT (datetime('now')),
    UNIQUE(user_id, device_hash)
);

CREATE TABLE IF NOT EXISTS login_logs (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id               INTEGER REFERENCES users(id) ON DELETE CASCADE,
    username_attempted    TEXT,
    timestamp             TEXT DEFAULT (datetime('now')),
    ip                    TEXT,
    country               TEXT,
    region                TEXT,
    city                  TEXT,
    lat                   REAL,
    lon                   REAL,
    isp                   TEXT,
    timezone              TEXT,
    device_hash           TEXT,
    risk_score            INTEGER,
    risk_tier             TEXT,
    risk_reasons          TEXT,
    required_factors      TEXT,
    outcome               TEXT,
    simulated_attack_type TEXT
);

CREATE TABLE IF NOT EXISTS pending_challenges (
    token              TEXT PRIMARY KEY,
    user_id            INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    required_factors   TEXT NOT NULL,
    satisfied_factors  TEXT NOT NULL DEFAULT '[]',
    email_otp_hash     TEXT,
    email_otp_expires  TEXT,
    sms_otp_hash       TEXT,
    sms_otp_expires    TEXT,
    ip TEXT, country TEXT, region TEXT, city TEXT,
    lat REAL, lon REAL, isp TEXT, timezone TEXT,
    device_hash        TEXT,
    risk_score         INTEGER,
    risk_tier          TEXT,
    risk_reasons       TEXT,
    created_at         TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sus_responses (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER,
    participant     TEXT,
    answers         TEXT NOT NULL,
    raw_score       REAL NOT NULL,
    total_score     REAL NOT NULL,
    suggestions     TEXT,
    submitted_at    TEXT DEFAULT (datetime('now'))
);
"""


def get_db():
    if "db" not in g:
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db(app):
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()
    app.teardown_appcontext(close_db)