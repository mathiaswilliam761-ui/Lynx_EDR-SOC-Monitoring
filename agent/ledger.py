#!/usr/bin/env python3
"""
Lynx shared foundation: config loading, logging, and the chain-of-custody ledger.

The ledger is a SQLite database that records every alert, file-version, and block
action with a SHA-256 hash, forming a tamper-evident chain of custody.
"""

from __future__ import annotations

import json
import os
import sqlite3
import hashlib
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

INSTALL_DIR = os.environ.get(
    "LYNX_DIR",
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
CONFIG_PATH = os.path.join(INSTALL_DIR, "configs", "agent.yaml")


def load_config() -> dict:
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def setup_logging(level: str = "INFO"):
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    return logging.getLogger("lynx")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: str) -> str:
    """Streamed SHA-256 (handles large files)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def sha256_text(data: str) -> str:
    return hashlib.sha256(data.encode()).hexdigest()


class Ledger:
    """Chain-of-custody SQLite ledger."""

    def __init__(self, db_path: str):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self):
        c = self.conn.cursor()
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,     -- alert | file_change | process | network | block | backup
                severity TEXT,
                source TEXT,                  -- module name
                detail TEXT,                  -- JSON payload
                hash TEXT                     -- SHA-256 of `detail` (tamper-evidence)
            );

            CREATE TABLE IF NOT EXISTS chain_custody (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                artifact_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER,
                custodian TEXT DEFAULT 'lynx-agent'
            );

            CREATE TABLE IF NOT EXISTS blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT,
                mac TEXT,
                reason TEXT,
                backend TEXT,
                active INTEGER DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS file_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                orig_path TEXT NOT NULL,
                version_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                event TEXT                -- created | modified | deleted
            );
            """
        )
        self.conn.commit()

    def record(self, event_type: str, detail, severity: str = "info",
               source: str = "agent") -> int:
        """Record an event. `detail` is any JSON-serializable structure."""
        detail_json = json.dumps(detail, default=str, sort_keys=True)
        h = sha256_text(detail_json)
        ts = now_iso()
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO events (ts, event_type, severity, source, detail, hash) "
            "VALUES (?,?,?,?,?,?)",
            (ts, event_type, severity, source, detail_json, h),
        )
        self.conn.commit()
        return c.lastrowid

    def record_artifact(self, path: str, size: int | None = None):
        """Add a hashed artifact to the chain-of-custody table."""
        sha = sha256_file(path)
        size = size if size is not None else os.path.getsize(path)
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO chain_custody (ts, artifact_path, sha256, size_bytes) "
            "VALUES (?,?,?,?)",
            (now_iso(), path, sha, size),
        )
        self.conn.commit()
        return sha

    def record_block(self, ip: str | None, mac: str | None, reason: str,
                     backend: str) -> int:
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO blocks (ts, ip, mac, reason, backend) VALUES (?,?,?,?,?)",
            (now_iso(), ip, mac, reason, backend),
        )
        self.conn.commit()
        return c.lastrowid

    def record_version(self, orig: str, version: str, event: str) -> str:
        sha = sha256_file(version)
        c = self.conn.cursor()
        c.execute(
            "INSERT INTO file_versions (ts, orig_path, version_path, sha256, event) "
            "VALUES (?,?,?,?,?)",
            (now_iso(), orig, version, sha, event),
        )
        self.conn.commit()
        return sha

    def query(self, sql: str, params=()):
        c = self.conn.cursor()
        c.execute(sql, params)
        return c.fetchall()

    def close(self):
        self.conn.close()