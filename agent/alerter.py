#!/usr/bin/env python3
"""Alerting — writes alerts to a local JSONL file and optionally a webhook/Telegram."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from urllib import request


class Alerter:
    def __init__(self, cfg: dict, install_dir: str, logger):
        self.cfg = cfg.get("alerting", {})
        self.log = logger
        self.local_file = os.path.join(install_dir, self.cfg.get("local_file",
                                                                "logs/alerts.json"))
        os.makedirs(os.path.dirname(self.local_file), exist_ok=True)
        self.webhook = self.cfg.get("webhook_url", "")
        self.tg = self.cfg.get("telegram", {}) or {}

    def alert(self, event: dict):
        """Persist + optionally forward a single alert."""
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            **event,
        }
        with open(self.local_file, "a") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        if self.webhook:
            self._webhook(rec)
        if self.tg.get("bot_token") and self.tg.get("chat_id"):
            self._telegram(rec)

    def _webhook(self, rec):
        try:
            data = json.dumps(rec).encode()
            req = request.Request(self.webhook, data=data,
                                  headers={"Content-Type": "application/json"})
            request.urlopen(req, timeout=5)
        except Exception as e:
            self.log.warning("webhook failed: %s", e)

    def _telegram(self, rec):
        token = self.tg["bot_token"]
        chat = self.tg["chat_id"]
        text = f"🚨 Lynx alert: {rec.get('type')} — {rec.get('reason', rec.get('rule', ''))}"
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        try:
            data = json.dumps({"chat_id": chat, "text": text}).encode()
            req = request.Request(url, data=data,
                                  headers={"Content-Type": "application/json"})
            request.urlopen(req, timeout=5)
        except Exception as e:
            self.log.warning("telegram failed: %s", e)