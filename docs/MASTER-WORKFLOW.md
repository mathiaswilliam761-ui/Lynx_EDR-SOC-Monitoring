# Lynx EDR — Master Workflow (Deploy → Protect → Detect → Block → Recover → Report)

The complete guide to deploying the **single Linux EDR agent** on any machine and
running it as your diploma project. Everything happens on **one host** — no VMware,
no pfSense, no multi-VM topology.

**How to use:** work top-to-bottom. Each ✅ gate must pass before the next step.
⭐ marks a design decision I made for you — adopt as-is.

---

## What the agent does (recap)

| # | Capability | Module |
|---|-----------|--------|
| 1 | Monitor logs (auth/syslog/audit) | `agent/log_monitor.py` |
| 2 | File integrity (create/modify/delete) | `agent/file_integrity.py` |
| 3 | Process monitoring (suspicious names / CPU) | `agent/process_monitor.py` |
| 4 | Network IDS (connections, port scans, brute force) | `agent/network_ids.py` |
| 5 | Block attacker by IP + MAC (nftables) | `agent/blocker.py` |
| 6 | Continuous backup + versioning + restore | `agent/backup.py` |
| 7 | Chain-of-custody ledger (SQLite) | `agent/ledger.py` |
| 8 | Alerts (file + webhook + Telegram) | `agent/alerter.py` |
| 9 | Incident report (Markdown) | `agent/reporter.py` |
| 10 | **Web dashboard** (browser UI) | `agent/dashboard.py` |

---

## PHASE 0 — Understand the layout

```
/opt/data/edr-agent/
├── agent/            ← the Python modules (all logic)
│   ├── main.py           ← entrypoint (run | report | status)
│   ├── ledger.py         ← SQLite chain-of-custody + event store
│   ├── log_monitor.py    ← tails logs, regex rules
│   ├── file_integrity.py ← FIM hash watcher
│   ├── process_monitor.py← /proc process scanner
│   ├── network_ids.py    ← connection/scan/brute-force detector
│   ├── blocker.py        ← nftables IP/MAC blocking
│   ├── backup.py         ← versioning + restore
│   ├── alerter.py        ← local/webhook/Telegram alerts
│   └── reporter.py       ← incident report generator
├── configs/agent.yaml    ← ⭐ EDIT THIS (watched dirs, alerting, blocking)
├── scripts/
│   ├── simulate_attack.py    ← safe attack simulator (test the agent)
│   └── integration_test.py   ← proves the whole loop works
├── install.sh              ← one-shot installer
└── requirements.txt        ← PyYAML only
```

---

## PHASE 1 — Install

```bash
cd /opt/data/edr-agent
bash install.sh
# or manually:
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

1.1 ✅ `source .venv/bin/activate && python -c "import yaml"` works.

---

## PHASE 2 — Configure for YOUR machine

Edit `configs/agent.yaml`. The defaults are sane, but you must set:

- `fim.watch_dirs` — which folders to watch for changes (default `/etc`, `/home`).
- `backup.source_dirs` — which folders get continuously backed up.
- `network_ids.iface` — your real interface (`ip a` to find it; often `eth0`/`ens3`).
- `alerting.webhook_url` / `alerting.telegram` — how you want alerts delivered.
  ⭐ Leave `alerting.local_file` always — it's your offline record.
- `blocking.backend` — keep `nftables` (falls back to iptables automatically).

2.1 ✅ Confirm your interface name with `ip a`.

**Important safety note:** the default `fim.watch_dirs` includes `/home` and
`backup.source_dirs` includes `/home` + `/etc`. On a production box that means the agent
will copy *every* file under those trees on first run (the baseline). That's expected —
run the first sweep on a test box first, or trim the dirs to a small folder like
`/opt/data/important` until you're comfortable.

---

## PHASE 3 — Start the agent

```bash
sudo .venv/bin/python -m agent.main run
```

Why `sudo`:
- Reading other users' processes in `/proc`, `/var/log/auth.log`.
- Adding `nftables`/`iptables` rules (blocking).

3.1 ✅ You see `Lynx EDR starting (poll=2s)` and `FIM baseline captured: N files`.

### ⭐ Run it as a service (survives reboot/logout)

```bash
sed -i "s|/opt/data/edr-agent|$(pwd)|g" configs/lynx-edr.service   # if path differs
sudo cp configs/lynx-edr.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now lynx-edr
sudo systemctl status lynx-edr          # ✅ should show active (running)
journalctl -u lynx-edr -f               # live logs
```

---

## PHASE 4 — Prove it detects (simulate an attack)

In a second terminal:
```bash
.venv/bin/python scripts/simulate_attack.py
```

This safely triggers: brute-force log lines, file create/modify/delete, a
suspicious-name process, and port-scan connections.

4.1 ✅ Watch the agent terminal log `LOG ALERT`, `FIM`, `SUSPICIOUS PROC`,
`BLOCKED`, and `BACKUP` lines.
4.2 ✅ Run `sudo .venv/bin/python -m agent.main status` — you should see alert/block/
version counts increase.

---

## PHASE 5 — Confirm blocking (IP + MAC)

The Network IDS detects a port scan / brute force and hands the attacker IP (+ MAC from
the ARP table) to the Blocker, which adds an nftables drop rule.

5.1 ✅ Check the live rules: `sudo nft list ruleset | grep lynx_block`
5.2 ✅ Confirm the blocked IP can no longer connect to the host.
5.3 ⭐ If you must ever unblock: `sudo nft flush table inet lynx_block`.

> ⭐ With `blocking.dry_run: true`, it logs "would block" without touching your firewall.
> Use this during demos where you don't want to lock yourself out.

---

## PHASE 6 — Confirm recovery (backup + restore)

The simulator deletes a file after modifying it. The Backup module kept a versioned,
SHA-256-hashed copy.

6.1 ✅ List versions: `sudo .venv/bin/python -m agent.main restore <path>`
   (prints all versions, then asks to restore the latest).
6.2 ✅ Restore a specific version:
   `sudo .venv/bin/python -m agent.main restore <path> --version <backup_path>`.

---

## PHASE 7 — Generate the incident report

```bash
.venv/bin/python -m agent.main report
```
7.1 ✅ `logs/incident_report.md` contains: summary counts, blocked attackers (IP+MAC),
and the alert timeline. This is your diploma deliverable.

---

## PHASE 8 — Run it for real (continuous)

- Revert `blocking.dry_run` to `false`, point `fim`/`backup` at real dirs.
- Deploy to a real server and let it run. Review `logs/alerts.json` daily.
- ⭐ Set up Telegram/webhook so alerts reach your phone.

---

## The fixed/decided things (why I built it this way)

| Decision | Reason |
|----------|--------|
| SQLite, not Postgres | single agent, no DB server to host |
| nftables (backend auto-fallback) | modern, blocks IP *and* MAC via `ether saddr` |
| File-level versioning (not LVM/VSS) | portable, no root snapshots, restorable anywhere |
| Pure stdlib + PyYAML only | easy to install on any Linux box |
| Dry-run mode default in tests | never lock yourself out during a demo |
| Attack simulator included | you can demo detection with zero real malware |

## What I did NOT build (yet) — say the word and I'll add

1. **Raw packet capture** (scapy/snort-style deep inspection) — currently the IDS uses
   connection tables (no root capture). `network_ids.capture_packets` is the knob.
2. **Windows support** — the agent is Linux-only (matches your "Linux first" choice).
3. **True block-level snapshots (VSS-style)** — currently file-level versioning.

---

## Verification status

- ✅ All 12 Python files compile.
- ✅ Every module tested in isolation (log alert, FIM, backup versioning, restore,
  IP parsing, dry-run block, report generation).
- ✅ Full integration test (`scripts/integration_test.py`) passes: detect → block →
  backup → delete → restore → report, all on one machine.

**Not verifiable here** (needs root/firewall): actual `nft` rule insertion and raw
packet capture. The code paths are correct and dry-run verified.