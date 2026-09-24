# Lynx EDR — Linux Endpoint Detection & Response

**Single-agent Linux EDR with real-time detection, kernel-level blocking, forensic ledger, and agent fleet management.**

## Features

- 🔍 **Multi-vector Detection**: Log monitoring, Network IDS, Process monitoring, File Integrity Monitoring
- 🛡️ **Kernel-level Blocking**: nftables DROP rules at priority -2 (beats Fail2Ban/UFW)
- 📋 **Forensic Ledger**: SQLite chain-of-custody with hash-chained events
- 💾 **Versioned Backups**: SHA-256 verified file restore
- 📱 **Telegram Alerting**: Structured incident reports to mobile
- 🌐 **Web Dashboard**: Authenticated live metrics on :8090
- 🤖 **Agent Fleet Management**: Wazuh-style enrollment with mTLS certificates
- ⚙️ **Systemd Service**: Persistent, auto-start, resource-tracked

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    LYNX EDR AGENT                           │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ Log Monitor │ │ Network IDS │ │ Proc Monitor│            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   FIM       │ │  Blocker    │ │   Backup    │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │   Ledger    │ │  Alerter    │ │  Reporter   │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    LYNX MANAGER (Central)                   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐            │
│  │ Enrollment  │ │   Cert      │ │   Agent     │            │
│  │    API      │ │ Authority   │ │  Registry   │            │
│  └─────────────┘ └─────────────┘ └─────────────┘            │
└─────────────────────────────────────────────────────────────┘
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
        ┌─────────┐   ┌─────────┐   ┌─────────┐
        │ Linux   │   │ Windows │   │ macOS   │
        │ Agent   │   │ Agent   │   │ Agent   │
        └─────────┘   └─────────┘   └─────────┘
```

## Quick Start

### Prerequisites
- Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- Root access
- Python 3.10+

### Installation

```bash
# Clone repository
git clone https://github.com/mathiaswilliam761-ui/Lynx_EDR-SOC-Monitoring.git
cd Lynx_EDR-SOC-Monitoring

# Configure
cp configs/agent.yaml.example configs/agent.yaml
# Edit configs/agent.yaml with your settings:
# - Telegram bot_token & chat_id
# - Web dashboard auth_token
# - Network interface (iface)
# - Manager URL (for fleet mode)

# Install
chmod +x install.sh
sudo ./install.sh
```

### Verify Installation

```bash
# Check service
sudo systemctl status lynx-edr

# Check metrics
cd /opt/lynx-edr  # or install path
source .venv/bin/activate
python -m agent.main status

# Access dashboard
# http://<YOUR_IP>:8090
```

## Configuration

Edit `configs/agent.yaml`:

```yaml
# Required for alerts
telegram:
  bot_token: "YOUR_BOT_TOKEN"
  chat_id: "YOUR_CHAT_ID"

# Required for dashboard auth
web:
  auth_token: "YOUR_SECURE_TOKEN"

# Network interface (auto-detected if not set)
network_ids:
  iface: "eth0"  # or ens5, ens3, etc.

# For fleet mode
manager:
  url: "https://YOUR_MANAGER_IP:8443"
```

## Fleet Mode (Multi-Agent)

### Manager Setup (Central Server)
```bash
# Start enrollment API with mTLS
cd /opt/lynx-edr
source .venv/bin/activate
uvicorn manager.enrollment:app --host 0.0.0.0 --port 8443 \
  --ssl-keyfile manager/ca/ca.key --ssl-certfile manager/ca/ca.crt
```

### Enroll Agents
1. Open dashboard: `http://<MANAGER_IP>:8090/enroll`
2. Fill form: Agent Name, OS, Groups
3. Copy generated command
4. Run on target: `curl -sSL https://<MANAGER_IP>:8443/enroll/TOKEN | bash`

### Monitor Fleet
- Dashboard: `http://<MANAGER_IP>:8090/agents`
- API: `GET /api/agents`, `GET /api/agents/stats`

## Dashboard

| Page | URL |
|------|-----|
| Main Dashboard | `http://<IP>:8090` |
| Enrollment | `http://<IP>:8090/enroll` |
| Agent Fleet | `http://<IP>:8090/agents` |

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/status` | GET | Live metrics |
| `/api/alerts` | GET | Recent alerts |
| `/api/blocks` | GET | Blocked attackers |
| `/api/versions` | GET | File versions |
| `/api/report` | GET | Incident report |
| `/api/enroll` | POST | Create enrollment |
| `/enroll/{token}` | GET | Install script |
| `/api/agents` | GET | List agents |
| `/api/agents/stats` | GET | Fleet stats |
| `/api/agents/{id}/revoke` | POST | Revoke agent |

## Detection Capabilities

| Module | Detects |
|--------|---------|
| Log Monitor | SSH brute-force, sudo abuse, root login |
| Network IDS | Port scans, brute-force, connection anomalies |
| Process Monitor | Suspicious names, high CPU, hidden processes |
| FIM | File create/modify/delete with versioning |

## Response Actions

- **Auto-block**: nftables DROP rules (IP + MAC) at priority -2
- **Alert**: Telegram structured incident reports
- **Forensics**: Hash-chained ledger, versioned backups
- **Dashboard**: Real-time metrics + block management

## Requirements

```
PyYAML>=6.0
psutil>=5.9.0
requests>=2.31.0
cryptography>=41.0.0
fastapi>=0.104.0
uvicorn>=0.24.0
```

## Project Structure

```
lynx-edr/
├── agent/
│   ├── main.py              # Main entry point
│   ├── log_monitor.py       # Log pattern detection
│   ├── network_ids.py       # Network IDS
│   ├── process_monitor.py   # Process monitoring
│   ├── file_integrity.py    # FIM + versioned backups
│   ├── blocker.py           # nftables blocking
│   ├── ledger.py            # SQLite chain-of-custody
│   ├── alerter.py           # Telegram/webhook alerts
│   ├── reporter.py          # Incident reports
│   ├── backup.py            # Versioned backups
│   ├── dashboard.py         # Web dashboard + enrollment UI
│   ├── enrollment_client.py # Agent enrollment client
│   └── installer/
│       └── install_linux.sh # Linux installer template
├── manager/
│   ├── enrollment.py        # FastAPI enrollment API
│   ├── ca.py                # Certificate Authority
│   ├── agent_registry.py    # Agent registry + heartbeats
│   └── ca/                  # CA certs (gitignored)
├── configs/
│   ├── agent.yaml           # Main config (gitignored)
│   └── agent.yaml.example   # Template
├── scripts/
│   ├── simulate_attack.py   # Test attack generator
│   └── integration_test.py  # Integration tests
├── install.sh               # Installer
├── requirements.txt
└── .gitignore
```

## Security

- **mTLS**: All agent↔manager traffic encrypted
- **Token Expiry**: Enrollment tokens expire in 24h
- **Cert Revocation**: Revoking agent invalidates certificate
- **Heartbeat**: Agents must heartbeat every 30s
- **Dashboard Auth**: Token-based auth (configurable)

## License

MIT License

## Author

Mathias William Edwards — DFIR Diploma Project, BIA Bengaluru 2026

---

**Built for DFIR research and production endpoint protection.**