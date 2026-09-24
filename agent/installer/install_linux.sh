#!/bin/bash
# Lynx EDR Agent Installer Template
# This template is populated by the enrollment server with actual values

# ==========================================
# PLACEHOLDERS (replaced by enrollment server):
# {{ENROLLMENT_TOKEN}} - Enrollment token
# {{MANAGER_URL}} - Manager URL (e.g., https://manager.example.com:8443)
# {{AGENT_NAME}} - Agent name
# {{AGENT_ID}} - Agent ID
# {{AGENT_GROUPS}} - Comma-separated groups
# {{CA_CERT_PEM}} - CA certificate PEM
# {{AGENT_CERT_PEM}} - Agent certificate PEM
# {{AGENT_KEY_PEM}} - Agent private key PEM
# ==========================================

set -e

# ==========================================
# CONFIGURATION (populated by enrollment server)
# ==========================================
ENROLLMENT_TOKEN="{{ENROLLMENT_TOKEN}}"
MANAGER_URL="{{MANAGER_URL}}"
AGENT_NAME="{{AGENT_NAME}}"
AGENT_ID="{{AGENT_ID}}"
AGENT_GROUPS="{{AGENT_GROUPS}}"
AGENT_DIR="/opt/lynx-agent"

# ==========================================
# CERTIFICATES (embedded by enrollment server)
# ==========================================
CA_CERT_PEM='{{CA_CERT_PEM}}'
AGENT_CERT_PEM='{{AGENT_CERT_PEM}}'
AGENT_KEY_PEM='{{AGENT_KEY_PEM}}'

# ==========================================
# COLORS FOR OUTPUT
# ==========================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() { echo -e "${GREEN}[+]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[!]${NC} $1"; }
log_error() { echo -e "${RED}[-]${NC} $1"; }

# ==========================================
# MAIN INSTALLATION
# ==========================================
main() {
    log_info "Starting Lynx EDR Agent installation"
    log_info "Agent: $AGENT_NAME (${AGENT_ID})"
    log_info "Groups: $AGENT_GROUPS"
    log_info "Manager: $MANAGER_URL"
    
    # Check root
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root"
        exit 1
    fi
    
    # Check OS
    if [[ ! -f /etc/os-release ]]; then
        log_error "Cannot determine OS"
        exit 1
    fi
    
    log_info "Creating agent directory: /opt/lynx-agent"
    mkdir -p /opt/lynx-agent
    cd /opt/lynx-agent
    
    # Create directory structure
    log_info "Creating directory structure..."
    mkdir -p certs configs scripts agent
    
    # Write certificates
    log_info "Writing certificates..."
    cat > /opt/lynx-agent/certs/ca.crt << 'CA_EOF'
{{CA_CERT_PEM}}
CA_EOF

    cat > /opt/lynx-agent/certs/agent.crt << 'CERT_EOF'
{{AGENT_CERT_PEM}}
CERT_EOF

    cat > /opt/lynx-agent/certs/agent.key << 'KEY_EOF'
{{AGENT_KEY_PEM}}
KEY_EOF

    # Set certificate permissions
    chmod 600 /opt/lynx-agent/certs/agent.key
    chmod 644 /opt/lynx-agent/certs/agent.crt /opt/lynx-agent/certs/ca.crt
    log_info "Certificates written and secured"
    
    # Write agent configuration
    log_info "Writing agent configuration..."
    cat > /opt/lynx-agent/configs/agent.yaml << CONFIG_EOF
agent:
  name: "$AGENT_NAME"
  id: "$AGENT_ID"
  groups: [$(echo $AGENT_GROUPS | sed 's/,/","/g' | sed 's/^/"/;s/$/"/;s/,/","/g')]

manager:
  url: "$MANAGER_URL"
  ca_cert: "/opt/lynx-agent/certs/ca.crt"
  agent_cert: "/opt/lynx-agent/certs/agent.crt"
  agent_key: "/opt/lynx-agent/certs/agent.key"

# Include base config
include: ["/opt/lynx-agent/configs/base.yaml"]
CONFIG_EOF
    log_info "Agent configuration written"
    
    # Create base configuration template
    cat > /opt/lynx-agent/configs/base.yaml << 'BASE_EOF'
# Lynx EDR Base Configuration
# This file is included by agent.yaml

log_monitor:
  enabled: true
  files:
    - "/var/log/auth.log"
    - "/var/log/syslog"
  patterns:
    ssh_failed_login: "Failed password for .* from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
    ssh_invalid_user: "Invalid user .* from (?P<ip>\\d+\\.\\d+\\.\\d+\\.\\d+)"
    sudo_failure: "sudo: .* command not found|COMMAND=.*authentication failure"
    su_failure: "authentication failure.*su"
    root_login: "Accepted (publickey|password) for root"

fim:
  enabled: true
  watch_dirs:
    - "/etc"
    - "/home"
    - "/root"
    - "/opt"
  ignore_extensions: [".swp", ".tmp", ".pyc", ".log"]
  max_events_per_sweep: 200

process_monitor:
  enabled: true
  suspicious_names: ["minerd", "xmrig", "kworkerds", "kinsing", "crack", "brute", "xmrminer"]
  high_cpu_threshold: 90.0

network_ids:
  enabled: true
  watch_ports: [22, 80, 443, 445, 3389]
  scan_threshold: 8
  brute_force_threshold: 5
  window_seconds: 30
  capture_packets: false

blocking:
  enabled: true
  backend: "nftables"
  table_name: "lynx_block"
  max_auto_blocks: 100
  dry_run: false

backup:
  enabled: true
  source_dirs:
    - "/etc"
    - "/home"
    - "/root"
  backup_dir: "/opt/lynx-agent/backup"
  max_versions: 100
  compression: true

heartbeat:
  enabled: true
  interval_seconds: 30
  manager_url: "https://manager.example.com:8443"
  cert_dir: "/opt/lynx-agent/certs"
BASE_EOF

    log_info "Base configuration created"
    
    # Create Python virtual environment and install dependencies
    log_info "Setting up Python virtual environment..."
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --upgrade pip -q
    pip install pyyaml psutil requests cryptography -q
    log_info "Dependencies installed"
    
    # Create systemd service
    log_info "Creating systemd service..."
    cat > /etc/systemd/system/lynx-agent.service << 'SVC_EOF'
[Unit]
Description=Lynx EDR Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lynx-agent
ExecStart=/opt/lynx-agent/.venv/bin/python -m agent.main run
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVC_EOF

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable lynx-agent
    systemctl start lynx-agent
    log_info "Systemd service created and started"
    
    # Verify service is running
    sleep 2
    if systemctl is-active --quiet lynx-agent; then
        log_info "Lynx EDR Agent service is running"
    else
        log_error "Service failed to start"
        systemctl status lynx-agent
        exit 1
    fi
    
    log_info "=========================================="
    log_info "Lynx EDR Agent installation complete!"
    log_info "Agent Name: $AGENT_NAME"
    log_info "Agent ID: $AGENT_ID"
    log_info "Groups: $AGENT_GROUPS"
    log_info "Installation directory: /opt/lynx-agent"
    log_info "Service: lynx-agent (systemd)"
    log_info "=========================================="
    log_info "To check status: systemctl status lynx-agent"
    log_info "To view logs: journalctl -u lynx-agent -f"
}

# Run main
main "$@"