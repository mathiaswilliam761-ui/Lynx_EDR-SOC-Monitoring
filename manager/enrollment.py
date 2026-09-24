"""
Lynx EDR Enrollment API
FastAPI-based enrollment service for agent registration.
"""

import os
import secrets
import json
import datetime
from pathlib import Path
from typing import Optional, List
from dataclasses import dataclass, asdict

from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from manager.ca import get_ca
from manager.agent_registry import get_agent_registry


# Models
class EnrollmentRequest(BaseModel):
    agent_name: str = Field(..., min_length=1, max_length=100)
    os: str = Field(..., pattern="^(linux|windows|macos)$")
    architecture: str = Field(default="x86_64", pattern="^(x86_64|arm64|aarch64|i386)$")
    groups: List[str] = Field(default_factory=lambda: ["default"])
    manager_url: str = Field(default="https://localhost:8443")


class EnrollmentResponse(BaseModel):
    enrollment_token: str
    agent_id: str
    install_command: str
    expires_at: str


class AgentInfo(BaseModel):
    agent_id: str
    agent_name: str
    os: str
    architecture: str
    groups: List[str]
    status: str
    last_seen: Optional[str]
    enrolled_at: str
    manager_url: str


class TokenData(BaseModel):
    enrollment_token: str
    agent_id: str
    agent_name: str
    os: str
    architecture: str
    groups: List[str]
    created_at: str
    expires_at: str


# Auth
security = HTTPBearer(auto_error=False)

# Enrollment tokens storage
TOKENS_FILE = "/opt/data/edr-agent/manager/enrollment_tokens.json"


def load_tokens() -> dict:
    try:
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_tokens(tokens: dict):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f, indent=2)


def generate_enrollment_token() -> str:
    """Generate secure enrollment token."""
    return secrets.token_urlsafe(32)


def validate_enrollment_token(token: str) -> Optional[TokenData]:
    """Validate and return token data if valid."""
    tokens = load_tokens()
    if token not in tokens:
        return None
    
    token_data = tokens[token]
    expires_at = datetime.datetime.fromisoformat(token_data["expires_at"])
    if datetime.datetime.utcnow() > expires_at:
        # Token expired
        del tokens[token]
        save_tokens(tokens)
        return None
    
    return TokenData(**token_data)


# FastAPI app
app = FastAPI(title="Lynx EDR Enrollment API", version="1.0.0")


# Dependency for token validation
async def get_valid_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> TokenData:
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing authentication token")
    
    token_data = validate_enrollment_token(credentials.credentials)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")
    
    return token_data


@app.post("/api/enroll", response_model=EnrollmentResponse)
async def create_enrollment(request: EnrollmentRequest):
    """Create new agent enrollment."""
    # Generate agent ID
    agent_id = secrets.token_urlsafe(16)
    
    # Generate enrollment token
    enrollment_token = generate_enrollment_token()
    expires_at = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    
    # Store token data
    token_data = TokenData(
        enrollment_token=enrollment_token,
        agent_id=agent_id,
        agent_name=request.agent_name,
        os=request.os,
        architecture=request.architecture,
        groups=request.groups,
        created_at=datetime.datetime.utcnow().isoformat(),
        expires_at=expires_at.isoformat(),
    )
    
    tokens = load_tokens()
    tokens[enrollment_token] = asdict(token_data)
    save_tokens(tokens)
    
    # Generate install command
    base_url = request.manager_url.rstrip("/")
    install_commands = {
        "linux": f"curl -sSL {base_url}/enroll/{enrollment_token} | bash",
        "windows": f"Invoke-WebRequest -Uri {base_url}/enroll/{enrollment_token} -OutFile $env:TEMP\\lynx_install.ps1; powershell -ExecutionPolicy Bypass -File $env:TEMP\\lynx_install.ps1",
        "macos": f"curl -sSL {base_url}/enroll/{enrollment_token} | bash",
    }
    
    install_command = install_commands.get(request.os, install_commands["linux"])
    
    return EnrollmentResponse(
        enrollment_token=enrollment_token,
        agent_id=agent_id,
        install_command=install_command,
        expires_at=expires_at.isoformat(),
    )


@app.get("/enroll/{enrollment_token}", response_class=PlainTextResponse)
async def get_install_script(enrollment_token: str):
    """Return the install script for the agent."""
    token_data = validate_enrollment_token(enrollment_token)
    if not token_data:
        raise HTTPException(status_code=404, detail="Invalid or expired enrollment token")
    
    # Get CA cert
    ca = get_ca()
    _, _, ca_pem = ca.generate_agent_cert(
        agent_id=token_data.agent_id,
        agent_name=token_data.agent_name,
        groups=token_data.groups
    )
    
    # Mark token as used (remove it)
    tokens = load_tokens()
    if enrollment_token in tokens:
        del tokens[enrollment_token]
        save_tokens(tokens)
    
    # Generate agent certificate
    agent_cert_pem, agent_key_pem, ca_cert_pem = ca.generate_agent_cert(
        agent_id=token_data.agent_id,
        agent_name=token_data.agent_name,
        groups=token_data.groups
    )
    
    # Register agent
    registry = get_agent_registry()
    registry.register_agent(
        agent_id=token_data.agent_id,
        agent_name=token_data.agent_name,
        os=token_data.os,
        architecture=token_data.architecture,
        groups=token_data.groups,
        certificate_pem=agent_cert_pem.decode(),
        key_pem=agent_key_pem.decode(),
        ca_pem=ca_cert_pem.decode(),
    )
    
    # Generate install script
    script = f"""#!/bin/bash
# Lynx EDR Agent Install Script
# Agent: {token_data.agent_name} ({token_data.agent_id})
# OS: {token_data.os}
# Groups: {",".join(token_data.groups)}
# Generated: {datetime.datetime.utcnow().isoformat()}Z

set -e

echo "[+] Installing Lynx EDR Agent: {token_data.agent_name}"

# Create agent directory
sudo mkdir -p /opt/lynx-agent
cd /opt/lynx-agent

# Download agent package (placeholder - replace with actual download URL)
# sudo curl -sSL https://manager.example.com/download/lynx-agent-linux.tar.gz | sudo tar -xz

# For now, create minimal structure
sudo mkdir -p /opt/lynx-agent/agent /opt/lynx-agent/configs /opt/lynx-agent/scripts /opt/lynx-agent/certs

# Write certificates
cat > /opt/lynx-agent/certs/agent.crt << 'CERTEOF'
{agent_cert_pem.decode()}
CERTEOF

cat > /opt/lynx-agent/certs/agent.key << 'KEYEOF'
{agent_key_pem.decode()}
KEYEOF

cat > /opt/lynx-agent/certs/ca.crt << 'CAEOF'
{ca_cert_pem.decode()}
CAEOF

# Set permissions
sudo chmod 600 /opt/lynx-agent/certs/agent.key
sudo chmod 644 /opt/lynx-agent/certs/agent.crt /opt/lynx-agent/certs/ca.crt

# Write agent config
cat > /opt/lynx-agent/configs/agent.yaml << 'CONFIGEOF'
agent:
  name: "{token_data.agent_name}"
  id: "{token_data.agent_id}"
  groups: {token_data.groups}

manager:
  url: "https://manager.example.com:8443"
  ca_cert: "/opt/lynx-agent/certs/ca.crt"
  agent_cert: "/opt/lynx-agent/certs/agent.crt"
  agent_key: "/opt/lynx-agent/certs/agent.key"

# Include base config
include: ["/opt/lynx-agent/configs/base.yaml"]
CONFIGEOF

# Install systemd service (simplified)
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

[Install]
WantedBy=multi-user.target
SVC_EOF

# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable lynx-agent
sudo systemctl start lynx-agent

echo "[+] Lynx EDR Agent installed and started"
echo "[+] Agent ID: {token_data.agent_id}"
echo "[+] Agent Name: {token_data.agent_name}"
"""

    return script


@app.get("/api/agents", response_model=List[AgentInfo])
async def list_agents():
    """List all enrolled agents."""
    registry = get_agent_registry()
    agents = registry.list_agents()
    return agents


@app.get("/api/agents/{agent_id}", response_model=AgentInfo)
async def get_agent(agent_id: str):
    """Get agent details."""
    registry = get_agent_registry()
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.post("/api/agents/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, token_data: TokenData = Depends(get_valid_token)):
    """Agent heartbeat endpoint."""
    registry = get_agent_registry()
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    if agent["agent_id"] != token_data.agent_id:
        raise HTTPException(status_code=403, detail="Token does not match agent")
    
    registry.update_heartbeat(agent_id)
    return {"status": "ok"}


@app.post("/api/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: str):
    """Revoke agent enrollment."""
    registry = get_agent_registry()
    agent = registry.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    
    # Revoke certificate
    ca = get_ca()
    ca.revoke_agent_cert(agent_id)
    
    # Mark agent as revoked
    registry.revoke_agent(agent_id)
    
    return {"status": "revoked"}


# Health check
@app.get("/health")
async def health_check():
    return {"status": "healthy", "service": "lynx-enrollment"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8443, ssl_keyfile="/opt/data/edr-agent/manager/ca/ca.key", ssl_certfile="/opt/data/edr-agent/manager/ca/ca.crt")