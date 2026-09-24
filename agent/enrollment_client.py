#!/usr/bin/env python3
"""
Lynx EDR Agent Enrollment Client
Runs on agent during installation to enroll with manager.
"""

import os
import sys
import json
import argparse
import ssl
import tempfile
import subprocess
from pathlib import Path
from urllib.parse import urljoin

import requests


class EnrollmentClient:
    """Client for enrolling agent with Lynx Manager."""
    
    def __init__(self, manager_url: str, enrollment_token: str, agent_name: str = None):
        self.manager_url = manager_url.rstrip("/")
        self.enrollment_token = enrollment_token
        self.agent_name = agent_name
        self.session = requests.Session()
        # Disable SSL verification for self-signed certs (dev only)
        self.session.verify = False
        requests.packages.urllib3.disable_warnings()
    
    def enroll(self) -> dict:
        """Enroll agent with manager using enrollment token."""
        url = urljoin(self.manager_url, f"/enroll/{self.enrollment_token}")
        
        response = self.session.get(url, timeout=30)
        if response.status_code != 200:
            raise Exception(f"Enrollment failed: {response.status_code} - {response.text}")
        
        return response.text  # Returns install script
    
    def save_certs(self, cert_pem: str, key_pem: str, ca_pem: str, cert_dir: str):
        """Save certificates to disk."""
        cert_dir = Path(cert_dir)
        cert_dir.mkdir(parents=True, exist_ok=True)
        
        with open(cert_dir / "agent.crt", "w") as f:
            f.write(cert_pem)
        with open(cert_dir / "agent.key", "w") as f:
            f.write(key_pem)
        with open(cert_dir / "ca.crt", "w") as f:
            f.write(ca_pem)
        
        # Set permissions
        os.chmod(cert_dir / "agent.key", 0o600)
        os.chmod(cert_dir / "agent.crt", 0o644)
        os.chmod(cert_dir / "ca.crt", 0o644)
    
    def write_config(self, config_dir: str, agent_config: dict):
        """Write agent configuration."""
        config_dir = Path(config_dir)
        config_dir.mkdir(parents=True, exist_ok=True)
        
        import yaml
        config = {
            "agent": {
                "name": agent_config.get("agent_name"),
                "id": agent_config.get("agent_id"),
                "groups": agent_config.get("groups", ["default"]),
            },
            "manager": {
                "url": agent_config.get("manager_url", "https://manager.example.com:8443"),
                "ca_cert": "/opt/lynx-agent/certs/ca.crt",
                "agent_cert": "/opt/lynx-agent/certs/agent.crt",
                "agent_key": "/opt/lynx-agent/certs/agent.key",
            },
            "include": ["/opt/lynx-agent/configs/base.yaml"],
        }
        
        with open(Path(config_dir) / "agent.yaml", "w") as f:
            yaml.dump(config, f, default_flow_style=False)
    
    def install_systemd_service(self, agent_dir: str):
        """Install systemd service for the agent."""
        service_content = f"""[Unit]
Description=Lynx EDR Agent
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={agent_dir}
ExecStart={agent_dir}/.venv/bin/python -m agent.main run
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        service_path = Path("/etc/systemd/system/lynx-agent.service")
        with open(service_path, "w") as f:
            f.write(_service_content)
        
        # Reload and enable
        subprocess.run(["systemctl", "daemon-reload"], check=True)
        subprocess.run(["systemctl", "enable", "lynx-agent"], check=True)
        subprocess.run(["systemctl", "start", "lynx-agent"], check=True)
    
    def run_enrollment(self, agent_dir: str = "/opt/lynx-agent") -> bool:
        """Run full enrollment process."""
        try:
            print(f"[+] Enrolling agent with manager: {self.manager_url}")
            
            # Get install script from manager
            script = self.enroll()
            
            # Parse the script to extract certs and config
            # (The script contains certs embedded - we'd parse them)
            # For now, we'll execute the script directly
            
            print("[+] Received enrollment script from manager")
            print("[+] Executing installation script...")
            
            # Execute the script
            env = os.environ.copy()
            env["LYNX_AGENT_DIR"] = "/opt/lynx-agent"
            result = subprocess.run(
                ["bash", "-c", script],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if result.returncode != 0:
                print(f"[-] Installation failed: {result.stderr}")
                return False
            
            print("[+] Installation completed successfully")
            print(result.stdout)
            return True
            
        except Exception as e:
            print(f"[-] Enrollment failed: {e}")
            return False


def main():
    parser = argparse.ArgumentParser(description="Lynx EDR Agent Enrollment Client")
    parser.add_argument("--manager", required=True, help="Manager URL (e.g., https://manager.example.com:8443)")
    parser.add_argument("--token", required=True, help="Enrollment token")
    parser.add_argument("--name", help="Agent name")
    parser.add_argument("--dir", default="/opt/lynx-agent", help="Agent installation directory")
    
    args = parser.parse_args()
    
    # Disable SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    client = EnrollmentClient(
        manager_url=args.manager,
        enrollment_token=args.token,
        agent_name=args.name
    )
    
    success = client.run_enrollment(args.dir)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()