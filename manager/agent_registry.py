"""
Lynx EDR Agent Registry
Tracks enrolled agents, heartbeats, and status.
"""

import os
import json
import threading
import datetime
from pathlib import Path
from typing import Optional, List, Dict, Any


REGISTRY_FILE = "/opt/data/edr-agent/manager/agent_registry.json"


class AgentRegistry:
    """Thread-safe agent registry."""
    
    def __init__(self, registry_file: str = REGISTRY_FILE):
        self.registry_file = Path(registry_file)
        self.registry_file.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._init_registry()
    
    def _init_registry(self):
        """Initialize registry file if not exists."""
        if not self.registry_file.exists():
            with open(self.registry_file, "w") as f:
                json.dump({}, f)
    
    def _load(self) -> dict:
        """Load registry from file."""
        with self._lock:
            try:
                with open(self.registry_file, "r") as f:
                    return json.load(f)
            except (FileNotFoundError, json.JSONDecodeError):
                return {}
    
    def _save(self, data: dict):
        """Save registry to file."""
        with self._lock:
            with open(self.registry_file, "w") as f:
                json.dump(data, f, indent=2)
    
    def register_agent(
        self,
        agent_id: str,
        agent_name: str,
        os: str,
        architecture: str,
        groups: list,
        certificate_pem: str,
        key_pem: str,
        ca_pem: str,
    ) -> dict:
        """Register a new agent."""
        with self._lock:
            data = self._load()
            
            agent = {
                "agent_id": agent_id,
                "agent_name": agent_id,  # Will be updated with actual name
                "os": "linux",
                "architecture": "x86_64",
                "groups": ["default"],
                "status": "enrolled",
                "enrolled_at": datetime.datetime.now(datetime.UTC).isoformat(),
                "last_seen": None,
                "certificate_pem": certificate_pem,
                "key_pem": key_pem,
                "ca_pem": ca_pem,
                "revoked": False,
            }
            
            data[agent_id] = agent
            self._save(data)
            return agent
    
    def update_agent_info(self, agent_id: str, **kwargs) -> bool:
        """Update agent information."""
        with self._lock:
            data = self._load()
            if agent_id not in data:
                return False
            
            for key, value in kwargs.items():
                if key in data[agent_id]:
                    data[agent_id][key] = value
            
            self._save(data)
            return True
    
    def get_agent(self, agent_id: str) -> Optional[dict]:
        """Get agent by ID."""
        with self._lock:
            data = self._load()
            return data.get(agent_id)
    
    def list_agents(self) -> List[dict]:
        """List all agents."""
        with self._lock:
            data = self._load()
            agents = []
            for agent_id, agent in data.items():
                # Determine status
                status = agent.get("status", "unknown")
                last_seen = agent.get("last_seen")
                if last_seen:
                    last_seen_dt = datetime.datetime.fromisoformat(last_seen)
                    if datetime.datetime.now(datetime.UTC) - last_seen_dt > datetime.timedelta(minutes=5):
                        if status == "online":
                            status = "stale"
                    else:
                        status = "online"
                else:
                    status = "enrolled"
                
                agents.append({
                    "agent_id": agent_id,
                    "agent_name": agent.get("agent_name", agent_id),
                    "os": agent.get("os", "linux"),
                    "architecture": agent.get("architecture", "x86_64"),
                    "groups": agent.get("groups", ["default"]),
                    "status": status,
                    "last_seen": agent.get("last_seen"),
                    "enrolled_at": agent.get("enrolled_at"),
                    "revoked": agent.get("revoked", False),
                })
            return agents
    
    def get_agent(self, agent_id: str) -> Optional[dict]:
        """Get agent details."""
        with self._lock:
            data = self._load()
            agent = data.get(agent_id)
            if not agent:
                return None
            
            # Determine current status
            status = agent.get("status", "unknown")
            last_seen = agent.get("last_seen")
            if last_seen:
                last_seen_dt = datetime.datetime.fromisoformat(last_seen)
                if datetime.datetime.now(datetime.UTC) - last_seen_dt > datetime.timedelta(minutes=5):
                    if status == "online":
                        status = "stale"
                else:
                    status = "online"
            else:
                status = "enrolled"
            
            return {
                "agent_id": agent_id,
                "agent_name": agent.get("agent_name", agent_id),
                "os": agent.get("os", "linux"),
                "architecture": agent.get("architecture", "x86_64"),
                "groups": agent.get("groups", ["default"]),
                "status": status,
                "last_seen": agent.get("last_seen"),
                "enrolled_at": agent.get("enrolled_at"),
                "revoked": agent.get("revoked", False),
            }
    
    def update_heartbeat(self, agent_id: str) -> bool:
        """Update agent heartbeat."""
        with self._lock:
            data = self._load()
            if agent_id not in data:
                return False
            
            data[agent_id]["last_seen"] = datetime.datetime.now(datetime.UTC).isoformat()
            data[agent_id]["status"] = "online"
            self._save(data)
            return True
    
    def revoke_agent(self, agent_id: str) -> bool:
        """Revoke agent."""
        with self._lock:
            data = self._load()
            if agent_id not in data:
                return False
            
            data[agent_id]["revoked"] = True
            data[agent_id]["status"] = "revoked"
            data[agent_id]["revoked_at"] = datetime.datetime.now(datetime.UTC).isoformat()
            self._save(data)
            return True
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete agent from registry."""
        with self._lock:
            data = self._load()
            if agent_id not in data:
                return False
            
            del data[agent_id]
            self._save(data)
            return True
    
    def get_online_agents(self) -> List[dict]:
        """Get list of online agents."""
        return [a for a in self.list_agents() if a["status"] == "online"]
    
    def get_stats(self) -> dict:
        """Get registry statistics."""
        agents = self.list_agents()
        return {
            "total": len(agents),
            "online": len([a for a in agents if a["status"] == "online"]),
            "stale": len([a for a in agents if a["status"] == "stale"]),
            "enrolled": len([a for a in agents if a["status"] == "enrolled"]),
            "revoked": len([a for a in agents if a["status"] == "revoked"]),
            "by_os": {},
            "by_group": {},
        }


# Singleton instance
_registry_instance = None


def get_agent_registry() -> AgentRegistry:
    """Get or create agent registry singleton."""
    global _registry_instance
    if _registry_instance is None:
        _registry_instance = AgentRegistry()
    return _registry_instance