"""
Certificate Authority for Lynx EDR mTLS
Generates and manages certificates for agent enrollment.
"""

import os
import json
import secrets
import datetime
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class LynxCA:
    """Simple Certificate Authority for Lynx EDR agent certificates."""
    
    def __init__(self, ca_dir: str = "/opt/data/edr-agent/manager/ca"):
        self.ca_dir = Path(ca_dir)
        self.ca_dir.mkdir(parents=True, exist_ok=True)
        self.ca_key_path = self.ca_dir / "ca.key"
        self.ca_cert_path = self.ca_dir / "ca.crt"
        self.index_path = self.ca_dir / "index.json"
        self._init_ca()
    
    def _init_ca(self):
        """Initialize CA if not exists."""
        if not self.ca_key_path.exists() or not self.ca_cert_path.exists():
            self._generate_ca()
        if not self.index_path.exists():
            self._save_index({})
    
    def _generate_ca(self):
        """Generate root CA key and certificate."""
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create CA certificate
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lynx EDR"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Lynx EDR Root CA"),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=3650)  # 10 years
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                decipher_only=False,
                encipher_only=False,
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        # Save CA key and cert
        with open(self.ca_key_path, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        with open(self.ca_cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Set permissions
        os.chmod(self.ca_key_path, 0o600)
    
    def _load_index(self) -> dict:
        """Load certificate index."""
        try:
            with open(self.index_path, "r") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
    
    def _save_index(self, index: dict):
        """Save certificate index."""
        with open(self.index_path, "w") as f:
            json.dump(index, f, indent=2)
    
    def _load_ca_key(self):
        """Load CA private key."""
        with open(self.ca_key_path, "rb") as f:
            return serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )
    
    def _load_ca_cert(self):
        """Load CA certificate."""
        with open(self.ca_cert_path, "rb") as f:
            return x509.load_pem_x509_certificate(f.read(), default_backend())
    
    def generate_agent_cert(self, agent_id: str, agent_name: str, groups: list = None) -> tuple:
        """
        Generate agent certificate signed by CA.
        Returns (cert_pem, key_pem, ca_cert_pem)
        """
        ca_key = self._load_ca_key()
        ca_cert = self._load_ca_cert()
        
        # Generate agent private key
        agent_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create agent certificate
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lynx EDR"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, ",".join(groups or ["default"])),
            x509.NameAttribute(NameOID.COMMON_NAME, agent_name),
        ])
        
        # Subject Alternative Name
        san = x509.SubjectAlternativeName([
            x509.DNSName(f"{agent_name}.lynx.local"),
            x509.DNSName(agent_id),
        ])
        
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            agent_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)  # 1 year
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                decipher_only=False,
                encipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).add_extension(
            san,
            critical=False,
        ).sign(ca_key, hashes.SHA256(), default_backend())
        
        # Save to index
        index = self._load_index()
        index[agent_id] = {
            "agent_name": agent_name,
            "groups": groups or ["default"],
            "serial_number": str(cert.serial_number),
            "issued_at": datetime.datetime.utcnow().isoformat(),
            "expires_at": cert.not_valid_after_utc.isoformat(),
            "revoked": False,
        }
        self._save_index(index)
        
        # Return PEMs
        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = agent_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
        
        return cert_pem, key_pem, ca_pem
    
    def revoke_agent_cert(self, agent_id: str) -> bool:
        """Revoke agent certificate."""
        index = self._load_index()
        if agent_id in index and not index[agent_id].get("revoked", False):
            index[agent_id]["revoked"] = True
            index[agent_id]["revoked_at"] = datetime.datetime.utcnow().isoformat()
            self._save_index(index)
            return True
        return False
    
    def get_agent_info(self, agent_id: str) -> dict:
        """Get agent certificate info."""
        index = self._load_index()
        return index.get(agent_id, {})
    
    def list_agents(self) -> list:
        """List all agents."""
        index = self._load_index()
        return [
            {
                "agent_id": agent_id,
                "agent_name": info.get("agent_name"),
                "groups": info.get("groups", []),
                "issued_at": info.get("issued_at"),
                "expires_at": info.get("expires_at"),
                "revoked": info.get("revoked", False),
            }
            for agent_id, info in index.items()
        ]


# Singleton instance
_ca_instance = None


def get_ca() -> LynxCA:
    """Get or create CA singleton."""
    global _ca_instance
    if _ca_instance is None:
        _ca_instance = LynxCA()
    return _ca_instance