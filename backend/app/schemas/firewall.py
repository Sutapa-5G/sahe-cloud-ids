"""
backend/app/schemas/firewall.py

Request/response schemas for /firewall/block, /firewall/unblock,
/firewall/rules.
"""
from __future__ import annotations

from pydantic import BaseModel, Field, field_validator
import ipaddress


class BlockRequest(BaseModel):
    ip: str = Field(..., description="IPv4 or IPv6 address to block.")
    reason: str = Field(..., description="Why this IP is being blocked (e.g. attack_type + event_id).")

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        # Raises ValueError (which FastAPI turns into a 422) for anything
        # that isn't a real IP address — never pass an unvalidated string
        # toward a firewall provider, especially the iptables one.
        ipaddress.ip_address(v)
        return v


class UnblockRequest(BaseModel):
    ip: str

    @field_validator("ip")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v


class FirewallActionResponse(BaseModel):
    ip: str
    action: str
    mode: str
    success: bool
    message: str


class FirewallRuleEntry(BaseModel):
    ip: str
    action: str
    mode: str
    reason: str
    timestamp: str
