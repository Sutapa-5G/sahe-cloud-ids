"""
backend/app/firewall/provider.py

Firewall blocking abstraction. Per the Phase 0 review and the project's
repeated safety requirement: the DEFAULT is always simulated mode. This
system never modifies a real host firewall unless explicitly configured
to do so (FIREWALL_MODE=iptables in settings) — and even then,
IptablesFirewallProvider validates every IP, logs every action, prevents
duplicate rules, and fails safely rather than raising an uncaught
exception into calling code.

This is a defensive IDS/IPS research project — nothing here is intended
or suitable for offensive use.
"""
from __future__ import annotations

import ipaddress
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class FirewallActionResult:
    ip: str
    action: str  # "block" | "unblock"
    mode: str    # "simulated" | "iptables"
    success: bool
    message: str
    timestamp: str


class FirewallProvider(ABC):
    @abstractmethod
    def block(self, ip: str, reason: str) -> FirewallActionResult:
        ...

    @abstractmethod
    def unblock(self, ip: str) -> FirewallActionResult:
        ...

    @abstractmethod
    def list_rules(self) -> list[dict]:
        ...


def _validate_ip(ip: str) -> None:
    """Raises ValueError for anything that isn't a real IP address.
    Called defensively even though the API schema layer (schemas/firewall.py)
    already validates this — a provider must never trust that every
    caller went through that layer."""
    ipaddress.ip_address(ip)


class SimulatedFirewallProvider(FirewallProvider):
    """
    Default provider. Maintains an in-memory (or, once Phase 10 wires it
    up, MongoDB-backed) record of "blocked" IPs without touching any real
    network configuration. Safe to use in any environment, including this
    development sandbox.
    """

    def __init__(self) -> None:
        self._blocked: dict[str, dict] = {}

    def block(self, ip: str, reason: str) -> FirewallActionResult:
        _validate_ip(ip)
        now = datetime.now(timezone.utc).isoformat()
        if ip in self._blocked:
            return FirewallActionResult(
                ip=ip, action="block", mode="simulated", success=True,
                message=f"IP {ip} was already blocked (no duplicate rule created); reason unchanged: {self._blocked[ip]['reason']}",
                timestamp=now,
            )
        self._blocked[ip] = {"reason": reason, "timestamp": now}
        return FirewallActionResult(
            ip=ip, action="block", mode="simulated", success=True,
            message=f"IP {ip} recorded as blocked (simulated — no real firewall modified). Reason: {reason}",
            timestamp=now,
        )

    def unblock(self, ip: str) -> FirewallActionResult:
        _validate_ip(ip)
        now = datetime.now(timezone.utc).isoformat()
        if ip not in self._blocked:
            return FirewallActionResult(
                ip=ip, action="unblock", mode="simulated", success=True,
                message=f"IP {ip} was not currently blocked; no action needed.",
                timestamp=now,
            )
        del self._blocked[ip]
        return FirewallActionResult(
            ip=ip, action="unblock", mode="simulated", success=True,
            message=f"IP {ip} removed from simulated block list.",
            timestamp=now,
        )

    def list_rules(self) -> list[dict]:
        return [
            {"ip": ip, "action": "block", "mode": "simulated", "reason": data["reason"], "timestamp": data["timestamp"]}
            for ip, data in self._blocked.items()
        ]


class IptablesFirewallProvider(FirewallProvider):
    """
    Real iptables integration. Requires explicit opt-in via
    FIREWALL_MODE=iptables in settings AND requires the process to have
    the necessary privileges to run `iptables` — which it will NOT have
    in this development sandbox, and this class's methods are therefore
    UNTESTED against a real iptables installation in this environment.

    Every action is validated, logged (via the returned
    FirewallActionResult, which calling code is expected to pass to the
    audit logger), and fails safely: a subprocess failure is caught and
    reported as success=False with the error message, never raised as an
    uncaught exception that could crash the request handler.
    """

    def __init__(self) -> None:
        self._known_rules: dict[str, dict] = {}

    def block(self, ip: str, reason: str) -> FirewallActionResult:
        _validate_ip(ip)
        now = datetime.now(timezone.utc).isoformat()

        if ip in self._known_rules:
            return FirewallActionResult(
                ip=ip, action="block", mode="iptables", success=True,
                message=f"IP {ip} already has an active DROP rule; no duplicate created.",
                timestamp=now,
            )

        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            return FirewallActionResult(
                ip=ip, action="block", mode="iptables", success=False,
                message=f"Failed to apply iptables rule for {ip}: {e}",
                timestamp=now,
            )

        self._known_rules[ip] = {"reason": reason, "timestamp": now}
        return FirewallActionResult(
            ip=ip, action="block", mode="iptables", success=True,
            message=f"iptables DROP rule applied for {ip}. Reason: {reason}",
            timestamp=now,
        )

    def unblock(self, ip: str) -> FirewallActionResult:
        _validate_ip(ip)
        now = datetime.now(timezone.utc).isoformat()

        if ip not in self._known_rules:
            return FirewallActionResult(
                ip=ip, action="unblock", mode="iptables", success=True,
                message=f"IP {ip} has no known active rule; no action needed.",
                timestamp=now,
            )

        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=5,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError) as e:
            return FirewallActionResult(
                ip=ip, action="unblock", mode="iptables", success=False,
                message=f"Failed to remove iptables rule for {ip}: {e}",
                timestamp=now,
            )

        del self._known_rules[ip]
        return FirewallActionResult(
            ip=ip, action="unblock", mode="iptables", success=True,
            message=f"iptables DROP rule removed for {ip}.",
            timestamp=now,
        )

    def list_rules(self) -> list[dict]:
        return [
            {"ip": ip, "action": "block", "mode": "iptables", "reason": data["reason"], "timestamp": data["timestamp"]}
            for ip, data in self._known_rules.items()
        ]


def get_firewall_provider(mode: str) -> FirewallProvider:
    if mode == "iptables":
        return IptablesFirewallProvider()
    return SimulatedFirewallProvider()
