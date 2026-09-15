"""
backend/app/services/blocking_service.py

Phase 12: encapsulates the POLICY of when a detection should trigger an
automatic firewall block, separate from the MECHANISM of how blocking
happens (that's firewall/provider.py, unchanged from Phase 9).

Documented policy (mirrors the severity-driven caution already used for
SAHE's signature policy — narrow and explicit, not "any malicious
detection blocks immediately"):

  - Auto-block triggers ONLY for HIGH or CRITICAL severity detections.
  - LOW/MEDIUM severity detections alert (Phase 11) but do NOT
    auto-block — an operator should review before taking action, since
    over-eager auto-blocking on lower-confidence/lower-impact detections
    risks blocking legitimate traffic (a false-positive cost this
    project has not measured, since no real CICIDS2017 evaluation has
    been run yet — see docs/methodology/*.md).
  - A detection with no source_ip cannot be auto-blocked (there is
    nothing to block) — this is reported explicitly, not silently
    skipped without explanation.

This policy is intentionally conservative and, like the severity impact
table in Phase 4, is a documented starting point for the project team to
review — not asserted as objectively correct.
"""
from __future__ import annotations

from dataclasses import dataclass

from backend.app.audit.audit_logger import AuditLogger
from backend.app.firewall.provider import FirewallProvider
from ml.severity.severity_engine import Severity

AUTO_BLOCK_SEVERITIES = {Severity.HIGH, Severity.CRITICAL}


@dataclass
class BlockingDecision:
    should_block: bool
    reason: str
    action_taken: bool = False
    action_success: bool | None = None
    action_message: str | None = None


class BlockingService:
    def __init__(self, firewall_provider: FirewallProvider, audit_logger: AuditLogger):
        self._firewall_provider = firewall_provider
        self._audit_logger = audit_logger

    def evaluate(self, severity: Severity, source_ip: str | None) -> BlockingDecision:
        """
        Decides whether THIS detection should be auto-blocked, without
        performing the block yet — split from `enforce()` so the policy
        decision is independently testable/inspectable (e.g. for the
        dashboard to preview "would this have been blocked?").
        """
        if severity not in AUTO_BLOCK_SEVERITIES:
            return BlockingDecision(
                should_block=False,
                reason=f"Severity {severity.name} is below the auto-block threshold "
                       f"({[s.name for s in AUTO_BLOCK_SEVERITIES]}); alert-only.",
            )
        if source_ip is None:
            return BlockingDecision(
                should_block=False,
                reason=f"Severity {severity.name} qualifies for auto-block, but no "
                       f"source_ip was provided with the detection — nothing to block.",
            )
        return BlockingDecision(
            should_block=True,
            reason=f"Severity {severity.name} meets the auto-block threshold and a source_ip was provided.",
        )

    def enforce(
        self,
        severity: Severity,
        source_ip: str | None,
        attack_type: str,
        correlation_id: str | None = None,
    ) -> BlockingDecision:
        """
        Evaluates the policy AND performs the block if warranted. Every
        outcome (blocked, not-blocked-due-to-severity,
        not-blocked-due-to-missing-ip, or a failed block attempt) is
        logged to the audit trail — silence is never an acceptable
        outcome for a security-relevant decision.
        """
        decision = self.evaluate(severity, source_ip)

        if not decision.should_block:
            self._audit_logger.log_firewall_action(
                action="auto_block_skipped", ip=source_ip or "unknown",
                mode=self._firewall_provider.__class__.__name__,
                correlation_id=correlation_id,
            )
            return decision

        result = self._firewall_provider.block(source_ip, reason=f"auto-block: {attack_type} ({severity.name})")
        decision.action_taken = True
        decision.action_success = result.success
        decision.action_message = result.message

        self._audit_logger.log_firewall_action(
            action=result.action, ip=result.ip, mode=result.mode, correlation_id=correlation_id,
        )

        return decision
