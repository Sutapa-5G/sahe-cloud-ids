"""
backend/app/api/routes/firewall.py

/firewall/block, /firewall/unblock, /firewall/rules. Protected by
require_auth. Uses whichever FirewallProvider is configured on
app.state (defaults to SimulatedFirewallProvider — see main.py).
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from backend.app.api.auth import require_auth
from backend.app.schemas.firewall import (
    BlockRequest,
    UnblockRequest,
    FirewallActionResponse,
    FirewallRuleEntry,
)

router = APIRouter(prefix="/firewall", tags=["firewall"])


@router.post("/block", response_model=FirewallActionResponse, dependencies=[Depends(require_auth)])
async def block_ip(body: BlockRequest, request: Request) -> FirewallActionResponse:
    provider = request.app.state.firewall_provider
    audit_logger = request.app.state.audit_logger

    result = provider.block(body.ip, body.reason)
    audit_logger.log_firewall_action(result.action, result.ip, result.mode)

    return FirewallActionResponse(
        ip=result.ip, action=result.action, mode=result.mode,
        success=result.success, message=result.message,
    )


@router.post("/unblock", response_model=FirewallActionResponse, dependencies=[Depends(require_auth)])
async def unblock_ip(body: UnblockRequest, request: Request) -> FirewallActionResponse:
    provider = request.app.state.firewall_provider
    audit_logger = request.app.state.audit_logger

    result = provider.unblock(body.ip)
    audit_logger.log_firewall_action(result.action, result.ip, result.mode)

    return FirewallActionResponse(
        ip=result.ip, action=result.action, mode=result.mode,
        success=result.success, message=result.message,
    )


@router.get("/rules", response_model=list[FirewallRuleEntry])
async def list_rules(request: Request) -> list[FirewallRuleEntry]:
    provider = request.app.state.firewall_provider
    rules = provider.list_rules()
    return [FirewallRuleEntry(**r) for r in rules]
