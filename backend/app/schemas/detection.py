"""
backend/app/schemas/detection.py

Request/response schemas for the /detect endpoint.
"""
from __future__ import annotations

from pydantic import BaseModel, Field


class DetectionRequest(BaseModel):
    """
    Represents a single flow's already-extracted numeric features, in the
    same feature space Phase 1's preprocessing pipeline produces. This
    endpoint does NOT do feature extraction from raw packets — that is
    out of scope for Phase 9 (see docs/architecture/phases.md's Phase 9
    notes) and would be a `nice-to-have` live-Scapy-capture extension.
    """
    features: dict[str, float] = Field(..., description="Feature name -> value, matching the trained model's feature_names.")
    source_ip: str | None = Field(
        default=None,
        description="Source IP of the flow, if known. Required for automatic blocking (Phase 12) to have a target — without it, a malicious detection still alerts but cannot be auto-blocked.",
    )


class DetectionResponse(BaseModel):
    attack_type: str
    confidence: float
    is_malicious: bool
    severity: str
    severity_rationale: str
    model_used: str
    event_id: str | None = Field(
        default=None,
        description="Set only for malicious detections, which raise a real-time alert via AlertService (Phase 11). None for benign detections.",
    )
    auto_block_triggered: bool = Field(
        default=False,
        description="True if this detection's severity met the auto-block threshold AND a source_ip was provided AND the block was attempted (see BlockingService, Phase 12). Does not imply the block succeeded — check auto_block_message.",
    )
    auto_block_message: str | None = Field(
        default=None,
        description="Explains the auto-block decision: why it was/wasn't triggered, or the result of the block attempt.",
    )
