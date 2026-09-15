"""
backend/app/api/routes/detection.py

/detect endpoint. Loads a trained model (Phase 2's Random Forest or
Phase 3's XGBoost) from ml/models/ if one exists, and returns a clear
503 if not — this project has NOT yet trained a model on real
CICIDS2017 data (see docs/methodology/*.md), so in a fresh checkout of
this repo, this endpoint will correctly report "no model available"
rather than fabricate a prediction.
"""
from __future__ import annotations

import pandas as pd
from fastapi import APIRouter, HTTPException, Request, status

from backend.app.schemas.detection import DetectionRequest, DetectionResponse
from ml.severity.severity_engine import SeverityEngine

router = APIRouter(tags=["detection"])

_severity_engine = SeverityEngine()


@router.post("/detect", response_model=DetectionResponse)
async def detect(body: DetectionRequest, request: Request) -> DetectionResponse:
    model_bundle = request.app.state.detection_model

    if model_bundle is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                "No trained detection model is loaded. This project has "
                "not yet trained a model on real CICIDS2017 data (the "
                "dataset was unavailable during development — see "
                "docs/methodology/preprocessing.md). Train a model via "
                "'python -m ml.training.run_random_forest' or "
                "'run_xgboost.py' against real processed data, place the "
                "resulting .joblib file in ml/models/, and restart the "
                "backend."
            ),
        )

    model = model_bundle["model"]
    feature_names = model_bundle["feature_names"]

    missing = [f for f in feature_names if f not in body.features]
    if missing:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Request is missing required features: {missing}",
        )

    X = pd.DataFrame([{f: body.features[f] for f in feature_names}])

    prediction = model.predict(X)[0]
    confidence = 1.0
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        classes = list(getattr(model, "classes_", []))
        if prediction in classes:
            confidence = float(proba[classes.index(prediction)])

    severity_decision = _severity_engine.assess(str(prediction), confidence)
    is_malicious = str(prediction) != "BENIGN"

    event_id = None
    auto_block_triggered = False
    auto_block_message = None

    if is_malicious:
        alert_service = request.app.state.alert_service
        alert = await alert_service.raise_alert(
            attack_type=str(prediction),
            confidence=confidence,
            severity=severity_decision.final_severity.name,
        )
        event_id = alert.event_id

        blocking_service = request.app.state.blocking_service
        blocking_decision = blocking_service.enforce(
            severity=severity_decision.final_severity,
            source_ip=body.source_ip,
            attack_type=str(prediction),
            correlation_id=event_id,
        )
        auto_block_triggered = blocking_decision.action_taken
        auto_block_message = blocking_decision.action_message or blocking_decision.reason
    else:
        # Benign detections are logged but do NOT broadcast an alert or
        # create an event record, matching the architecture: BENIGN ->
        # normal logging only (see docs/architecture/overview.md).
        audit_logger = request.app.state.audit_logger
        audit_logger.log_detection(str(prediction), confidence)
        audit_logger.log_severity_assignment(severity_decision.to_dict())

    return DetectionResponse(
        attack_type=str(prediction),
        confidence=confidence,
        is_malicious=is_malicious,
        severity=severity_decision.final_severity.name,
        severity_rationale=severity_decision.rationale,
        model_used=model_bundle.get("model_name", "unknown"),
        event_id=event_id,
        auto_block_triggered=auto_block_triggered,
        auto_block_message=auto_block_message,
    )
