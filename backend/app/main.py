"""
backend/app/main.py

Main FastAPI application. Wires together everything built in Phases 2-8:
- ML detection model (loaded from ml/models/ if present; None otherwise —
  see api/routes/detection.py for the resulting 503 behavior)
- Severity Engine (Phase 4)
- SAHE crypto engine (Phase 5/6)
- Firewall provider (simulated by default, per config)
- Audit logger (in-memory sink for this phase; Phase 10 adds MongoDB)

No MongoDB is available in this development environment, so several
routes use documented in-memory placeholders (see events.py, crypto.py's
envelope store) that Phase 10 will replace with real persistence.
"""
from __future__ import annotations

import joblib
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.app.config import get_settings
from backend.app.audit.audit_logger import AuditLogger, InMemoryAuditSink
from backend.app.firewall.provider import get_firewall_provider
from backend.app.database.mongodb import MongoManager
from backend.app.database.repositories import EventRepository
from backend.app.services.alert_service import AlertService
from backend.app.services.blocking_service import BlockingService
from backend.app.websocket.manager import manager as ws_manager
from crypto.sahe.engine import RecipientKeys
from crypto.algorithms import ecdh_x25519, rsa_oaep_hybrid, signatures

from backend.app.api.routes import health, detection, events, firewall, benchmark, websocket as ws_route
from backend.app.api.routes.crypto import router as crypto_policy_router, top_level_router as crypto_top_level_router


def _load_detection_model(model_dir: Path) -> dict | None:
    """
    Tries Random Forest first, then XGBoost. Returns None if neither
    exists — this is the expected state until real CICIDS2017 data is
    used to train a model (see docs/methodology/*.md). Never fabricates
    a model.
    """
    rf_path = model_dir / "random_forest.joblib"
    xgb_path = model_dir / "xgboost.joblib"

    if rf_path.exists():
        bundle = joblib.load(rf_path)
        bundle["model_name"] = "RandomForestClassifier"
        return bundle

    if xgb_path.exists():
        # XGBoost's saved bundle wraps model+label_encoder differently
        # (see ml/training/train_xgboost.py); wrap it the same way
        # api/routes/detection.py expects (a plain .predict()-capable
        # object plus feature_names).
        from ml.training.train_xgboost import DecodingXGBWrapper
        raw = joblib.load(xgb_path)
        wrapped = DecodingXGBWrapper(raw["model"], raw["label_encoder"])
        return {"model": wrapped, "feature_names": raw["feature_names"], "model_name": "XGBoostClassifier"}

    return None


def _generate_server_keys() -> RecipientKeys:
    """
    Generates one long-term server keypair set at startup, for all three
    crypto primitives SAHE may need. A real multi-tenant deployment would
    use a proper key manager (Phase 10+) with per-purpose or per-tenant
    keys instead of one global set — documented simplification for this
    phase's scope.
    """
    x25519_kp = ecdh_x25519.generate_keypair()
    rsa_kp = rsa_oaep_hybrid.generate_rsa_keypair()
    ed_kp = signatures.generate_keypair()
    return RecipientKeys(
        x25519_private_key=x25519_kp.private_key,
        x25519_public_key=x25519_kp.public_key,
        rsa_private_key=rsa_kp.private_key,
        rsa_public_key=rsa_kp.public_key,
        ed25519_private_key=ed_kp.private_key,
        ed25519_public_key=ed_kp.public_key,
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    app.state.settings = settings
    app.state.audit_logger = AuditLogger(InMemoryAuditSink())
    app.state.firewall_provider = get_firewall_provider(settings.firewall_mode)
    app.state.recipient_keys = _generate_server_keys()
    app.state.detection_model = _load_detection_model(Path(settings.ml_model_dir))
    app.state.connection_manager = ws_manager
    app.state.alert_service = AlertService(ws_manager, app.state.audit_logger)
    app.state.blocking_service = BlockingService(app.state.firewall_provider, app.state.audit_logger)

    # Attempt a real MongoDB connection. If it's unreachable (as is the
    # case in the development sandbox this project was built in — see
    # docs/methodology/mongodb.md), fall back to the in-memory placeholder
    # EXPLICITLY: app.state.event_repository stays None, and events.py
    # checks for that and uses its fallback store, tagging every response
    # with storage_backend so the difference is never silently hidden.
    mongo_manager = MongoManager(settings.mongodb_uri, settings.mongodb_db_name)
    try:
        mongo_manager.connect()
        # A cheap operation to actually verify the connection works,
        # rather than trusting that connect() (which is lazy for motor)
        # succeeded.
        await mongo_manager.db.command("ping")
        await mongo_manager.ensure_indexes()
        app.state.mongo_manager = mongo_manager
        app.state.event_repository = EventRepository(mongo_manager.db)
        print("MongoDB connection established; using real database storage.")
    except Exception as e:
        print(
            f"MongoDB unavailable ({e}); falling back to in-memory storage "
            f"for /events. This is expected in the development sandbox — "
            f"see docs/methodology/mongodb.md."
        )
        mongo_manager.close()
        app.state.mongo_manager = None
        app.state.event_repository = None

    yield

    if app.state.mongo_manager is not None:
        app.state.mongo_manager.close()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="SAHE Cloud IDS/IPS",
        description="Cloud-Based Intrusion Detection and Prevention System with Threat-Aware Adaptive Cryptographic Policy",
        version="0.15.0",  # Phase 15
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_allowed_origins_list,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(health.router)
    app.include_router(detection.router)
    app.include_router(events.router)
    app.include_router(crypto_top_level_router)
    app.include_router(crypto_policy_router)
    app.include_router(firewall.router)
    app.include_router(benchmark.router)
    app.include_router(ws_route.router)

    return app


app = create_app()
