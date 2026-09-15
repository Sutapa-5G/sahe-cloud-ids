"""
backend/app/config.py

Application configuration, loaded from environment variables / .env.
Mirrors the keys already defined in the repo root's .env.example — this
file is the typed, validated interface to those values.

No secrets have default values that look like real credentials; the
defaults here are safe local-development placeholders only.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- MongoDB ---
    mongodb_uri: str = "mongodb://localhost:27017"
    mongodb_db_name: str = "sahe_ids"

    # --- App ---
    app_env: str = "development"
    log_level: str = "INFO"

    # --- ML ---
    cicids2017_data_path: str = "./ml/data/raw"
    ml_model_dir: str = "./ml/models"

    # --- SAHE thresholds (bytes) ---
    sahe_small_threshold_bytes: int = 100 * 1024
    sahe_large_threshold_bytes: int = 1024 * 1024

    # --- SAHE cost function weights ---
    sahe_weight_latency: float = 0.30
    sahe_weight_cpu: float = 0.20
    sahe_weight_memory: float = 0.10
    sahe_weight_storage: float = 0.10
    sahe_weight_security: float = 0.30

    # --- Key management (prototype only) ---
    key_store_path: str = "./backend/app/crypto/.keystore_dev"

    # --- Firewall ---
    firewall_mode: str = "simulated"  # simulated | iptables

    # --- Auth (Phase 9 stub; see api/auth.py) ---
    # A real deployment MUST override this via .env — it is intentionally
    # NOT a usable secret by default, so an unconfigured deployment fails
    # closed (auth.py rejects all requests) rather than failing open.
    api_auth_token: str | None = None

    # --- CORS (Phase 15) ---
    # Comma-separated list of allowed origins for the dashboard frontend.
    # Defaults cover the standard local dev setup (Vite on 5173) and the
    # docker-compose frontend port. Override via CORS_ALLOWED_ORIGINS in
    # .env for a real deployment — this default list is NOT safe to rely
    # on in production (e.g. it doesn't include a real domain).
    cors_allowed_origins: str = "http://localhost:5173,http://127.0.0.1:5173"

    @property
    def cors_allowed_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]


_settings: Settings | None = None


def get_settings() -> Settings:
    """
    Cached settings accessor. Using a function (rather than a
    module-level instance) makes it easy to override in tests via
    dependency injection (see backend/tests/conftest.py).
    """
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
