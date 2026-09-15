import os
import pytest
from fastapi.testclient import TestClient

# Set before importing app modules so Settings() picks it up.
os.environ.setdefault("API_AUTH_TOKEN", "test-token-for-pytest")


@pytest.fixture
def client():
    from backend.app.main import create_app
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def auth_headers():
    return {"Authorization": "Bearer test-token-for-pytest"}
