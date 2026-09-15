def test_allowed_origin_gets_cors_header(client):
    r = client.get("/health", headers={"Origin": "http://localhost:5173"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") == "http://localhost:5173"


def test_disallowed_origin_gets_no_cors_header(client):
    r = client.get("/health", headers={"Origin": "http://evil.example.com"})
    assert r.status_code == 200  # request still succeeds server-side
    assert r.headers.get("access-control-allow-origin") is None  # browser would block it


def test_cors_origins_list_parses_comma_separated(monkeypatch):
    import backend.app.config as config_module
    config_module._settings = None
    monkeypatch.setenv("CORS_ALLOWED_ORIGINS", "http://a.com, http://b.com ,http://c.com")
    settings = config_module.get_settings()
    assert settings.cors_allowed_origins_list == ["http://a.com", "http://b.com", "http://c.com"]
    config_module._settings = None
