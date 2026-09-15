import base64


def test_policy_preview_no_auth_required(client):
    r = client.post("/crypto/policy", json={"payload_size_bytes": 1024, "severity": "LOW", "data_type": "LOG"})
    assert r.status_code == 200
    body = r.json()
    assert body["key_establishment_method"] == "ECDH_X25519"
    assert body["requires_signature"] is False


def test_policy_preview_audit_critical_requires_signature(client):
    r = client.post("/crypto/policy", json={"payload_size_bytes": 1024, "severity": "CRITICAL", "data_type": "AUDIT"})
    assert r.status_code == 200
    assert r.json()["requires_signature"] is True


def test_policy_preview_invalid_severity_rejected(client):
    r = client.post("/crypto/policy", json={"payload_size_bytes": 1024, "severity": "NOT_A_SEVERITY", "data_type": "LOG"})
    assert r.status_code == 422


def test_policy_preview_negative_size_rejected(client):
    r = client.post("/crypto/policy", json={"payload_size_bytes": -1, "severity": "LOW", "data_type": "LOG"})
    assert r.status_code == 422


def test_encrypt_requires_auth(client):
    r = client.post("/encrypt", json={"plaintext_base64": "aGVsbG8=", "severity": "LOW", "data_type": "LOG"})
    assert r.status_code == 401


def test_encrypt_decrypt_roundtrip(client, auth_headers):
    plaintext = b"integration test payload"
    r = client.post(
        "/encrypt",
        json={
            "plaintext_base64": base64.b64encode(plaintext).decode(),
            "severity": "HIGH",
            "data_type": "ALERT",
        },
        headers=auth_headers,
    )
    assert r.status_code == 200
    envelope_id = r.json()["envelope_id"]

    r2 = client.post("/decrypt", json={"envelope_id": envelope_id}, headers=auth_headers)
    assert r2.status_code == 200
    recovered = base64.b64decode(r2.json()["plaintext_base64"])
    assert recovered == plaintext


def test_encrypt_wrong_token_rejected(client):
    r = client.post(
        "/encrypt",
        json={"plaintext_base64": "aGVsbG8=", "severity": "LOW", "data_type": "LOG"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r.status_code == 401


def test_decrypt_unknown_envelope_id_404(client, auth_headers):
    r = client.post("/decrypt", json={"envelope_id": "does-not-exist"}, headers=auth_headers)
    assert r.status_code == 404


def test_encrypt_invalid_base64_rejected(client, auth_headers):
    r = client.post(
        "/encrypt",
        json={"plaintext_base64": "not valid base64!!!", "severity": "LOW", "data_type": "LOG"},
        headers=auth_headers,
    )
    assert r.status_code == 422


def test_audit_critical_encryption_produces_signature(client, auth_headers):
    plaintext = b"audit trail entry"
    r = client.post(
        "/encrypt",
        json={
            "plaintext_base64": base64.b64encode(plaintext).decode(),
            "severity": "CRITICAL",
            "data_type": "AUDIT",
        },
        headers=auth_headers,
    )
    assert r.status_code == 200
    body = r.json()
    assert body["requires_signature"] is True
    assert body["signature_base64"] is not None

    r2 = client.post("/decrypt", json={"envelope_id": body["envelope_id"]}, headers=auth_headers)
    assert r2.status_code == 200
    assert base64.b64decode(r2.json()["plaintext_base64"]) == plaintext
