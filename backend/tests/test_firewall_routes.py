def test_block_requires_auth(client):
    r = client.post("/firewall/block", json={"ip": "10.0.0.1", "reason": "test"})
    assert r.status_code == 401


def test_block_unblock_roundtrip(client, auth_headers):
    r = client.post("/firewall/block", json={"ip": "10.0.0.9", "reason": "test attack"}, headers=auth_headers)
    assert r.status_code == 200
    body = r.json()
    assert body["success"] is True
    assert body["mode"] == "simulated"

    r2 = client.get("/firewall/rules")
    assert any(rule["ip"] == "10.0.0.9" for rule in r2.json())

    r3 = client.post("/firewall/unblock", json={"ip": "10.0.0.9"}, headers=auth_headers)
    assert r3.status_code == 200

    r4 = client.get("/firewall/rules")
    assert not any(rule["ip"] == "10.0.0.9" for rule in r4.json())


def test_block_invalid_ip_rejected(client, auth_headers):
    r = client.post("/firewall/block", json={"ip": "not-an-ip-address", "reason": "test"}, headers=auth_headers)
    assert r.status_code == 422


def test_block_duplicate_does_not_error(client, auth_headers):
    r1 = client.post("/firewall/block", json={"ip": "10.0.0.20", "reason": "first"}, headers=auth_headers)
    assert r1.status_code == 200
    r2 = client.post("/firewall/block", json={"ip": "10.0.0.20", "reason": "second"}, headers=auth_headers)
    assert r2.status_code == 200
    assert "already blocked" in r2.json()["message"]


def test_rules_list_is_public(client):
    r = client.get("/firewall/rules")
    assert r.status_code == 200
    assert isinstance(r.json(), list)
