import re

import pytest

from app import create_app
from conftest import ITEM, STRONG_PW, TEST_CONFIG, add_item, csrf_token, register, signup_and_login


def test_csrf_blocks_forms_and_api_without_token():
    app = create_app({**TEST_CONFIG, "WTF_CSRF_ENABLED": True})
    c = app.test_client()
    r = c.post("/register", data={"username": "x"})
    assert r.status_code == 400
    r = c.post("/api/generate-password", json={})
    assert r.status_code == 400 and r.get_json()["code"] == "csrf"


def test_csrf_accepts_a_valid_token():
    app = create_app({**TEST_CONFIG, "WTF_CSRF_ENABLED": True})
    c = app.test_client()
    token = csrf_token(c)
    r = c.post("/api/generate-password", json={}, headers={"X-CSRFToken": token})
    assert r.status_code == 200


def test_delete_requires_csrf_token():
    app = create_app({**TEST_CONFIG, "WTF_CSRF_ENABLED": True})
    c = app.test_client()
    token = csrf_token(c)
    c.post("/register", data={"full_name": "Alice E", "username": "alice", "email": "a@example.com",
                              "password": STRONG_PW, "confirm_password": STRONG_PW, "csrf_token": token})
    c.post("/login", data={"identifier": "alice", "password": STRONG_PW, "csrf_token": token})
    token = re.search(r'name="csrf-token" content="([^"]+)"', c.get("/dashboard").get_data(as_text=True)).group(1)
    hdr = {"X-CSRFToken": token}
    item_id = c.post("/api/vault", json=ITEM, headers=hdr).get_json()["item"]["id"]
    assert c.delete(f"/api/vault/{item_id}").status_code == 400          # no header
    assert c.delete(f"/api/vault/{item_id}", headers=hdr).status_code == 200


def test_invalid_vault_ids(client):
    signup_and_login(client)
    assert client.get("/api/vault/99999").status_code == 404
    assert client.put("/api/vault/99999", json={"title": "x"}).status_code == 404
    assert client.delete("/api/vault/99999").status_code == 404
    assert client.get("/api/vault/not-a-number").status_code == 404
    assert client.get("/vault/edit/99999").status_code == 404


def test_login_is_rate_limited():
    app = create_app({**TEST_CONFIG, "RATELIMIT_ENABLED": True, "LOGIN_RATE_LIMIT": "3 per minute"})
    c = app.test_client()
    env = {"REMOTE_ADDR": "10.9.8.7"}
    codes = [c.post("/login", data={"identifier": "x", "password": "y"}, environ_base=env).status_code for _ in range(5)]
    assert codes[:3] == [401, 401, 401]
    assert codes[3] == 429 and codes[4] == 429


def test_session_cookie_flags(client):
    register(client)
    r = client.post("/login", data={"identifier": "alice", "password": STRONG_PW})
    cookie = next(v for k, v in r.headers if k == "Set-Cookie" and v.startswith("passvault_session"))
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
    assert "Expires=" in cookie                     # permanent session -> idle timeout applies


def test_security_headers(client):
    r = client.get("/")
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert "'unsafe-inline'" not in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "Referrer-Policy" in r.headers


def test_responses_with_secrets_are_not_cacheable(client):
    signup_and_login(client)
    item_id = add_item(client).get_json()["item"]["id"]
    assert "no-store" in client.post(f"/api/vault/{item_id}/reveal").headers["Cache-Control"]


def test_locked_vault_blocks_reveal_until_unlocked(client):
    signup_and_login(client)
    item_id = add_item(client).get_json()["item"]["id"]
    assert client.post("/api/lock").status_code == 200
    r = client.post(f"/api/vault/{item_id}/reveal")
    assert r.status_code == 403 and r.get_json()["code"] == "vault_locked"
    assert client.get("/vault").status_code == 302                      # bounced to /unlock
    assert client.post("/unlock", data={"password": "wrong"}).status_code == 401
    assert client.post("/unlock", data={"password": STRONG_PW}).status_code == 302
    assert client.post(f"/api/vault/{item_id}/reveal").get_json()["password"] == ITEM["password"]


def test_security_report_finds_weak_reused_and_never_returns_passwords(client):
    signup_and_login(client)
    add_item(client, title="One", password="Tangerine!Bicycle-Orbit-2024")
    add_item(client, title="Two", password="Tangerine!Bicycle-Orbit-2024")
    add_item(client, title="Weak", password="abc")
    body = client.get("/api/security-report").get_data(as_text=True)
    report = client.get("/api/security-report").get_json()
    assert report["total"] == 3 and report["reused"] == 2 and report["weak"] == 1
    assert 0 <= report["health"] <= 100 and report["recommendations"]
    assert "Tangerine!Bicycle" not in body
    page = client.get("/security")
    assert page.status_code == 200 and b"Tangerine!Bicycle" not in page.data


def test_xss_in_titles_is_escaped(client):
    signup_and_login(client)
    item_id = add_item(client, title="<script>alert(1)</script>").get_json()["item"]["id"]
    html = client.get(f"/vault/edit/{item_id}").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


def test_error_pages_do_not_leak_details(client):
    r = client.get("/definitely-not-a-page")
    assert r.status_code == 404 and b"Traceback" not in r.data
    assert client.get("/api/nope").get_json()["error"]
