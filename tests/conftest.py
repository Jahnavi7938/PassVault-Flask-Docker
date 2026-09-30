import re

import pytest

from app import create_app, db

STRONG_PW = "Str0ng!Passw0rd#42"

TEST_CONFIG = {
    "TESTING": True,
    "SECRET_KEY": "test-secret-key-not-for-production",
    "VAULT_ENCRYPTION_KEY": "test-vault-key-not-for-production",
    "SQLALCHEMY_DATABASE_URI": "sqlite://",   # in-memory
    "WTF_CSRF_ENABLED": False,
    "RATELIMIT_ENABLED": False,
    "SESSION_COOKIE_SECURE": False,
}


@pytest.fixture()
def app():
    app = create_app(dict(TEST_CONFIG))
    yield app
    with app.app_context():
        db.session.remove()
        db.drop_all()


@pytest.fixture()
def client(app):
    return app.test_client()


def register(client, username="alice", email=None, password=STRONG_PW, full_name="Alice Example"):
    return client.post("/register", data={
        "full_name": full_name, "username": username, "email": email or f"{username}@example.com",
        "password": password, "confirm_password": password,
    })


def login(client, identifier="alice", password=STRONG_PW):
    return client.post("/login", data={"identifier": identifier, "password": password})


def signup_and_login(client, username="alice"):
    assert register(client, username).status_code == 302
    assert login(client, username).status_code == 302
    return client


def csrf_token(client):
    html = client.get("/login").get_data(as_text=True)
    return re.search(r'name="csrf-token" content="([^"]+)"', html).group(1)


ITEM = {"title": "GitHub", "website_url": "https://github.com", "username": "alice@example.com",
        "password": "Sup3r!Secret-Value-99", "notes": "recovery codes in the safe", "category": "Work"}


def add_item(client, **overrides):
    return client.post("/api/vault", json={**ITEM, **overrides})
