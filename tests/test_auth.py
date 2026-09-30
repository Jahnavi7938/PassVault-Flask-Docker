from app import db
from app.models import User
from conftest import STRONG_PW, login, register, signup_and_login


def test_registration_creates_hashed_user(app, client):
    r = register(client)
    assert r.status_code == 302 and "/login" in r.headers["Location"]
    with app.app_context():
        user = User.query.filter_by(username="alice").one()
        assert user.password_hash != STRONG_PW
        assert STRONG_PW not in user.password_hash
        assert user.check_password(STRONG_PW)


def test_duplicate_username_rejected(client):
    register(client, "alice", "a1@example.com")
    r = register(client, "Alice", "a2@example.com")   # usernames are case-insensitive
    assert r.status_code == 400 and b"taken" in r.data


def test_duplicate_email_rejected(client):
    register(client, "alice", "same@example.com")
    r = register(client, "bob", "SAME@example.com")
    assert r.status_code == 400 and b"already exists" in r.data


def test_weak_password_and_bad_email_rejected(client):
    assert register(client, password="short").status_code == 400
    assert register(client, email="not-an-email").status_code == 400


def test_password_mismatch_rejected(client):
    r = client.post("/register", data={"full_name": "A B", "username": "abc", "email": "a@b.co",
                                       "password": STRONG_PW, "confirm_password": STRONG_PW + "x"})
    assert r.status_code == 400 and b"don&#39;t match" in r.data


def test_login_success_by_username_and_email(client):
    register(client)
    r = login(client, "alice")
    assert r.status_code == 302 and "/dashboard" in r.headers["Location"]
    client.post("/logout")
    assert login(client, "alice@example.com").status_code == 302


def test_wrong_password_and_unknown_user_get_same_generic_message(client):
    register(client)
    wrong = login(client, "alice", "Wrong-Password-1!")
    unknown = login(client, "nobody", "Wrong-Password-1!")
    assert wrong.status_code == unknown.status_code == 401
    assert b"Invalid username/email or password." in wrong.data
    assert b"Invalid username/email or password." in unknown.data


def test_account_locks_after_repeated_failures(client):
    register(client)
    for _ in range(5):
        login(client, "alice", "Wrong-Password-1!")
    r = login(client, "alice", STRONG_PW)              # right password, but locked out
    assert r.status_code == 401 and b"Invalid username/email or password." in r.data


def test_logout_ends_session(client):
    signup_and_login(client)
    assert client.get("/dashboard").status_code == 200
    assert client.post("/logout").status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_protected_pages_redirect_to_login(client):
    for path in ("/dashboard", "/vault", "/vault/add", "/generator", "/security", "/profile", "/settings"):
        r = client.get(path)
        assert r.status_code == 302 and "/login" in r.headers["Location"], path


def test_api_requires_authentication(client):
    assert client.get("/api/vault").status_code == 401
    assert client.post("/api/vault", json={}).status_code == 401
    assert client.post("/api/vault/1/reveal").status_code == 401


def test_open_redirect_is_blocked(client):
    register(client)
    r = client.post("/login?next=//evil.example", data={"identifier": "alice", "password": STRONG_PW})
    assert "evil.example" not in r.headers["Location"]


def test_profile_email_change_needs_password(client):
    signup_and_login(client)
    r = client.post("/profile", data={"full_name": "Alice", "email": "new@example.com", "current_password": ""})
    assert r.status_code == 200 and b"current password" in r.data
    r = client.post("/profile", data={"full_name": "Alice", "email": "new@example.com", "current_password": STRONG_PW})
    assert r.status_code == 302
