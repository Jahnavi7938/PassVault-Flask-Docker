from app import db
from app.models import VaultItem
from app.services.encryption import decrypt
from app.models import User
from conftest import ITEM, add_item, signup_and_login


def test_create_read_update_delete(client):
    signup_and_login(client)
    created = add_item(client)
    assert created.status_code == 201
    item_id = created.get_json()["item"]["id"]

    listing = client.get("/api/vault").get_json()
    assert listing["count"] == 1 and listing["items"][0]["title"] == "GitHub"

    detail = client.get(f"/api/vault/{item_id}").get_json()["item"]
    assert detail["notes"] == ITEM["notes"]

    upd = client.put(f"/api/vault/{item_id}", json={"title": "GitHub (work)", "password": "An0ther!Strong-Pass-77"})
    assert upd.status_code == 200 and upd.get_json()["item"]["title"] == "GitHub (work)"
    assert client.post(f"/api/vault/{item_id}/reveal").get_json()["password"] == "An0ther!Strong-Pass-77"

    assert client.delete(f"/api/vault/{item_id}").status_code == 200
    assert client.get(f"/api/vault/{item_id}").status_code == 404


def test_update_without_password_keeps_old_one(client):
    signup_and_login(client)
    item_id = add_item(client).get_json()["item"]["id"]
    client.put(f"/api/vault/{item_id}", json={"username": "changed", "password": ""})
    assert client.post(f"/api/vault/{item_id}/reveal").get_json()["password"] == ITEM["password"]


def test_password_is_encrypted_in_the_database(app, client):
    signup_and_login(client)
    item_id = add_item(client).get_json()["item"]["id"]
    with app.app_context():
        item = db.session.get(VaultItem, item_id)
        assert ITEM["password"] not in item.encrypted_password
        assert ITEM["notes"] not in item.notes
        assert decrypt(db.session.get(User, item.user_id), item.encrypted_password) == ITEM["password"]


def test_ciphertext_is_bound_to_the_owner_key(app, client):
    from app.services.encryption import DecryptionError, encrypt
    import pytest
    signup_and_login(client, "alice")
    with app.app_context():
        alice = User.query.filter_by(username="alice").one()
        token = encrypt(alice, "secret")
        other = User(full_name="Bob", username="bob", email="bob@example.com", password_hash="x", key_salt="ab" * 16)
        with pytest.raises(DecryptionError):
            decrypt(other, token)
        with pytest.raises(DecryptionError):
            decrypt(alice, token[:-3] + "AAA")   # tampering is detected


def test_list_and_detail_never_contain_the_password(client):
    signup_and_login(client)
    item_id = add_item(client).get_json()["item"]["id"]
    assert ITEM["password"] not in client.get("/api/vault").get_data(as_text=True)
    assert ITEM["password"] not in client.get(f"/api/vault/{item_id}").get_data(as_text=True)
    assert ITEM["password"] not in client.get("/vault").get_data(as_text=True)
    assert ITEM["password"] not in client.get(f"/vault/edit/{item_id}").get_data(as_text=True)
    assert ITEM["password"] not in client.get("/dashboard").get_data(as_text=True)


def test_user_a_cannot_access_user_b_vault_item(app):
    a, b = app.test_client(), app.test_client()
    signup_and_login(a, "alice")
    signup_and_login(b, "bob")
    item_id = add_item(b).get_json()["item"]["id"]        # Bob's credential

    for method, url, kwargs in [
        ("get", f"/api/vault/{item_id}", {}),
        ("put", f"/api/vault/{item_id}", {"json": {"title": "hijacked"}}),
        ("delete", f"/api/vault/{item_id}", {}),
        ("post", f"/api/vault/{item_id}/reveal", {}),
        ("post", f"/api/vault/{item_id}/copy", {}),
        ("get", f"/vault/edit/{item_id}", {}),
    ]:
        r = getattr(a, method)(url, **kwargs)
        assert r.status_code in (403, 404), (method, url, r.status_code)
        assert ITEM["password"] not in r.get_data(as_text=True)

    assert a.get("/api/vault").get_json()["count"] == 0        # not even listed
    assert b.get(f"/api/vault/{item_id}").get_json()["item"]["title"] == "GitHub"   # untouched


def test_client_supplied_user_id_is_ignored(app):
    a, b = app.test_client(), app.test_client()
    signup_and_login(a, "alice")
    signup_and_login(b, "bob")
    add_item(a, user_id=2)                                   # try to plant it in Bob's vault
    assert b.get("/api/vault").get_json()["count"] == 0
    assert a.get("/api/vault").get_json()["count"] == 1


def test_validation_errors(client):
    signup_and_login(client)
    r = add_item(client, title="", password="")
    assert r.status_code == 400 and "title" in r.get_json()["fields"] and "password" in r.get_json()["fields"]
    assert add_item(client, category="Nope").status_code == 400
    assert add_item(client, website_url="javascript:alert(1)").status_code == 400


def test_search_and_filters(client):
    signup_and_login(client)
    add_item(client, title="GitHub", category="Work")
    add_item(client, title="MyBank", category="Banking", username="bob", password="abc")
    assert client.get("/api/vault?q=bank").get_json()["count"] == 1
    assert client.get("/api/vault?q=bob").get_json()["count"] == 1
    assert client.get("/api/vault?category=Work").get_json()["count"] == 1
    assert client.get("/api/vault?filter=weak").get_json()["items"][0]["title"] == "MyBank"
    assert client.get("/api/vault?q=%25").get_json()["count"] == 0        # % is not a wildcard
    assert client.get("/api/vault?filter=recent").get_json()["count"] == 2
