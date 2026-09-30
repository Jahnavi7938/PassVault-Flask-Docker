import inspect
import string

import pytest

from app.services import password_generator as gen
from app.services.security_service import evaluate_strength, password_policy_errors


@pytest.mark.parametrize("n", [8, 20, 64])
def test_length_is_respected(n):
    assert len(gen.generate_random(n)["password"]) == n


def test_length_out_of_range_rejected():
    for bad in (7, 65):
        with pytest.raises(ValueError):
            gen.generate_random(bad)


def test_every_selected_group_is_present():
    for _ in range(200):
        pw = gen.generate_random(8)["password"]      # shortest length is the hardest case
        assert any(c in string.ascii_uppercase for c in pw)
        assert any(c in string.ascii_lowercase for c in pw)
        assert any(c in string.digits for c in pw)
        assert any(c in gen.SYMBOLS for c in pw)


def test_only_selected_groups_are_used():
    pw = gen.generate_random(40, upper=False, lower=False, digits=True, symbols=False)["password"]
    assert set(pw) <= set(string.digits)


def test_ambiguous_characters_excluded():
    for _ in range(100):
        assert not set(gen.generate_random(30, exclude_ambiguous=True)["password"]) & set("O0Il1")


def test_no_character_type_selected_is_an_error():
    with pytest.raises(ValueError):
        gen.generate_random(20, upper=False, lower=False, digits=False, symbols=False)


def test_uses_secrets_not_random():
    src = inspect.getsource(gen)
    assert "import secrets" in src and "secrets.choice" in src
    assert "import random" not in src and "random.choice" not in src and "Math.random" not in src


def test_outputs_are_not_repeated():
    assert len({gen.generate_random(20)["password"] for _ in range(300)}) == 300


def test_pin_and_memorable_modes():
    pin = gen.generate_pin(8)["password"]
    assert len(pin) == 8 and pin.isdigit()
    phrase = gen.generate_memorable(5)["password"]
    assert phrase.count("-") >= 5 and any(c.isdigit() for c in phrase)
    with pytest.raises(ValueError):
        gen.generate_pin(3)


def test_entropy_estimate_scales_with_length():
    assert gen.generate_random(32)["entropy"] > gen.generate_random(12)["entropy"]


def test_strength_calculation():
    assert evaluate_strength("")["label"] == "weak"
    assert evaluate_strength("aaaaaaaaaaaa")["label"] == "weak"
    assert evaluate_strength("Password123!")["label"] == "weak"        # common word, despite 4 classes
    assert evaluate_strength("qwerty123456")["label"] == "weak"
    assert evaluate_strength("xK9#mQ2$vL7@pR4!wZ8n")["label"] == "strong"
    assert evaluate_strength("xK9#mQ2$vL7@pR4!wZ8n")["score"] > evaluate_strength("Zq8#mL2x")["score"]


def test_registration_policy():
    assert password_policy_errors("Str0ng!Passw0rd#42") == []
    assert len(password_policy_errors("abc")) == 5


def test_generate_endpoint(client):
    r = client.post("/api/generate-password", json={"mode": "random", "length": 24, "symbols": False})
    body = r.get_json()
    assert r.status_code == 200 and len(body["password"]) == 24 and body["strength"] in ("weak", "medium", "strong")
    assert not any(c in gen.SYMBOLS for c in body["password"])
    assert client.post("/api/generate-password", json={"length": 3}).status_code == 400
    assert client.post("/api/generate-password", json={"mode": "banana"}).status_code == 400
    assert client.post("/api/generate-password", data="nope").status_code == 400
