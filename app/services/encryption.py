"""Vault encryption.

Key hierarchy
-------------
VAULT_ENCRYPTION_KEY (from .env)
   --scrypt--> master key (cached in memory per process)
   --HKDF(salt = this user's key_salt)--> per-user Fernet key

Fernet is AES-128-CBC + HMAC-SHA256, i.e. authenticated encryption: a tampered
ciphertext is rejected instead of decrypting to garbage.

The user's *login* password is never involved. It is only ever stored as a
Werkzeug hash. The trade-off is that whoever holds the server's .env can decrypt
vault data - see the README's security model section.
"""
import base64
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from flask import current_app


class DecryptionError(Exception):
    pass


@lru_cache(maxsize=4)
def _master_key(secret: str) -> bytes:
    # Slow on purpose, but only runs once per process. Makes a weak passphrase in
    # .env harder to brute-force if someone gets hold of the database alone.
    kdf = Scrypt(salt=b"passvault/master/v1", length=32, n=2**14, r=8, p=1)
    return kdf.derive(secret.encode("utf-8"))


def _fernet_for(user) -> Fernet:
    master = _master_key(current_app.config["VAULT_ENCRYPTION_KEY"])
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=bytes.fromhex(user.key_salt),
        info=b"passvault/user-vault-key/v1",
    )
    return Fernet(base64.urlsafe_b64encode(hkdf.derive(master)))


def encrypt(user, plaintext: str) -> str:
    return _fernet_for(user).encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt(user, token: str) -> str:
    try:
        return _fernet_for(user).decrypt(token.encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as exc:
        raise DecryptionError("Could not decrypt this item (wrong key or corrupted data).") from exc
