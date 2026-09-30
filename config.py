"""Configuration. Every secret comes from the environment (.env), never from source."""
import os
import secrets
from datetime import timedelta
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent
ENV_PATH = BASE_DIR / ".env"


def ensure_env_file():
    """First-run convenience: create a .env with fresh random secrets if none exists.

    The secrets are written to the file only - they are not printed or logged.
    """
    if ENV_PATH.exists():
        return False
    lines = [
        f"SECRET_KEY={secrets.token_urlsafe(64)}",
        f"VAULT_ENCRYPTION_KEY={secrets.token_urlsafe(48)}",
        "DATABASE_URL=sqlite:///instance/passvault.db",
        "SESSION_COOKIE_SECURE=false",
        "SESSION_LIFETIME_MINUTES=30",
        "LOGIN_RATE_LIMIT=5 per minute",
        "DEBUG=false",
    ]
    ENV_PATH.write_text("\n".join(lines) + "\n", encoding="utf-8")
    try:
        os.chmod(ENV_PATH, 0o600)
    except OSError:
        pass  # chmod is a no-op on Windows
    print("[PassVault] Created a new .env with random secrets.")
    print("[PassVault] Back up VAULT_ENCRYPTION_KEY - without it saved passwords cannot be decrypted.")
    return True


def _flag(name, default="false"):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


def _resolve_db_url(url):
    """Only SQLite is supported. Relative paths are anchored at the project root
    (Flask-SQLAlchemy would otherwise put them inside instance/instance/)."""
    prefix = "sqlite:///"
    if not url.startswith(prefix):
        raise RuntimeError("PassVault only supports SQLite. DATABASE_URL must start with sqlite:///")
    path = url[len(prefix):]
    if path in ("", ":memory:"):
        return url
    p = Path(path)
    if not p.is_absolute():
        p = BASE_DIR / p
    p.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{p.as_posix()}"


class Config:
    def __init__(self):
        load_dotenv(ENV_PATH)
        env = os.environ
        self.SECRET_KEY = env.get("SECRET_KEY", "")
        self.VAULT_ENCRYPTION_KEY = env.get("VAULT_ENCRYPTION_KEY", "")
        self.SQLALCHEMY_DATABASE_URI = _resolve_db_url(env.get("DATABASE_URL", "sqlite:///instance/passvault.db"))
        self.SQLALCHEMY_TRACK_MODIFICATIONS = False
        self.DEBUG = _flag("DEBUG")

        secure = _flag("SESSION_COOKIE_SECURE")
        self.SESSION_COOKIE_NAME = "passvault_session"
        self.SESSION_COOKIE_HTTPONLY = True
        self.SESSION_COOKIE_SAMESITE = "Lax"
        self.SESSION_COOKIE_SECURE = secure
        self.REMEMBER_COOKIE_HTTPONLY = True
        self.REMEMBER_COOKIE_SAMESITE = "Lax"
        self.REMEMBER_COOKIE_SECURE = secure
        self.REMEMBER_COOKIE_DURATION = timedelta(days=14)
        self.PERMANENT_SESSION_LIFETIME = timedelta(minutes=int(env.get("SESSION_LIFETIME_MINUTES", "30")))

        self.WTF_CSRF_TIME_LIMIT = None  # token lives as long as the session
        self.MAX_CONTENT_LENGTH = 64 * 1024

        self.RATELIMIT_STORAGE_URI = "memory://"
        self.RATELIMIT_ENABLED = True
        self.LOGIN_RATE_LIMIT = env.get("LOGIN_RATE_LIMIT", "5 per minute")

        self.MAX_FAILED_LOGINS = 5
        self.LOCKOUT_MINUTES = 10
        self.OLD_PASSWORD_DAYS = 180
