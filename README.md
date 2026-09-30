# PassVault

A small, self-hosted password manager and password generator. Flask + SQLite on the back end; plain HTML, CSS and JavaScript on the front end.

## 🌐 Live Demo

🚀 **Visit the live website:**

👉 [**PassVault – Live Website**](https://passvault-flask-docker.onrender.com/)

## Overview

You register an account, sign in, and get a personal vault. You can generate strong passwords or write your own, store them encrypted, search them, reveal or copy them when you need them, and check the vault for weak, reused and stale passwords. Every user only ever sees their own records.

It is meant to be read, run and learned from. It has not been through an external security audit - see *Limitations* before trusting it with anything you can't afford to lose.

## Features

- Registration with live strength feedback, duplicate username/email checks, and a 12-character policy (upper, lower, number, symbol)
- Login by username or email, remember-me, brute-force protection (per-IP rate limit **and** temporary account lockout), identical error message for every failure
- Idle session expiry, manual "Lock vault", and browser-side auto-lock (configurable)
- Password generator: random, memorable (word-based) and PIN modes, length 8-64, character-type toggles, "exclude ambiguous" (`O 0 I l 1`), entropy estimate, strength meter
- Vault: add, view, edit, delete, search (website / username / category), filters (strong / medium / weak / recent)
- Reveal and copy happen per item, on request; revealed passwords re-hide themselves; the clipboard is cleared after a delay
- Security dashboard: weak, reused, old passwords and an overall health score, with recommendations
- Profile (name, email, password change) and settings (theme, timeouts)
- Dark theme by default, light theme optional, responsive down to phones (the vault becomes cards)

## Technology stack

| Layer | Used |
|---|---|
| Front end | HTML5, CSS3, vanilla JavaScript, Fetch API. No framework, no CSS library, no CDN, no external fonts |
| Back end | Python 3, Flask |
| Database | SQLite through SQLAlchemy (Flask-SQLAlchemy) |
| Auth | Flask-Login, Werkzeug password hashing (scrypt), Flask-WTF CSRF, Flask-Limiter |
| Crypto | `cryptography` (Fernet, HKDF, scrypt), Python `secrets` |

## Project architecture

```
PassVault/
├── app.py                  entry point (python app.py)
├── config.py               reads .env, builds Flask config
├── app/
│   ├── __init__.py         app factory, security headers, error handlers
│   ├── models/             User, VaultItem
│   ├── routes/             auth, dashboard, vault (pages), generator, security, profile, api (JSON)
│   ├── services/           encryption.py, password_generator.py, security_service.py
│   ├── templates/          Jinja2 pages
│   └── static/             css/, js/, img/
└── tests/                  pytest suite
```

Pages are rendered by Flask. Anything that touches vault data goes through the JSON API (`/api/...`) using `fetch`, with the CSRF token sent in an `X-CSRFToken` header.

| Method | Endpoint | Purpose |
|---|---|---|
| POST | `/api/generate-password` | Generate a password (server-side, `secrets`) |
| GET | `/api/vault` | List items (`?q=`, `?category=`, `?filter=`), **never** includes passwords |
| POST | `/api/vault` | Create an item |
| GET | `/api/vault/<id>` | Item details and decrypted notes, **no password** |
| PUT | `/api/vault/<id>` | Update (blank password = keep the old one) |
| DELETE | `/api/vault/<id>` | Delete |
| POST | `/api/vault/<id>/reveal` | Return the decrypted password for this one item |
| POST | `/api/vault/<id>/copy` | Same, used by the Copy button |
| GET | `/api/security-report` | Health summary |
| POST | `/api/lock` | Lock the vault for this session |

Status codes: 200/201 success, 400 validation or CSRF, 401 not signed in, 403 vault locked, 404 not found *or not yours*, 429 rate limited, 500 server error.

## Security architecture

Two completely separate paths:

```
Signing in                              Saving a credential
──────────                              ───────────────────
login password                          site password (+ notes)
   ↓ Werkzeug scrypt hash                  ↓ Fernet (AES + HMAC-SHA256)
users.password_hash                     vault_items.encrypted_password
```

**Login passwords** are one-way hashed with Werkzeug (scrypt, per-password salt). They are never stored, logged or used as an encryption key.

**Vault passwords and notes** must be readable again, so they are *encrypted*, not hashed, with Fernet (authenticated encryption - tampering is detected). The key hierarchy:

```
VAULT_ENCRYPTION_KEY (.env)
   └─ scrypt ─▶ master key (in memory only)
        └─ HKDF, salt = users.key_salt ─▶ per-user Fernet key
```

- The root secret lives in `.env`, never in source code, SQLite, HTML, JavaScript or an API response.
- `users.key_salt` is not secret; it just gives every user a different key.
- Because the login password isn't involved, changing it doesn't require re-encrypting anything.

Other protections:

- **Authorization:** every vault query is filtered by `user_id == current_user.id`; a `user_id` in a request body is ignored. Someone else's item returns **404**, not 403, so IDs can't be probed.
- **CSRF:** Flask-WTF on every POST/PUT/DELETE, including JSON calls (header token).
- **SQL injection:** SQLAlchemy ORM only, no string-built SQL. Search input is escaped so `%` isn't a wildcard.
- **XSS:** Jinja autoescape; the JS builds DOM nodes with `textContent`; a strict CSP (`script-src 'self'; style-src 'self'`, no inline code).
- **Headers:** CSP, `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Referrer-Policy`, `Permissions-Policy`, HSTS when secure cookies are on, and `Cache-Control: no-store` on pages and API responses.
- **Cookies:** `HttpOnly`, `SameSite=Lax`, `Secure` when `SESSION_COOKIE_SECURE=true`. Flask-Login "strong" session protection.
- **Timing:** logging in as an unknown user still performs a hash check, so response time doesn't reveal which accounts exist.
- **Logging:** only IDs, IP addresses and event names - never passwords, keys or tokens.

### The encryption key is critical

`VAULT_ENCRYPTION_KEY` is the only thing that can decrypt your vault.

- **Lose it and every saved password is permanently unreadable.** There is no recovery.
- Change it and existing items stop decrypting. (Key rotation isn't implemented.)
- Back it up somewhere separate from the database, e.g. a second password manager or a printed copy in a safe.
- Never commit `.env`.

### Limitations (please read)

- **Server-side encryption, not zero-knowledge.** Whoever has both the database *and* the server's `.env` (or a running, compromised server process) can decrypt vault data. That's the price of "the server decrypts on Reveal". A zero-knowledge design derives keys in the browser from a master password; this project deliberately doesn't.
- Revealed and copied passwords exist in the browser's memory and DOM for a while. Malware or a malicious browser extension can read them. Clipboard clearing is best-effort.
- The generated-password "entropy" and the strength meter are estimates, not guarantees. The scorer is a heuristic with a small common-password list.
- Rate limiting uses in-memory storage, which is per-process. Behind several workers, point `RATELIMIT_STORAGE_URI` at Redis.
- No email verification, password reset, two-factor authentication, breach checking or audit log.
- Not independently audited. Don't describe it as "military grade" - it isn't a claim this project makes.

## Database structure

SQLite, created automatically on first run (`instance/passvault.db`). Foreign keys are switched on for every connection.

**users** - `id`, `full_name`, `username` (unique, stored lowercase), `email` (unique), `password_hash`, `created_at`, `last_login`, `is_active`, plus `key_salt`, `failed_logins`, `locked_until`

**vault_items** - `id`, `user_id` → `users.id` (ON DELETE CASCADE), `title`, `website_url`, `username`, `encrypted_password`, `notes` (encrypted), `category`, `created_at`, `updated_at`, `last_accessed`, plus `strength`, `strength_score`, `password_changed_at`

The extra columns exist so the vault list can show strength and age without decrypting every password.

## Installation

Requires Python 3.10+.

```bash
cd PassVault
python -m venv .venv
```

Activate it:

```bash
# Windows (PowerShell / cmd)
.venv\Scripts\activate

# macOS / Linux
source .venv/bin/activate
```

Install and run:

```bash
pip install -r requirements.txt
python app.py
```

Then open <http://127.0.0.1:5000>.

### Configuration (`.env`)

On first run, if there is no `.env`, PassVault creates one with freshly generated random secrets. **Back up `VAULT_ENCRYPTION_KEY` from that file straight away.**

To do it by hand instead:

```bash
cp .env.example .env        # Windows: copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(64))"   # -> SECRET_KEY
python -c "import secrets; print(secrets.token_urlsafe(48))"   # -> VAULT_ENCRYPTION_KEY
```

| Variable | Meaning |
|---|---|
| `SECRET_KEY` | Signs session cookies and CSRF tokens |
| `VAULT_ENCRYPTION_KEY` | Root of all vault encryption keys - **back it up** |
| `DATABASE_URL` | Must be SQLite. Default `sqlite:///instance/passvault.db` (relative to the project folder) |
| `SESSION_COOKIE_SECURE` | `true` when served over HTTPS |
| `SESSION_LIFETIME_MINUTES` | Idle time before the login session expires (default 30) |
| `LOGIN_RATE_LIMIT` | Default `5 per minute` per IP |
| `DEBUG` | Leave `false` outside development |

The database is created automatically. Delete `instance/passvault.db` to start over.

### Running the tests

```bash
pip install -r requirements-dev.txt
pytest
```

The suite covers registration, login/logout, duplicate accounts, the generator, encryption (including tamper detection), CSRF, rate limiting, session cookies, vault locking, XSS escaping, and - most importantly - `test_user_a_cannot_access_user_b_vault_item`.

## Deployment considerations

- **Use HTTPS**, and set `SESSION_COOKIE_SECURE=true`. Put a reverse proxy (nginx, Caddy) in front and terminate TLS there.
- Don't use `python app.py` in production. Use a real server, for example `gunicorn -w 2 "app:create_app()"` (Linux/macOS) or `waitress-serve --call app:create_app` (Windows). Note: `app:create_app()` refers to the package in `app/`.
- Set `DEBUG=false` (the default). Error pages are generic; details go to the server log only.
- Keep `.env` outside version control, readable only by the service user (`chmod 600`). Prefer injecting secrets through your platform's secret store.
- Back up `instance/passvault.db` **and** `VAULT_ENCRYPTION_KEY` - separately. One without the other is useless.
- Behind a proxy, configure `X-Forwarded-For` handling so rate limiting sees real client IPs, and use Redis for `RATELIMIT_STORAGE_URI` if you run more than one worker.
- SQLite is fine for one person or a small group. It's a single file on one machine, not a multi-server database.
