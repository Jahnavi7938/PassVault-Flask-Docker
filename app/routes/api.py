"""JSON API. Every route here requires a login (except password generation) and CSRF via the X-CSRFToken header."""
from urllib.parse import urlparse

from flask import Blueprint, current_app, jsonify, request, session
from flask_login import current_user, login_required
from sqlalchemy import or_

from app import CATEGORIES, db, limiter
from app.models import VaultItem, utcnow
from app.routes import owned_item_or_404, vault_unlocked
from app.services.encryption import DecryptionError, decrypt, encrypt
from app.services.password_generator import generate
from app.services.security_service import evaluate_strength, vault_report

bp = Blueprint("api", __name__, url_prefix="/api")


def error(message, status=400, **extra):
    return jsonify(error=message, **extra), status


def _body():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def _clean(data, creating):
    """Validate and normalise an item payload. Returns (clean, errors)."""
    clean, errs = {}, {}

    def text(key, maxlen, required=False):
        if key not in data and not creating:
            return
        val = data.get(key)
        val = val.strip() if isinstance(val, str) else ""
        if required and not val:
            errs[key] = "Required."
        elif len(val) > maxlen:
            errs[key] = f"Max {maxlen} characters."
        else:
            clean[key] = val

    text("title", 120, required=True)
    text("username", 255)
    text("notes", 2000)
    text("website_url", 500)
    if clean.get("website_url"):
        url = clean["website_url"]
        if "://" not in url:
            url = "https://" + url
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            errs["website_url"] = "Enter a valid http(s) address."
        else:
            clean["website_url"] = url

    if "category" in data or creating:
        cat = data.get("category") or "Other"
        if cat not in CATEGORIES:
            errs["category"] = "Unknown category."
        else:
            clean["category"] = cat

    pw = data.get("password")
    if creating and (not isinstance(pw, str) or not pw):
        errs["password"] = "Required."
    elif pw is not None and pw != "":
        if not isinstance(pw, str) or len(pw) > 1024:
            errs["password"] = "Too long."
        else:
            clean["password"] = pw
    return clean, errs


# ---------- generator ----------

@bp.route("/generate-password", methods=["POST"])
@limiter.limit("60 per minute")
def generate_password():
    opts = _body()
    if opts is None:
        return error("Send a JSON body.")
    try:
        return jsonify(generate(opts)), 200
    except ValueError as exc:
        return error(str(exc))


# ---------- vault ----------

@bp.route("/vault", methods=["GET"])
@login_required
@vault_unlocked
def list_items():
    q = request.args.get("q", "").strip()[:100]
    category = request.args.get("category", "")
    flt = request.args.get("filter", "all")

    query = VaultItem.query.filter_by(user_id=current_user.id)
    if q:
        query = query.filter(or_(
            VaultItem.title.icontains(q, autoescape=True),
            VaultItem.username.icontains(q, autoescape=True),
            VaultItem.category.icontains(q, autoescape=True),
            VaultItem.website_url.icontains(q, autoescape=True),
        ))
    if category in CATEGORIES:
        query = query.filter(VaultItem.category == category)
    if flt in ("strong", "medium", "weak"):
        query = query.filter(VaultItem.strength == flt)
    elif flt == "recent":
        from datetime import timedelta
        query = query.filter(VaultItem.created_at >= utcnow() - timedelta(days=7))
    items = query.order_by(VaultItem.title.collate("NOCASE")).all()
    return jsonify(items=[i.to_dict() for i in items], count=len(items))


@bp.route("/vault", methods=["POST"])
@login_required
@vault_unlocked
@limiter.limit("60 per minute")
def create_item():
    data = _body()
    if data is None:
        return error("Send a JSON body.")
    clean, errs = _clean(data, creating=True)
    if errs:
        return error("Please fix the highlighted fields.", 400, fields=errs)
    strength = evaluate_strength(clean["password"])
    item = VaultItem(
        user_id=current_user.id,  # always the session user - any user_id in the payload is ignored
        title=clean["title"], website_url=clean.get("website_url") or None,
        username=clean.get("username") or None, category=clean["category"],
        encrypted_password=encrypt(current_user, clean["password"]),
        notes=encrypt(current_user, clean["notes"]) if clean.get("notes") else None,
        strength=strength["label"], strength_score=strength["score"],
    )
    db.session.add(item)
    db.session.commit()
    current_app.logger.info("Vault item %s created (user %s)", item.id, current_user.id)
    return jsonify(item=item.to_dict()), 201


@bp.route("/vault/<int:item_id>", methods=["GET"])
@login_required
@vault_unlocked
def get_item(item_id):
    item = owned_item_or_404(item_id)
    notes = ""
    if item.notes:
        try:
            notes = decrypt(current_user, item.notes)
        except DecryptionError:
            notes = ""
    item.last_accessed = utcnow()
    db.session.commit()
    return jsonify(item={**item.to_dict(), "notes": notes})


@bp.route("/vault/<int:item_id>", methods=["PUT"])
@login_required
@vault_unlocked
@limiter.limit("60 per minute")
def update_item(item_id):
    item = owned_item_or_404(item_id)
    data = _body()
    if data is None:
        return error("Send a JSON body.")
    clean, errs = _clean(data, creating=False)
    if errs:
        return error("Please fix the highlighted fields.", 400, fields=errs)
    for key in ("title", "category"):
        if key in clean:
            setattr(item, key, clean[key])
    for key in ("username", "website_url"):
        if key in clean:
            setattr(item, key, clean[key] or None)
    if "notes" in clean:
        item.notes = encrypt(current_user, clean["notes"]) if clean["notes"] else None
    if "password" in clean:  # blank/omitted means "keep the current one"
        strength = evaluate_strength(clean["password"])
        item.encrypted_password = encrypt(current_user, clean["password"])
        item.strength, item.strength_score = strength["label"], strength["score"]
        item.password_changed_at = utcnow()
    item.updated_at = utcnow()
    db.session.commit()
    current_app.logger.info("Vault item %s updated (user %s)", item.id, current_user.id)
    return jsonify(item=item.to_dict())


@bp.route("/vault/<int:item_id>", methods=["DELETE"])
@login_required
@vault_unlocked
def delete_item(item_id):
    item = owned_item_or_404(item_id)
    db.session.delete(item)
    db.session.commit()
    current_app.logger.info("Vault item %s deleted (user %s)", item_id, current_user.id)
    return jsonify(ok=True)


def _secret_response(item_id):
    item = owned_item_or_404(item_id)
    try:
        password = decrypt(current_user, item.encrypted_password)
    except DecryptionError:
        current_app.logger.error("Decryption failed for item %s", item.id)
        return error("This item couldn't be decrypted. Check your VAULT_ENCRYPTION_KEY.", 500)
    item.last_accessed = utcnow()
    db.session.commit()
    return jsonify(password=password)


@bp.route("/vault/<int:item_id>/reveal", methods=["POST"])
@login_required
@vault_unlocked
@limiter.limit("30 per minute")
def reveal(item_id):
    return _secret_response(item_id)


@bp.route("/vault/<int:item_id>/copy", methods=["POST"])
@login_required
@vault_unlocked
@limiter.limit("30 per minute")
def copy(item_id):
    return _secret_response(item_id)


# ---------- misc ----------

@bp.route("/security-report", methods=["GET"])
@login_required
@vault_unlocked
def security_report():
    return jsonify(vault_report(current_user))


@bp.route("/lock", methods=["POST"])
@login_required
def lock():
    session["vault_locked"] = True
    return jsonify(ok=True)
