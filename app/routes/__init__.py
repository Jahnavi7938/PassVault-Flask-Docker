"""Shared helpers for the route modules."""
from functools import wraps

from flask import abort, jsonify, redirect, request, session, url_for
from flask_login import current_user

from app.models import VaultItem


def is_safe_next(target):
    """Only allow same-site relative redirects (blocks open-redirect tricks like //evil.com)."""
    return bool(target) and target.startswith("/") and not target.startswith("//") and "\\" not in target


def vault_unlocked(view):
    """Vault pages and endpoints refuse to work while the vault is locked."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session.get("vault_locked"):
            if request.path.startswith("/api/"):
                return jsonify(error="Vault is locked. Enter your password to unlock it.", code="vault_locked"), 403
            return redirect(url_for("auth.unlock", next=request.path))
        return view(*args, **kwargs)
    return wrapper


def owned_item_or_404(item_id):
    """Fetch a vault item only if it belongs to the logged-in user.

    Someone else's item returns 404 (not 403) so IDs can't be probed for existence.
    """
    item = VaultItem.query.filter_by(id=item_id, user_id=current_user.id).first()
    if item is None or item.user_id != current_user.id:
        abort(404)
    return item
