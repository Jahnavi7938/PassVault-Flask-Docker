"""HTML pages for the vault. The data itself is loaded through /api/vault."""
from flask import Blueprint, current_app, render_template
from flask_login import current_user, login_required

from app.routes import owned_item_or_404, vault_unlocked
from app.services.encryption import DecryptionError, decrypt

bp = Blueprint("vault", __name__, url_prefix="/vault")


@bp.route("")
@login_required
@vault_unlocked
def index():
    return render_template("vault.html")


@bp.route("/add")
@login_required
@vault_unlocked
def add():
    return render_template("add_password.html")


@bp.route("/edit/<int:item_id>")
@login_required
@vault_unlocked
def edit(item_id):
    item = owned_item_or_404(item_id)
    notes = ""
    if item.notes:
        try:
            notes = decrypt(current_user, item.notes)
        except DecryptionError:
            current_app.logger.error("Could not decrypt notes for item %s", item.id)
    # The password itself is deliberately not sent to this page.
    return render_template("edit_password.html", item=item, notes=notes)
