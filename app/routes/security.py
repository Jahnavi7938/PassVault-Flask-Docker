from flask import Blueprint, render_template
from flask_login import current_user, login_required

from app.routes import vault_unlocked
from app.services.security_service import vault_report

bp = Blueprint("security", __name__)


@bp.route("/security")
@login_required
@vault_unlocked
def page():
    return render_template("security.html", report=vault_report(current_user))
