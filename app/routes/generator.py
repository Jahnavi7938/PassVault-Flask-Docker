from flask import Blueprint, render_template
from flask_login import login_required

from app.routes import vault_unlocked

bp = Blueprint("generator", __name__)


@bp.route("/generator")
@login_required
@vault_unlocked
def page():
    return render_template("generator.html")
