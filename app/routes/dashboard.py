from datetime import timedelta

from flask import Blueprint, render_template
from flask_login import current_user, login_required

from app.models import VaultItem, utcnow
from app.routes import vault_unlocked
from app.services.security_service import vault_report

bp = Blueprint("dashboard", __name__)


@bp.route("/")
def index():
    return render_template("index.html")


@bp.route("/dashboard")
@login_required
@vault_unlocked
def home():
    report = vault_report(current_user)
    recent = (VaultItem.query.filter_by(user_id=current_user.id)
              .order_by(VaultItem.created_at.desc()).limit(5).all())
    week_ago = utcnow() - timedelta(days=7)
    added_this_week = VaultItem.query.filter(VaultItem.user_id == current_user.id,
                                             VaultItem.created_at >= week_ago).count()
    return render_template("dashboard.html", report=report, recent=recent, added_this_week=added_this_week)
