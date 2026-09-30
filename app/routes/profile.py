from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required
from sqlalchemy.exc import IntegrityError

from app import db, limiter
from app.models import User
from app.services.security_service import password_policy_errors

bp = Blueprint("profile", __name__)


@bp.route("/profile", methods=["GET", "POST"])
@login_required
@limiter.limit("10 per minute", methods=["POST"])
def profile():
    errors = {}
    if request.method == "POST":
        name = request.form.get("full_name", "").strip()
        email_raw = request.form.get("email", "").strip()
        current_pw = request.form.get("current_password", "")
        email = current_user.email
        if not 2 <= len(name) <= 100:
            errors["full_name"] = "Enter your name (2-100 characters)."
        try:
            email = validate_email(email_raw, check_deliverability=False).normalized.lower()
        except EmailNotValidError:
            errors["email"] = "Enter a valid email address."
        # Changing the email changes how you sign in, so it needs the password again.
        if "email" not in errors and email != current_user.email:
            if not current_user.check_password(current_pw):
                errors["current_password"] = "Enter your current password to change your email."
            elif User.query.filter(User.email == email, User.id != current_user.id).first():
                errors["email"] = "That email is already in use."
        if not errors:
            current_user.full_name, current_user.email = name, email
            try:
                db.session.commit()
                flash("Profile updated.", "success")
                return redirect(url_for("profile.profile"))
            except IntegrityError:
                db.session.rollback()
                errors["email"] = "That email is already in use."
    return render_template("profile.html", errors=errors)


@bp.route("/profile/password", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def change_password():
    old = request.form.get("current_password", "")
    new = request.form.get("new_password", "")
    if not current_user.check_password(old):
        flash("Your current password is wrong.", "error")
    elif new != request.form.get("confirm_password", ""):
        flash("The new passwords don't match.", "error")
    elif password_policy_errors(new):
        flash("New password needs " + ", ".join(password_policy_errors(new)) + ".", "error")
    else:
        # Vault keys don't depend on the login password, so nothing has to be re-encrypted.
        current_user.set_password(new)
        db.session.commit()
        current_app.logger.info("Password changed (user id %s)", current_user.id)
        flash("Password changed.", "success")
    return redirect(url_for("profile.profile"))


@bp.route("/settings")
@login_required
def settings():
    return render_template("settings.html", lifetime=int(current_app.config["PERMANENT_SESSION_LIFETIME"].total_seconds() // 60))
