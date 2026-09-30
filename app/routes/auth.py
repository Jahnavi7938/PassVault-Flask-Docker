import re

from email_validator import EmailNotValidError, validate_email
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

from app import db, limiter
from app.models import User, utcnow
from app.routes import is_safe_next
from app.services.security_service import password_policy_errors

bp = Blueprint("auth", __name__)

GENERIC_LOGIN_ERROR = "Invalid username/email or password."
# Checked when the account doesn't exist, so a wrong username takes about as long as a wrong password.
_DUMMY_HASH = generate_password_hash("not-a-real-password")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _validate_registration(form, password, confirm):
    errors = {}
    if not 2 <= len(form["full_name"]) <= 100:
        errors["full_name"] = "Enter your name (2-100 characters)."
    try:
        form["email"] = validate_email(form["email"], check_deliverability=False).normalized.lower()
    except EmailNotValidError:
        errors["email"] = "Enter a valid email address."
    if not USERNAME_RE.match(form["username"]):
        errors["username"] = "3-32 characters: letters, numbers, dot, dash or underscore."
    missing = password_policy_errors(password)
    if missing:
        errors["password"] = "Password needs " + ", ".join(missing) + "."
    if password != confirm:
        errors["confirm_password"] = "The passwords don't match."
    if "username" not in errors and User.query.filter_by(username=form["username"].lower()).first():
        errors["username"] = "That username is taken."
    if "email" not in errors and User.query.filter_by(email=form["email"]).first():
        errors["email"] = "An account with that email already exists."
    return errors


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("10 per hour", methods=["POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))
    form, errors = {}, {}
    if request.method == "POST":
        form = {k: request.form.get(k, "").strip() for k in ("full_name", "email", "username")}
        password = request.form.get("password", "")
        errors = _validate_registration(form, password, request.form.get("confirm_password", ""))
        if not errors:
            user = User(full_name=form["full_name"], email=form["email"], username=form["username"].lower())
            user.set_password(password)
            db.session.add(user)
            try:
                db.session.commit()
            except IntegrityError:  # two people racing for the same name
                db.session.rollback()
                errors["username"] = "That username or email is already registered."
            else:
                current_app.logger.info("New account created (user id %s)", user.id)
                flash("Account created. You can sign in now.", "success")
                return redirect(url_for("auth.login"))
    return render_template("register.html", form=form, errors=errors), (400 if errors else 200)


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit(lambda: current_app.config["LOGIN_RATE_LIMIT"], methods=["POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.home"))
    error = None
    if request.method == "POST":
        ident = request.form.get("identifier", "").strip().lower()
        password = request.form.get("password", "")
        user = User.query.filter(or_(User.username == ident, User.email == ident)).first() if ident else None

        ok = False
        if user and user.is_active and not user.is_locked_out():
            ok = user.check_password(password)
        else:
            check_password_hash(_DUMMY_HASH, password)

        if ok:
            user.failed_logins = 0
            user.locked_until = None
            user.last_login = utcnow()
            db.session.commit()
            session.clear()
            login_user(user, remember=bool(request.form.get("remember")))
            session.permanent = True
            current_app.logger.info("Login ok (user id %s)", user.id)
            nxt = request.args.get("next", "")
            return redirect(nxt if is_safe_next(nxt) else url_for("dashboard.home"))

        if user and user.is_active:
            user.failed_logins += 1
            if user.failed_logins >= current_app.config["MAX_FAILED_LOGINS"]:
                from datetime import timedelta
                user.locked_until = utcnow() + timedelta(minutes=current_app.config["LOCKOUT_MINUTES"])
                user.failed_logins = 0
            db.session.commit()
        current_app.logger.warning("Failed login from %s", request.remote_addr)
        error = GENERIC_LOGIN_ERROR  # same message whether the account exists, is locked, or the password is wrong
    return render_template("login.html", error=error), (401 if error else 200)


@bp.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("You've been signed out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/unlock", methods=["GET", "POST"])
@login_required
@limiter.limit("5 per minute", methods=["POST"])
def unlock():
    error = None
    nxt = request.args.get("next", "")
    if request.method == "POST":
        if current_user.check_password(request.form.get("password", "")):
            session["vault_locked"] = False
            return redirect(nxt if is_safe_next(nxt) else url_for("dashboard.home"))
        error = "That password isn't right."
    return render_template("unlock.html", error=error), (401 if error else 200)
