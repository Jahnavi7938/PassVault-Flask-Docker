import logging

from flask import Flask, jsonify, redirect, render_template, request, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import CSRFError, CSRFProtect
from sqlalchemy import event
from sqlalchemy.engine import Engine

from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address)

CATEGORIES = ["Social", "Banking", "Email", "Work", "Education", "Shopping", "Other"]


@event.listens_for(Engine, "connect")
def _sqlite_foreign_keys(dbapi_conn, _record):
    # SQLite ignores FOREIGN KEY constraints unless you ask it not to.
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def _wants_json():
    return request.path.startswith("/api/")


def create_app(overrides=None):
    app = Flask(__name__)
    app.config.from_object(Config())
    if overrides:
        app.config.update(overrides)

    if not app.config.get("SECRET_KEY") or not app.config.get("VAULT_ENCRYPTION_KEY"):
        raise RuntimeError("SECRET_KEY and VAULT_ENCRYPTION_KEY must be set in .env")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    db.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to continue."
    login_manager.login_message_category = "info"
    login_manager.session_protection = "strong"

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        user = db.session.get(User, int(user_id))
        return user if user and user.is_active else None

    @login_manager.unauthorized_handler
    def unauthorized():
        if _wants_json():
            return jsonify(error="Authentication required.", code="unauthenticated"), 401
        return redirect(url_for("auth.login", next=request.full_path.rstrip("?")))

    from .routes import api, auth, dashboard, generator, profile, security, vault

    for module in (dashboard, auth, vault, generator, security, profile, api):
        app.register_blueprint(module.bp)

    @app.context_processor
    def inject_globals():
        return {"categories": CATEGORIES}

    register_hooks(app)

   # with app.app_context():
       # db.create_all()

    return app


def register_hooks(app):
    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if app.config["SESSION_COOKIE_SECURE"]:
            resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.path.startswith("/static/"):
            # Pages and API responses can contain private data - keep them out of caches.
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def fail(status, title, message):
        if _wants_json():
            return jsonify(error=message), status
        return render_template(f"{status}.html", title=title, message=message), status

    @app.errorhandler(404)
    def not_found(_e):
        return fail(404, "Not found", "That page doesn't exist, or it isn't yours to see.")

    @app.errorhandler(403)
    def forbidden(_e):
        return fail(403, "Forbidden", "You don't have permission to do that.")

    @app.errorhandler(405)
    def bad_method(_e):
        return fail(404, "Not found", "That page doesn't exist.")

    @app.errorhandler(429)
    def too_many(_e):
        return fail(429, "Slow down", "Too many attempts. Wait a minute and try again.")

    @app.errorhandler(CSRFError)
    def csrf_failed(_e):
        msg = "Your form expired or was invalid. Reload the page and try again."
        if _wants_json():
            return jsonify(error=msg, code="csrf"), 400
        return render_template("403.html", title="Form expired", message=msg), 400

    @app.errorhandler(500)
    def server_error(_e):
        db.session.rollback()
        app.logger.error("Unhandled server error on %s", request.path)
        return fail(500, "Something broke", "Something went wrong on our side. Nothing was lost.")
