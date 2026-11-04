from __future__ import annotations

import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

import pyotp
from flask import Flask, flash, redirect, render_template_string, request, session, url_for
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Boolean, DateTime, Integer, String, or_, select

BASE_DIR = Path(__file__).parent

db = SQLAlchemy()
bcrypt = Bcrypt()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

class User(db.Model):
    __tablename__ = "users"
    id = db.Column(Integer, primary_key=True)
    full_name = db.Column(String(120), nullable=False)
    username = db.Column(String(40), unique=True, nullable=False, index=True)
    email = db.Column(String(255), unique=True, nullable=False, index=True)
    password_hash = db.Column(String(255), nullable=False)
    created_at = db.Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    two_factor_enabled = db.Column(Boolean, default=False, nullable=False)
    totp_secret = db.Column(String(64), nullable=True)


def csrf_token() -> str:
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf() -> bool:
    submitted = request.form.get("csrf_token", "")
    stored = session.get("csrf_token", "")
    return bool(submitted and stored) and secrets.compare_digest(submitted, stored)


def password_errors(password: str) -> list[str]:
    errors = []
    if len(password) < 12: errors.append("Password must be at least 12 characters long.")
    if not re.search(r"[A-Z]", password): errors.append("Password must contain an uppercase letter.")
    if not re.search(r"[a-z]", password): errors.append("Password must contain a lowercase letter.")
    if not re.search(r"\d", password): errors.append("Password must contain a number.")
    if not re.search(r"[^A-Za-z0-9]", password): errors.append("Password must contain a special character.")
    common = {"password", "password123", "qwerty123", "123456789012", "letmein123!", "welcome123!"}
    if password.casefold() in common: errors.append("Choose a less common password.")
    return errors


def current_user() -> User | None:
    user_id = session.get("user_id")
    return db.session.get(User, user_id) if user_id else None


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user():
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def page(title: str, body: str, *, user: User | None = None) -> str:
    nav = f'<a href="{url_for("dashboard")}">Dashboard</a><a href="{url_for("security")}">Security</a><form method="post" action="{url_for("logout")}" class="inline"><input type="hidden" name="csrf_token" value="{csrf_token()}"><button class="link-button">Logout</button></form>' if user else f'<a href="{url_for("login")}">Login</a><a href="{url_for("register")}">Register</a>'
    flashes = "".join(f'<div class="flash {category}">{message}</div>' for category, message in session.pop("_flashes", []))
    return render_template_string("""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{ title }} · Secure Login System</title><style>
    *{box-sizing:border-box}body{margin:0;background:#071426;color:#eaf3fb;font-family:Arial,sans-serif;line-height:1.5}a{color:#8ecbff;text-decoration:none;margin-left:18px}a:hover{text-decoration:underline}.nav{display:flex;justify-content:space-between;align-items:center;max-width:1080px;margin:auto;padding:20px 24px}.brand{font-weight:800;letter-spacing:.08em;color:#fff}.navlinks{display:flex;align-items:center}.shell{max-width:1080px;margin:35px auto;padding:0 24px}.card{background:#10243d;border:1px solid #214363;border-radius:16px;padding:26px;box-shadow:0 14px 36px #0003;margin-bottom:18px}.narrow{max-width:560px;margin:35px auto}.eyebrow{color:#55b9ff;font-size:.78rem;font-weight:700;letter-spacing:.14em}.hero h1{font-size:2.3rem;margin:.35rem 0}.muted{color:#9db3c9}.form-row{margin:14px 0}label{display:block;font-weight:700;margin-bottom:6px}input{width:100%;padding:12px;border-radius:8px;border:1px solid #345877;background:#091a2d;color:#fff;font-size:1rem}button,.button{border:0;border-radius:8px;padding:11px 16px;background:#1477b8;color:#fff;font-weight:700;cursor:pointer;text-decoration:none;display:inline-block}button:hover,.button:hover{background:#1b91d6}.secondary{background:#26445f}.link-button{background:none;padding:0;color:#8ecbff;font-weight:400}.inline{display:inline}.flash{padding:12px 15px;border-radius:8px;margin-bottom:12px;background:#23415d}.flash.error{background:#572631;color:#ffd9dd}.flash.success{background:#174d3c;color:#c8ffe8}.flash.warning{background:#514117;color:#ffe99a}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(230px,1fr));gap:16px}.metric{font-size:1.8rem;font-weight:800;color:#65c3ff}.badge{display:inline-block;padding:4px 9px;border-radius:999px;background:#183b59;color:#a9dbff;font-size:.82rem}.check{padding:8px 0;border-bottom:1px solid #214363}.good{color:#62e2a2}.warning-text{color:#ffdc70}small{color:#9db3c9}@media(max-width:650px){.nav{display:block}.navlinks{margin-top:10px}.hero h1{font-size:1.8rem}}
    </style></head><body><nav class="nav"><div class="brand">SECURE LOGIN SYSTEM</div><div class="navlinks">{{ nav|safe }}</div></nav><main class="shell">{{ flashes|safe }}{{ body|safe }}</main></body></html>""", title=title, body=body, nav=nav, flashes=flashes)


def form_html(action: str, fields: str, button: str) -> str:
    return f'<form method="post" action="{action}"><input type="hidden" name="csrf_token" value="{csrf_token()}">{fields}<button type="submit">{button}</button></form>'


def input_field(name: str, label: str, input_type: str = "text", required: bool = True) -> str:
    return f'<div class="form-row"><label for="{name}">{label}</label><input id="{name}" name="{name}" type="{input_type}" autocomplete="off" {"required" if required else ""}></div>'


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
        SQLALCHEMY_DATABASE_URI=os.environ.get("DATABASE_URL", f"sqlite:///{BASE_DIR / 'secure_login.db'}"),
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        WTF_CSRF_TIME_LIMIT=3600,
    )
    if test_config: app.config.update(test_config)
    db.init_app(app); bcrypt.init_app(app); limiter.init_app(app)
    with app.app_context(): db.create_all()

    @app.context_processor
    def inject(): return {"csrf_token": csrf_token}

    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if current_user() else "login"))

    @app.route("/register", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def register():
        if request.method == "POST":
            if not validate_csrf(): flash("Invalid form security token. Please try again.", "error"); return redirect(url_for("register"))
            full_name = request.form.get("full_name", "").strip()
            username = request.form.get("username", "").strip().lower()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            errors = []
            if not full_name or len(full_name) > 120: errors.append("Enter a valid full name.")
            if not re.fullmatch(r"[a-zA-Z0-9_.-]{3,40}", username): errors.append("Username must be 3–40 characters using letters, numbers, dot, underscore, or hyphen.")
            if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email): errors.append("Enter a valid email address.")
            errors.extend(password_errors(password))
            if password != confirm: errors.append("Passwords do not match.")
            if db.session.scalar(select(User).where(or_(User.username == username, User.email == email))): errors.append("That username or email is already registered.")
            if errors:
                for error in errors: flash(error, "error")
            else:
                user = User(full_name=full_name, username=username, email=email, password_hash=bcrypt.generate_password_hash(password).decode("utf-8"))
                db.session.add(user); db.session.commit(); flash("Registration successful. You can now log in.", "success"); return redirect(url_for("login"))
        body = '<div class="card narrow"><div class="eyebrow">CREATE ACCOUNT</div><h1>Register</h1><p class="muted">Use a unique password with at least 12 characters.</p>' + form_html(url_for("register"), input_field("full_name", "Full name") + input_field("username", "Username") + input_field("email", "Email", "email") + input_field("password", "Password", "password") + input_field("confirm_password", "Confirm password", "password"), "Create account") + '</div>'
        return page("Register", body)

    @app.route("/login", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def login():
        if request.method == "POST":
            if not validate_csrf(): flash("Invalid form security token. Please try again.", "error"); return redirect(url_for("login"))
            identifier = request.form.get("identifier", "").strip().lower(); password = request.form.get("password", "")
            user = db.session.scalar(select(User).where(or_(User.username == identifier, User.email == identifier)))
            valid = user is not None and bcrypt.check_password_hash(user.password_hash, password)
            if not valid:
                flash("Invalid username/email or password.", "error")
            elif user.two_factor_enabled:
                session["pending_2fa_user"] = user.id; return redirect(url_for("verify_2fa"))
            else:
                session.clear(); session.permanent = True; session["user_id"] = user.id; session["csrf_token"] = secrets.token_urlsafe(32); return redirect(url_for("dashboard"))
        body = '<div class="card narrow"><div class="eyebrow">WELCOME BACK</div><h1>Sign in</h1><p class="muted">Use your username or email. Login errors are intentionally generic.</p>' + form_html(url_for("login"), input_field("identifier", "Username or email") + input_field("password", "Password", "password"), "Sign in") + '<p><small>New here? <a href="' + url_for("register") + '">Create an account</a></small></p></div>'
        return page("Login", body)

    @app.route("/verify-2fa", methods=["GET", "POST"])
    @limiter.limit("5 per minute", methods=["POST"])
    def verify_2fa():
        pending_id = session.get("pending_2fa_user")
        user = db.session.get(User, pending_id) if pending_id else None
        if not user: flash("Your login session expired. Please try again.", "warning"); return redirect(url_for("login"))
        if request.method == "POST":
            if not validate_csrf() or not pyotp.TOTP(user.totp_secret).verify(request.form.get("code", ""), valid_window=1): flash("Invalid verification code.", "error")
            else:
                session.clear(); session.permanent = True; session["user_id"] = user.id; session["csrf_token"] = secrets.token_urlsafe(32); return redirect(url_for("dashboard"))
        body = '<div class="card narrow"><div class="eyebrow">SECOND FACTOR</div><h1>Verify sign in</h1><p class="muted">Enter the six-digit code from your authenticator app.</p>' + form_html(url_for("verify_2fa"), input_field("code", "Authenticator code", "text"), "Verify") + '</div>'
        return page("Verify sign in", body)

    @app.route("/dashboard")
    @login_required
    def dashboard():
        user = current_user(); body = f'<div class="hero"><div class="eyebrow">PROTECTED AREA</div><h1>Welcome, {user.full_name}</h1><p class="muted">Your authenticated session is active.</p></div><div class="grid"><div class="card"><small>ACCOUNT</small><div class="metric">{user.username}</div><p>{user.email}</p></div><div class="card"><small>SECURITY STATUS</small><div class="metric">{"2FA enabled" if user.two_factor_enabled else "2FA available"}</div><p>Use the Security page to manage your second factor.</p></div><div class="card"><small>MEMBER SINCE</small><div class="metric">{user.created_at.strftime("%Y-%m-%d")}</div></div></div>'
        return page("Dashboard", body, user=user)

    @app.route("/security", methods=["GET", "POST"])
    @login_required
    def security():
        user = current_user()
        if request.method == "POST":
            if not validate_csrf(): flash("Invalid form security token.", "error"); return redirect(url_for("security"))
            action = request.form.get("action")
            if action == "enable":
                secret = user.totp_secret or pyotp.random_base32(); code = request.form.get("code", "")
                if pyotp.TOTP(secret).verify(code, valid_window=1): user.totp_secret = secret; user.two_factor_enabled = True; db.session.commit(); flash("Two-factor authentication enabled.", "success")
                else: flash("Enter a valid code from your authenticator app.", "error")
            elif action == "disable": user.two_factor_enabled = False; user.totp_secret = None; db.session.commit(); flash("Two-factor authentication disabled.", "warning")
            return redirect(url_for("security"))
        secret = user.totp_secret or pyotp.random_base32();
        if not user.totp_secret: user.totp_secret = secret; db.session.commit()
        provisioning = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Secure Login System")
        if user.two_factor_enabled: action_html = form_html(url_for("security"), '<input type="hidden" name="action" value="disable">', "Disable 2FA")
        else: action_html = form_html(url_for("security"), '<input type="hidden" name="action" value="enable">' + input_field("code", "Enter the code shown in your authenticator app"), "Enable 2FA")
        body = f'<div class="card narrow"><div class="eyebrow">ACCOUNT SECURITY</div><h1>Two-factor authentication</h1><p class="muted">Status: <span class="badge">{"Enabled" if user.two_factor_enabled else "Not enabled"}</span></p><p>Scan this provisioning URI with a compatible authenticator app, or enter the secret manually:</p><p><code>{secret}</code></p><small>{provisioning}</small><hr style="border-color:#214363;margin:22px 0">{action_html}</div>'
        return page("Security", body, user=user)

    @app.post("/logout")
    @login_required
    def logout():
        if not validate_csrf(): flash("Invalid form security token.", "error"); return redirect(url_for("dashboard"))
        session.clear(); flash("You have been securely logged out.", "success"); return redirect(url_for("login"))

    return app

app = create_app()

if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG", "0") == "1")
