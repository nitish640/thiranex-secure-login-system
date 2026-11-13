"""
Thiranex Cyber Security — Task 4: Secure Login System
=====================================================
Flask web app with:
  * bcrypt password hashing (never stores plaintext passwords)
  * Parameterised SQLite queries ONLY — no string-concatenated SQL
  * Input validation (username / email / password rules)
  * Flask session management with logout, 30-minute sessions,
    HttpOnly + SameSite=Lax session cookies
  * Rate limiting / lockout: 5 failed logins -> 5-minute lockout
  * Optional TOTP 2FA (pyotp) with QR-code setup, verified on login
  * Password strength meter + show/hide password on the forms

Run:
    python -m venv .venv
    .venv/bin/pip install -r requirements.txt
    .venv/bin/python app.py
    # open http://127.0.0.1:5000

Local use only. Do NOT deploy this as-is to production without
HTTPS, a persistent SECRET_KEY, and a production WSGI server.
"""
import io
import os
import re
import sqlite3
import time
from datetime import timedelta

import bcrypt
import pyotp
import qrcode
from flask import (Flask, flash, g, redirect, render_template, request,
                   session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "users.db")

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(32).hex()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

# --- Rate limiting / lockout ---------------------------------------------
# username -> list of failed-attempt epoch times (in-memory; resets on restart)
FAILED_ATTEMPTS = {}
MAX_FAILED = 5
LOCKOUT_SECONDS = 5 * 60
WINDOW_SECONDS = 15 * 60


def _prune(username):
    now = time.time()
    FAILED_ATTEMPTS[username] = [
        t for t in FAILED_ATTEMPTS.get(username, []) if now - t < WINDOW_SECONDS
    ]


def is_locked(username):
    _prune(username)
    return len(FAILED_ATTEMPTS.get(username, [])) >= MAX_FAILED


def record_failure(username):
    FAILED_ATTEMPTS.setdefault(username, []).append(time.time())


def clear_failures(username):
    FAILED_ATTEMPTS.pop(username, None)


# --- Database (parameterised queries only) ---------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash BLOB NOT NULL,
            totp_secret TEXT,
            twofa_enabled INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    db.close()


# --- Validation -------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def password_errors(password):
    """Return a list of problems with a password (empty list = acceptable)."""
    errors = []
    if len(password) < 8:
        errors.append("at least 8 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"[0-9]", password):
        errors.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("a special character")
    return errors


def password_strength(password):
    """Score 0-5 for the client-side meter (mirrored in JS)."""
    score = 0
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    if re.search(r"[A-Z]", password) and re.search(r"[a-z]", password):
        score += 1
    if re.search(r"[0-9]", password):
        score += 1
    if re.search(r"[^A-Za-z0-9]", password):
        score += 1
    return min(score, 5)


# --- Helpers -----------------------------------------------------------------
def current_user():
    if "user_id" not in session:
        return None
    db = get_db()
    # Parameterised query — the username/id is never interpolated into SQL.
    return db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if current_user() is None:
            flash("Please log in first.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# --- Routes -------------------------------------------------------------------
@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if not USERNAME_RE.match(username):
            flash("Username must be 3-20 characters: letters, digits, underscore only.", "error")
        elif not EMAIL_RE.match(email):
            flash("Please enter a valid email address.", "error")
        elif password != confirm:
            flash("Passwords do not match.", "error")
        else:
            pw_errors = password_errors(password)
            if pw_errors:
                flash("Password needs " + ", ".join(pw_errors) + ".", "error")
            else:
                db = get_db()
                existing = db.execute(
                    "SELECT id FROM users WHERE username = ? OR email = ?",
                    (username, email),
                ).fetchone()
                if existing:
                    flash("That username or email is already registered.", "error")
                else:
                    # bcrypt hash — only the hash is stored, never the password.
                    pw_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
                    db.execute(
                        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                        (username, email, pw_hash),
                    )
                    db.commit()
                    flash("Account created. You can log in now.", "success")
                    return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if is_locked(username):
            flash(
                "Too many failed attempts. Account locked for 5 minutes. Try again later.",
                "error",
            )
            return render_template("login.html")

        db = get_db()
        # Parameterised query: an injection string such as
        #   ' OR '1'='1
        # is treated as a literal username, matches nobody, and fails safely.
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
            clear_failures(username)
            if user["twofa_enabled"]:
                # Password OK, but 2FA still required — do NOT log in yet.
                session["pending_2fa_user_id"] = user["id"]
                return redirect(url_for("verify_2fa"))
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))

        record_failure(username)
        remaining = MAX_FAILED - len(FAILED_ATTEMPTS.get(username, []))
        if remaining <= 0:
            flash("Too many failed attempts. Account locked for 5 minutes.", "error")
        else:
            flash(f"Invalid username or password. ({remaining} attempts left)", "error")
    return render_template("login.html")


@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    user_id = session.get("pending_2fa_user_id")
    if not user_id:
        return redirect(url_for("login"))
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        if user and user["totp_secret"] and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
            session.pop("pending_2fa_user_id", None)
            session.permanent = True
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid 2FA code. Try again.", "error")
    return render_template("verify_2fa.html")


@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    return render_template("dashboard.html", user=user)


@app.route("/setup-2fa", methods=["GET", "POST"])
@login_required
def setup_2fa():
    user = current_user()
    db = get_db()
    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("totp_setup_secret")
        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            db.execute(
                "UPDATE users SET totp_secret = ?, twofa_enabled = 1 WHERE id = ?",
                (secret, user["id"]),
            )
            db.commit()
            session.pop("totp_setup_secret", None)
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for("dashboard"))
        flash("Invalid code — 2FA was not enabled. Try again.", "error")

    if not session.get("totp_setup_secret"):
        session["totp_setup_secret"] = pyotp.random_base32()
    secret = session["totp_setup_secret"]
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user["username"], issuer_name="Thiranex Task 4"
    )
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    import base64

    qr_data_uri = "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    return render_template("setup_2fa.html", user=user, secret=secret, qr_data_uri=qr_data_uri)


@app.route("/disable-2fa", methods=["POST"])
@login_required
def disable_2fa():
    db = get_db()
    db.execute(
        "UPDATE users SET totp_secret = NULL, twofa_enabled = 0 WHERE id = ?",
        (current_user()["id"],),
    )
    db.commit()
    flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("dashboard"))


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    init_db()
    # Local development only — never expose this directly to the internet.
    app.run(host="127.0.0.1", port=5000, debug=False)
