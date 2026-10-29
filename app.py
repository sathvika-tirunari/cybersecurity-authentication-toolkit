"""Cybersecurity Authentication Toolkit: a small, beginner-friendly Flask login system.

Run:  python app.py   then open http://127.0.0.1:5000
"""
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# --- Safe configuration: the secret comes from the environment, never from source code ---
_secret = os.environ.get("SECRET_KEY")
if not _secret:
    _secret = secrets.token_hex(32)  # random per start-up: fine for local demos, sessions reset on restart
    print("NOTE: SECRET_KEY not set. Using a temporary random key (sessions reset when the app restarts).")
app.config.update(
    SECRET_KEY=_secret,
    DATABASE=os.environ.get("DATABASE_PATH", os.path.join(BASE_DIR, "users.db")),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",  # set to 1 behind HTTPS
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
)

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MAX_ATTEMPTS, LOCK_SECONDS = 5, 300
_failed = {}  # (ip, username) -> (count, first_time)   in-memory demo throttle


# ---------------------------------------------------------------- database
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(app.config["DATABASE"]) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)""")


# ---------------------------------------------------------------- CSRF + validation
def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent = request.form.get("csrf_token", "")
        if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
            abort(400, "Invalid or missing CSRF token. Reload the page and try again.")


@app.after_request
def security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Content-Security-Policy"] = "default-src 'self'"
    resp.headers["Cache-Control"] = "no-store"
    return resp


def validate_registration(username, email, password, confirm):
    errors = []
    if not USERNAME_RE.match(username):
        errors.append("Username must be 3-30 characters: letters, numbers and underscore only.")
    if len(email) > 254 or not EMAIL_RE.match(email):
        errors.append("Please enter a valid email address.")
    if len(password) < 10:
        errors.append("Password must be at least 10 characters long.")
    if len(password) > 128:
        errors.append("Password must be at most 128 characters long.")
    if not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        errors.append("Password must contain at least one letter and one number.")
    if password != confirm:
        errors.append("Password and confirmation do not match.")
    return errors


# ---------------------------------------------------------------- routes
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        errors = validate_registration(username, email, password, confirm)
        if not errors:
            try:
                get_db().execute(
                    "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                    (username, email, generate_password_hash(password)),  # salted PBKDF2/scrypt hash
                )
                get_db().commit()
                flash("Account created. You can now log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                errors.append("That username or email is already registered.")
        for e in errors:
            flash(e, "error")
        return render_template("register.html", username=username, email=email), 400
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        key = (request.remote_addr, username.lower())
        count, first = _failed.get(key, (0, 0))
        if count >= MAX_ATTEMPTS and time.time() - first < LOCK_SECONDS:
            flash("Too many failed attempts. Please wait a few minutes and try again.", "error")
            return render_template("login.html", username=username), 429
        row = get_db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            _failed.pop(key, None)
            session.clear()  # prevents session fixation
            session.permanent = True
            session["user_id"], session["username"] = row["id"], row["username"]
            return redirect(url_for("dashboard"))
        if time.time() - first >= LOCK_SECONDS:
            count, first = 0, time.time()
        _failed[key] = (count + 1, first or time.time())
        flash("Invalid username or password.", "error")  # same message for both cases
        return render_template("login.html", username=username), 401
    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in to view that page.", "error")
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("index"))


@app.errorhandler(400)
def bad_request(e):
    return render_template("error.html", message=e.description), 400


@app.errorhandler(404)
def not_found(_e):
    return render_template("error.html", message="Page not found."), 404


init_db()

if __name__ == "__main__":
    # debug is OFF by default (debug mode must never be enabled in production)
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("FLASK_DEBUG") == "1")
