from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, flash, send_from_directory
)
import sqlite3
import time
import os
import secrets
import hashlib
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# -----------------------------
# APP CONFIG
# -----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_this_to_any_random_string")

DB_NAME = os.environ.get("DB_NAME", "users.db")

MAX_ATTEMPTS = 3
LOCK_SECONDS = 5 * 60  # 5 minutes

# Admin (for normal /login + uploading)
ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # change this on Render!

# Password reset tokens
RESET_TOKEN_EXPIRE_SECONDS = 15 * 60  # 15 minutes

# Email (optional)
MAIL_HOST = os.environ.get("MAIL_HOST", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "465"))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_APP_PASSWORD = os.environ.get("MAIL_APP_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", MAIL_USERNAME)

# -----------------------------
# FILE STORAGE
# -----------------------------
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")  # Render free: ephemeral
MAX_FILE_SIZE = 20 * 1024 * 1024  # 20MB
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt",
    "png", "jpg", "jpeg", "gif",
    "zip", "rar", "ppt", "pptx",
    "xls", "xlsx"
}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE


# -----------------------------
# DB HELPERS
# -----------------------------
def db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def init_db():
    """Create tables + auto-create admin user if not exists."""
    with db() as conn:
        cur = conn.cursor()

        # USERS table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                email TEXT,
                password_hash TEXT NOT NULL,
                attempts_left INTEGER NOT NULL DEFAULT 3,
                lock_until INTEGER NOT NULL DEFAULT 0
            )
        """)

        # PASSWORD RESETS table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)

        # FILES table (shared library)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL,
                size INTEGER NOT NULL,
                uploaded_at INTEGER NOT NULL
            )
        """)

        # Ensure admin user exists (for /login and uploads)
        cur.execute("SELECT id FROM users WHERE username = ?", (ADMIN_USERNAME,))
        exists = cur.fetchone()
        if not exists:
            cur.execute("""
                INSERT INTO users (username, email, password_hash, attempts_left, lock_until)
                VALUES (?, ?, ?, ?, ?)
            """, (ADMIN_USERNAME, "", generate_password_hash(ADMIN_PASSWORD), MAX_ATTEMPTS, 0))

        conn.commit()


# -----------------------------
# SECURITY + USER HELPERS
# -----------------------------
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def login_required() -> bool:
    return "user_id" in session


def require_login():
    if not login_required():
        return redirect(url_for("login"))
    return None


def require_admin():
    if not session.get("is_admin"):
        abort(403)


def get_user(username: str):
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id: int):
    with db() as conn:
        return conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def create_user(username: str, email: str, password: str) -> bool:
    try:
        with db() as conn:
            conn.execute("""
                INSERT INTO users (username, email, password_hash, attempts_left, lock_until)
                VALUES (?, ?, ?, ?, ?)
            """, (username, email, generate_password_hash(password), MAX_ATTEMPTS, 0))
            conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False


def update_attempts_and_lock(user_id: int, attempts_left: int, lock_until: int):
    with db() as conn:
        conn.execute(
            "UPDATE users SET attempts_left = ?, lock_until = ? WHERE id = ?",
            (attempts_left, lock_until, user_id)
        )
        conn.commit()


def reset_user_security(user_id: int):
    update_attempts_and_lock(user_id, MAX_ATTEMPTS, 0)


def set_user_password(user_id: int, new_password: str):
    with db() as conn:
        conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (generate_password_hash(new_password), user_id)
        )
        conn.commit()


# -----------------------------
# PASSWORD RESET (optional)
# -----------------------------
def send_reset_email(to_email: str, reset_link: str):
    if not MAIL_USERNAME or not MAIL_APP_PASSWORD or not MAIL_FROM:
        raise RuntimeError("Email not configured. Set MAIL_USERNAME and MAIL_APP_PASSWORD on Render.")

    msg = EmailMessage()
    msg["Subject"] = "Password Reset Link"
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.set_content(
        "You requested a password reset.\n\n"
        f"Reset your password (expires in 15 minutes):\n{reset_link}\n\n"
        "If you did not request this, ignore this email."
    )

    with smtplib.SMTP_SSL(MAIL_HOST, MAIL_PORT) as smtp:
        smtp.login(MAIL_USERNAME, MAIL_APP_PASSWORD)
        smtp.send_message(msg)


def create_password_reset(user_id: int) -> str:
    raw_token = secrets.token_urlsafe(32)
    token_hash = sha256_hex(raw_token)
    now = int(time.time())
    expires_at = now + RESET_TOKEN_EXPIRE_SECONDS

    with db() as conn:
        conn.execute("UPDATE password_resets SET used = 1 WHERE user_id = ?", (user_id,))
        conn.execute("""
            INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at)
            VALUES (?, ?, ?, 0, ?)
        """, (user_id, token_hash, expires_at, now))
        conn.commit()

    return raw_token


def find_valid_reset(token: str):
    token_hash = sha256_hex(token)
    now = int(time.time())
    with db() as conn:
        return conn.execute("""
            SELECT * FROM password_resets
            WHERE token_hash = ? AND used = 0 AND expires_at > ?
            ORDER BY id DESC LIMIT 1
        """, (token_hash, now)).fetchone()


def mark_reset_used(reset_id: int):
    with db() as conn:
        conn.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (reset_id,))
        conn.commit()


# -----------------------------
# ROUTES
# -----------------------------
@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        # Reserve admin username (so students can't take it)
        if username.lower() == ADMIN_USERNAME.lower():
            return render_template("register.html", error="This username is reserved. Choose another.")

        if len(username) < 3:
            return render_template("register.html", error="Username must be at least 3 characters.")
        if "@" not in email or "." not in email:
            return render_template("register.html", error="Enter a valid email address.")
        if len(password) < 4:
            return render_template("register.html", error="Password must be at least 4 characters.")

        ok = create_user(username, email, password)
        if not ok:
            return render_template("register.html", error="Username already exists. Try another.")

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = get_user(username)
        if not user:
            return render_template("login.html", error="User not found ❌")

        now = int(time.time())

        # Locked?
        if user["lock_until"] > now:
            remaining = user["lock_until"] - now
            return render_template("login.html", locked=True, remaining_seconds=remaining)

        # Correct password?
        if check_password_hash(user["password_hash"], password):
            reset_user_security(user["id"])
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = (user["username"].lower() == ADMIN_USERNAME.lower())
            return redirect(url_for("dashboard"))

        # Wrong password -> reduce attempts
        attempts_left = user["attempts_left"] - 1
        if attempts_left <= 0:
            update_attempts_and_lock(user["id"], 0, now + LOCK_SECONDS)
            return render_template("login.html", locked=True, remaining_seconds=LOCK_SECONDS)

        update_attempts_and_lock(user["id"], attempts_left, 0)
        return render_template("login.html", error=f"Wrong password. Attempts left: {attempts_left}")

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    redir = require_login()
    if redir:
        return redir
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/profile")
def profile():
    redir = require_login()
    if redir:
        return redir

    user = get_user_by_id(session["user_id"])
    if not user:
        session.clear()
        return redirect(url_for("login"))

    now = int(time.time())
    locked = user["lock_until"] > now
    remaining = (user["lock_until"] - now) if locked else 0

    return render_template(
        "profile.html",
        username=user["username"],
        attempts_left=user["attempts_left"],
        locked=locked,
        remaining=remaining,
        is_admin=session.get("is_admin", False)
    )


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# -----------------------------
# FILES (Shared library)
# Admin uploads only, students download only
# -----------------------------
@app.route("/files")
def files():
    redir = require_login()
    if redir:
        return redir

    with db() as conn:
        rows = conn.execute("SELECT * FROM files ORDER BY uploaded_at DESC").fetchall()
    return render_template("files.html", files=rows)


@app.route("/upload", methods=["POST"])
def upload():
    redir = require_login()
    if redir:
        return redir
    if not session.get("is_admin"):
        abort(403)

    if "file" not in request.files:
        flash("No file selected", "error")
        return redirect(url_for("files"))

    f = request.files["file"]
    if not f or f.filename == "":
        flash("No file selected", "error")
        return redirect(url_for("files"))

    if not allowed_file(f.filename):
        flash("File type not allowed", "error")
        return redirect(url_for("files"))

    original = secure_filename(f.filename)
    ext = original.rsplit(".", 1)[1].lower()
    stored = f"admin_{int(time.time())}_{os.urandom(6).hex()}.{ext}"

    save_path = os.path.join(app.config["UPLOAD_FOLDER"], stored)
    f.save(save_path)
    size = os.path.getsize(save_path)

    with db() as conn:
        conn.execute("""
            INSERT INTO files (username, original_name, stored_name, size, uploaded_at)
            VALUES (?, ?, ?, ?, ?)
        """, (session["username"], original, stored, size, int(time.time())))
        conn.commit()

    flash("Uploaded successfully ✅", "success")
    return redirect(url_for("files"))


@app.route("/download/<int:file_id>")
def download(file_id):
    redir = require_login()
    if redir:
        return redir

    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()

    if not row:
        abort(404)

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        row["stored_name"],
        as_attachment=True,
        download_name=row["original_name"]
    )


@app.route("/delete/<int:file_id>", methods=["POST"])
def delete(file_id):
    redir = require_login()
    if redir:
        return redir
    if not session.get("is_admin"):
        abort(403)

    with db() as conn:
        row = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
        if not row:
            abort(404)

        conn.execute("DELETE FROM files WHERE id=?", (file_id,))
        conn.commit()

    path = os.path.join(app.config["UPLOAD_FOLDER"], row["stored_name"])
    if os.path.exists(path):
        os.remove(path)

    flash("Deleted ✅", "success")
    return redirect(url_for("files"))


# -----------------------------
# OPTIONAL: Forgot / Reset routes
# (Only if your templates exist: forgot.html, reset.html)
# -----------------------------
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_user(username)

        if user and user["email"]:
            try:
                token = create_password_reset(user["id"])
                reset_link = url_for("reset_password", token=token, _external=True)
                send_reset_email(user["email"], reset_link)
            except Exception:
                pass

        return render_template("forgot.html", info="If that account exists, a reset link has been sent.")

    return render_template("forgot.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    reset_row = find_valid_reset(token)
    if not reset_row:
        return render_template("reset.html", invalid=True)

    if request.method == "POST":
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        if len(password) < 4:
            return render_template("reset.html", invalid=False, error="Password must be at least 4 characters.")
        if password != confirm:
            return render_template("reset.html", invalid=False, error="Passwords do not match.")

        set_user_password(reset_row["user_id"], password)
        reset_user_security(reset_row["user_id"])
        mark_reset_used(reset_row["id"])
        return render_template("reset.html", success=True)

    return render_template("reset.html", invalid=False)


# Initialize DB when app starts (important for Render)
init_db()