from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, flash
)
import os
import time
import secrets
import hashlib
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

import cloudinary
import cloudinary.uploader

import psycopg
from psycopg.rows import dict_row


# =============================
# CONFIG
# =============================
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_this_to_any_random_string")

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing. Set DATABASE_URL in Render env vars.")

# Ensure sslmode=require
if "sslmode=" not in DATABASE_URL:
    DATABASE_URL += "&sslmode=require" if "?" in DATABASE_URL else "?sslmode=require"

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")

MAX_ATTEMPTS = 3
LOCK_SECONDS = 5 * 60

RESET_TOKEN_EXPIRE_SECONDS = 15 * 60

MAIL_HOST = os.environ.get("MAIL_HOST", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "465"))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_APP_PASSWORD = os.environ.get("MAIL_APP_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", MAIL_USERNAME)

MAX_FILE_SIZE = 20 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt",
    "png", "jpg", "jpeg", "gif",
    "zip", "rar", "ppt", "pptx",
    "xls", "xlsx"
}
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

CLOUDINARY_URL = os.environ.get("CLOUDINARY_URL", "").strip()
if not CLOUDINARY_URL:
    raise RuntimeError("CLOUDINARY_URL is missing. Set CLOUDINARY_URL in Render env vars.")
cloudinary.config(cloudinary_url=CLOUDINARY_URL)


# =============================
# DB (Supabase Postgres via psycopg v3)
# =============================
def db_conn():
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def init_db():
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    password_hash TEXT NOT NULL,
                    attempts_left INT NOT NULL DEFAULT 3,
                    lock_until BIGINT NOT NULL DEFAULT 0
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_resets (
                    id SERIAL PRIMARY KEY,
                    user_id INT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash TEXT NOT NULL,
                    expires_at BIGINT NOT NULL,
                    used BOOLEAN NOT NULL DEFAULT FALSE,
                    created_at BIGINT NOT NULL
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS files (
                    id SERIAL PRIMARY KEY,
                    username TEXT NOT NULL,
                    original_name TEXT NOT NULL,
                    size BIGINT NOT NULL,
                    uploaded_at BIGINT NOT NULL,
                    url TEXT NOT NULL,
                    storage TEXT NOT NULL DEFAULT 'cloudinary'
                );
            """)

            # Ensure admin exists
            cur.execute("SELECT id FROM users WHERE username=%s", (ADMIN_USERNAME,))
            if not cur.fetchone():
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, attempts_left, lock_until)
                    VALUES (%s, %s, %s, %s, %s)
                """, (ADMIN_USERNAME, "", generate_password_hash(ADMIN_PASSWORD), MAX_ATTEMPTS, 0))

        conn.commit()


# =============================
# HELPERS
# =============================
def allowed_file(filename: str) -> bool:
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def require_login():
    if "user_id" not in session:
        return redirect(url_for("login"))
    return None


def get_user(username: str):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cur.fetchone()


def get_user_by_id(user_id: int):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            return cur.fetchone()


def create_user(username: str, email: str, password: str) -> bool:
    try:
        with db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, attempts_left, lock_until)
                    VALUES (%s, %s, %s, %s, %s)
                """, (username, email, generate_password_hash(password), MAX_ATTEMPTS, 0))
            conn.commit()
        return True
    except Exception as e:
        print("create_user error:", e)
        return False


def update_attempts_and_lock(user_id: int, attempts_left: int, lock_until: int):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET attempts_left=%s, lock_until=%s WHERE id=%s",
                (attempts_left, lock_until, user_id)
            )
        conn.commit()


def reset_user_security(user_id: int):
    update_attempts_and_lock(user_id, MAX_ATTEMPTS, 0)


def set_user_password(user_id: int, new_password: str):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (generate_password_hash(new_password), user_id)
            )
        conn.commit()


# =============================
# PASSWORD RESET
# =============================
def send_reset_email(to_email: str, reset_link: str):
    if not MAIL_USERNAME or not MAIL_APP_PASSWORD or not MAIL_FROM:
        raise RuntimeError("Email not configured.")

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

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE password_resets SET used=TRUE WHERE user_id=%s", (user_id,))
            cur.execute("""
                INSERT INTO password_resets (user_id, token_hash, expires_at, used, created_at)
                VALUES (%s, %s, %s, FALSE, %s)
            """, (user_id, token_hash, expires_at, now))
        conn.commit()

    return raw_token


def find_valid_reset(token: str):
    token_hash = sha256_hex(token)
    now = int(time.time())
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM password_resets
                WHERE token_hash=%s AND used=FALSE AND expires_at>%s
                ORDER BY id DESC LIMIT 1
            """, (token_hash, now))
            return cur.fetchone()


def mark_reset_used(reset_id: int):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE password_resets SET used=TRUE WHERE id=%s", (reset_id,))
        conn.commit()


# =============================
# CLOUDINARY UPLOAD
# =============================
def upload_to_cloudinary(file_storage, public_id_base: str):
    filename = file_storage.filename or ""
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""

    resource_type = "raw" if ext in [
        "pdf", "doc", "docx", "ppt", "pptx", "xls", "xlsx", "zip", "rar", "txt"
    ] else "image"

    result = cloudinary.uploader.upload(
        file_storage,
        public_id=f"uploads/{public_id_base}",
        resource_type=resource_type,
        overwrite=True
    )

    url = result.get("secure_url") or result.get("url")
    size = int(result.get("bytes") or 0)
    return url, size


# =============================
# ROUTES
# =============================
@app.route("/")
def home():
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if username.lower() == ADMIN_USERNAME.lower():
            return render_template("register.html", error="This username is reserved. Choose another.")
        if len(username) < 3:
            return render_template("register.html", error="Username must be at least 3 characters.")
        if "@" not in email or "." not in email:
            return render_template("register.html", error="Enter a valid email address.")
        if len(password) < 4:
            return render_template("register.html", error="Password must be at least 4 characters.")

        if not create_user(username, email, password):
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
        if int(user["lock_until"]) > now:
            remaining = int(user["lock_until"]) - now
            return render_template("login.html", locked=True, remaining_seconds=remaining)

        if check_password_hash(user["password_hash"], password):
            reset_user_security(user["id"])
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["is_admin"] = (user["username"].lower() == ADMIN_USERNAME.lower())
            return redirect(url_for("dashboard"))

        attempts_left = int(user["attempts_left"]) - 1
        if attempts_left <= 0:
            update_attempts_and_lock(user["id"], 0, now + LOCK_SECONDS)
            return render_template("login.html", locked=True, remaining_seconds=LOCK_SECONDS)

        update_attempts_and_lock(user["id"], attempts_left, 0)
        return render_template("login.html", error=f"Wrong password. Attempts left: {attempts_left}")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


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
    locked = int(user["lock_until"]) > now
    remaining = (int(user["lock_until"]) - now) if locked else 0

    return render_template(
        "profile.html",
        username=user["username"],
        attempts_left=user["attempts_left"],
        locked=locked,
        remaining=remaining,
        is_admin=session.get("is_admin", False)
    )


@app.route("/files")
def files():
    redir = require_login()
    if redir:
        return redir

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM files ORDER BY LOWER(original_name) ASC;")
            rows = cur.fetchall()

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
    public_id_base = f"admin_{int(time.time())}_{os.urandom(6).hex()}"

    try:
        url, size = upload_to_cloudinary(f, public_id_base)
    except Exception as e:
        print("Cloudinary upload error:", e)
        flash("Upload failed. Check Render logs.", "error")
        return redirect(url_for("files"))

    now = int(time.time())
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO files (username, original_name, size, uploaded_at, url, storage)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session.get("username", "admin"), original, size, now, url, "cloudinary"))
        conn.commit()

    flash("Uploaded successfully ✅", "success")
    return redirect(url_for("files"))


@app.route("/download/<int:file_id>")
def download(file_id):
    redir = require_login()
    if redir:
        return redir

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM files WHERE id=%s", (file_id,))
            row = cur.fetchone()

    if not row:
        abort(404)

    return redirect(row["url"])


# -------- Forgot / Reset routes (fixes your login.html error) --------
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_user(username)

        # Always return same message (avoid account enumeration)
        if user and user.get("email"):
            try:
                token = create_password_reset(user["id"])
                reset_link = url_for("reset_password", token=token, _external=True)
                send_reset_email(user["email"], reset_link)
            except Exception as e:
                print("send reset error:", e)

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


# =============================
# STARTUP
# =============================
init_db()

if __name__ == "__main__":
    app.run(debug=True)
