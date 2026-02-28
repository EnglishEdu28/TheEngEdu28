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

# ---- IMPORTANT: stable secret key ----
app.secret_key = os.environ.get("SECRET_KEY", "")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY is missing in environment variables.")

# ---- IMPORTANT: Render proxy/session stability ----
# Render uses HTTPS in front of your service; this makes Flask treat requests as secure.
app.config["PREFERRED_URL_SCHEME"] = "https"
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True  # must be True on Render (HTTPS)

DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is missing. Set DATABASE_URL in Render env vars.")

# Ensure sslmode=require
if "sslmode=" not in DATABASE_URL:
    DATABASE_URL += "&sslmode=require" if "?" in DATABASE_URL else "?sslmode=require"

ADMIN_USERNAME = (os.environ.get("ADMIN_USERNAME", "admin") or "admin").strip()
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
# DB
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

            # Ensure admin exists in DB
            cur.execute("SELECT id FROM users WHERE LOWER(username)=LOWER(%s)", (ADMIN_USERNAME,))
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


def is_logged_in() -> bool:
    return "user_id" in session and "username" in session


def require_login():
    if not is_logged_in():
        print("403 require_login: session missing", dict(session))
        return redirect(url_for("login"))
    return None


def require_admin():
    if not session.get("is_admin"):
        print("403 require_admin: not admin", dict(session))
        abort(403)


def get_user(username: str):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE LOWER(username)=LOWER(%s)", (username.strip(),))
            return cur.fetchone()


def get_user_by_id(user_id: int):
    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            return cur.fetchone()


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


@app.route("/whoami")
def whoami():
    # Debug page to prove what the server sees
    return {
        "logged_in": is_logged_in(),
        "user_id": session.get("user_id"),
        "username": session.get("username"),
        "is_admin": session.get("is_admin"),
        "admin_env": ADMIN_USERNAME,
    }


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

            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            # robust admin check
            session["is_admin"] = (user["username"].strip().lower() == ADMIN_USERNAME.strip().lower())

            print("LOGIN OK:", {"username": session["username"], "is_admin": session["is_admin"]})
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
    return render_template("dashboard.html", username=session.get("username"), is_admin=session.get("is_admin", False))


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
        email=user.get("email", ""),
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

    return render_template("files.html", files=rows, is_admin=session.get("is_admin", False))


@app.route("/upload", methods=["POST"])
def upload():
    redir = require_login()
    if redir:
        return redir
    require_admin()

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


@app.route("/file/<int:file_id>")
def file_view(file_id):
    redir = require_login()
    if redir:
        return redir

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM files WHERE id=%s", (file_id,))
            row = cur.fetchone()

    if not row:
        abort(404)

    name = row["original_name"]
    ext = name.rsplit(".", 1)[1].lower() if "." in name else ""
    is_pdf = (ext == "pdf")

    return render_template("file_view.html", f=row, is_pdf=is_pdf, is_admin=session.get("is_admin", False))


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


@app.route("/delete/<int:file_id>", methods=["POST"])
def delete(file_id):
    redir = require_login()
    if redir:
        return redir
    require_admin()

    with db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM files WHERE id=%s", (file_id,))
        conn.commit()

    flash("Deleted ✅", "success")
    return redirect(url_for("files"))


# =============================
# ERROR PAGES
# =============================
@app.errorhandler(403)
def forbidden(e):
    return render_template("error.html", code=403, message="Forbidden"), 403


@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="Not Found"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="Internal Server Error"), 500


# =============================
# STARTUP
# =============================
init_db()

if __name__ == "__main__":
    app.run(debug=True)
