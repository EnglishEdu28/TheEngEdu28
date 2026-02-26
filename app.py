from flask import (
    Flask, render_template, request, redirect, url_for,
    session, abort, flash, send_from_directory
)
import os
import time
import secrets
import hashlib
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# Cloudinary
import cloudinary
import cloudinary.uploader

# PostgreSQL (psycopg3)
import psycopg
from psycopg.rows import dict_row


# -----------------------------
# APP CONFIG
# -----------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change_this_to_any_random_string")

MAX_ATTEMPTS = 3
LOCK_SECONDS = 5 * 60  # 5 minutes

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")  # change on Render

RESET_TOKEN_EXPIRE_SECONDS = 15 * 60

MAIL_HOST = os.environ.get("MAIL_HOST", "smtp.gmail.com")
MAIL_PORT = int(os.environ.get("MAIL_PORT", "465"))
MAIL_USERNAME = os.environ.get("MAIL_USERNAME", "")
MAIL_APP_PASSWORD = os.environ.get("MAIL_APP_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", MAIL_USERNAME)

# Keep local uploads folder only as legacy fallback (Render disk is not permanent)
UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", "uploads")
MAX_FILE_SIZE = 20 * 1024 * 1024
ALLOWED_EXTENSIONS = {
    "pdf", "doc", "docx", "txt",
    "png", "jpg", "jpeg", "gif",
    "zip", "rar", "ppt", "pptx",
    "xls", "xlsx"
}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = MAX_FILE_SIZE

# Cloudinary reads CLOUDINARY_URL from environment
cloudinary.config(secure=True)


# -----------------------------
# POSTGRES DB
# -----------------------------
def _ensure_sslmode(url: str) -> str:
    if not url:
        return url
    lower = url.lower()
    if "sslmode=" in lower:
        return url
    if "?" in url:
        return url + "&sslmode=require"
    return url + "?sslmode=require"


def db():
    url = os.environ.get("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is not set (Render Environment).")
    url = _ensure_sslmode(url)
    # dict_row makes fetchone()/fetchall() return dict-like rows
    return psycopg.connect(url, row_factory=dict_row)


# -----------------------------
# UTILITIES
# -----------------------------
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


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


# -----------------------------
# DB INIT (Postgres)
# -----------------------------
def init_db():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT,
                    password_hash TEXT NOT NULL,
                    attempts_left INTEGER NOT NULL DEFAULT 3,
                    lock_until BIGINT NOT NULL DEFAULT 0
                );
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS password_resets (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
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
                    stored_name TEXT NOT NULL,
                    size BIGINT NOT NULL,
                    uploaded_at BIGINT NOT NULL,
                    cloud_public_id TEXT,
                    cloud_url TEXT
                );
            """)

            # Ensure admin user exists
            cur.execute("SELECT id FROM users WHERE username=%s", (ADMIN_USERNAME,))
            if cur.fetchone() is None:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, attempts_left, lock_until)
                    VALUES (%s, %s, %s, %s, %s)
                """, (ADMIN_USERNAME, "", generate_password_hash(ADMIN_PASSWORD), MAX_ATTEMPTS, 0))

        conn.commit()


# -----------------------------
# USER QUERIES
# -----------------------------
def get_user(username: str):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE username=%s", (username,))
            return cur.fetchone()


def get_user_by_id(user_id: int):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM users WHERE id=%s", (user_id,))
            return cur.fetchone()


def create_user(username: str, email: str, password: str) -> bool:
    try:
        with db() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO users (username, email, password_hash, attempts_left, lock_until)
                    VALUES (%s, %s, %s, %s, %s)
                """, (username, email, generate_password_hash(password), MAX_ATTEMPTS, 0))
            conn.commit()
        return True
    except Exception:
        # Most likely unique violation on username
        return False


def update_attempts_and_lock(user_id: int, attempts_left: int, lock_until: int):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET attempts_left=%s, lock_until=%s WHERE id=%s",
                (attempts_left, lock_until, user_id)
            )
        conn.commit()


def reset_user_security(user_id: int):
    update_attempts_and_lock(user_id, MAX_ATTEMPTS, 0)


def set_user_password(user_id: int, new_password: str):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE users SET password_hash=%s WHERE id=%s",
                (generate_password_hash(new_password), user_id)
            )
        conn.commit()


# -----------------------------
# EMAIL RESET
# -----------------------------
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

    with db() as conn:
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
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT * FROM password_resets
                WHERE token_hash=%s AND used=FALSE AND expires_at>%s
                ORDER BY id DESC LIMIT 1
            """, (token_hash, now))
            return cur.fetchone()


def mark_reset_used(reset_id: int):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE password_resets SET used=TRUE WHERE id=%s", (reset_id,))
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
        if user["lock_until"] > now:
            remaining = user["lock_until"] - now
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


@app.route("/files")
def files():
    redir = require_login()
    if redir:
        return redir

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM files ORDER BY uploaded_at DESC")
            rows = cur.fetchall()
    return render_template("files.html", files=rows)


# -----------------------------
# FILE UPLOAD (Cloudinary)
# -----------------------------
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
    public_id = f"uploads/{session['username']}_{int(time.time())}_{secrets.token_hex(8)}"

    try:
        result = cloudinary.uploader.upload(
            f,
            resource_type="raw",
            public_id=public_id,
            overwrite=False
        )
    except Exception as e:
        flash(f"Cloud upload failed: {e}", "error")
        return redirect(url_for("files"))

    url = result.get("secure_url")
    size = int(result.get("bytes") or 0)
    now = int(time.time())

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO files (username, original_name, stored_name, size, uploaded_at, cloud_public_id, cloud_url)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (session["username"], original, public_id, size, now, public_id, url))
        conn.commit()

    flash("Uploaded successfully ✅ (saved on Cloudinary)", "success")
    return redirect(url_for("files"))


@app.route("/download/<int:file_id>")
def download(file_id):
    redir = require_login()
    if redir:
        return redir

    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM files WHERE id=%s", (file_id,))
            row = cur.fetchone()

    if not row:
        abort(404)

    if row.get("cloud_url"):
        return redirect(row["cloud_url"])

    # legacy fallback
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
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM files WHERE id=%s", (file_id,))
            row = cur.fetchone()
            if not row:
                abort(404)

            cur.execute("DELETE FROM files WHERE id=%s", (file_id,))
        conn.commit()

    public_id = row.get("cloud_public_id") or row.get("stored_name")
    if row.get("cloud_url") and public_id:
        try:
            cloudinary.uploader.destroy(public_id, resource_type="raw")
        except Exception:
            pass

    flash("Deleted ✅", "success")
    return redirect(url_for("files"))


# -----------------------------
# ADMIN PANEL
# -----------------------------
def get_all_users():
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT id, username, email, attempts_left, lock_until FROM users ORDER BY id DESC")
            return cur.fetchall()


def delete_user_by_id(user_id: int):
    with db() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()


@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["is_admin"] = True
            session["admin_username"] = username
            return redirect(url_for("admin_panel"))

        return render_template("admin_login.html", error="Invalid admin credentials ❌")

    return render_template("admin_login.html")


@app.route("/admin/logout")
def admin_logout():
    session.pop("admin_username", None)
    if session.get("username", "").lower() != ADMIN_USERNAME.lower():
        session.pop("is_admin", None)
    return redirect(url_for("admin_login"))


@app.route("/admin")
def admin_panel():
    require_admin()
    users = get_all_users()
    now = int(time.time())

    users_view = []
    for u in users:
        remaining = (u["lock_until"] - now) if (u["lock_until"] and u["lock_until"] > now) else 0
        users_view.append({
            "id": u["id"],
            "username": u["username"],
            "email": u["email"],
            "attempts_left": u["attempts_left"],
            "lock_until": u["lock_until"],
            "remaining": remaining
        })

    return render_template("admin.html", users=users_view, admin=session.get("admin_username", ADMIN_USERNAME))


@app.route("/admin/reset/<int:user_id>", methods=["POST"])
def admin_reset_user(user_id):
    require_admin()
    reset_user_security(user_id)
    return redirect(url_for("admin_panel"))


@app.route("/admin/delete/<int:user_id>", methods=["POST"])
def admin_delete_user(user_id):
    require_admin()

    user = get_user_by_id(user_id)
    if user and user["username"].lower() == ADMIN_USERNAME.lower():
        flash("You can't delete the admin account.", "error")
        return redirect(url_for("admin_panel"))

    delete_user_by_id(user_id)
    return redirect(url_for("admin_panel"))


# Optional reset pages (only if you already have forgot.html / reset.html)
@app.route("/forgot", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        user = get_user(username)

        if user and user.get("email"):
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


# Render needs this on import
init_db()
