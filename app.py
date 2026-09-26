import os
import sqlite3
from functools import wraps

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash
)

from flask_wtf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

from database import get_connection, init_database
from encryption import encrypt_password, decrypt_password
from password_generator import generate_password


load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY is missing from .env")

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = False
app.config["SESSION_COOKIE_PATH"] = "/"
app.config["SESSION_COOKIE_NAME"] = "password_manager_session"

# Diagnostic code - put this BEFORE CSRFProtect
@app.before_request
def debug_csrf_session():
    if request.endpoint == "register":
        print("\n========== CSRF DEBUG ==========")
        print("Method:", request.method)
        print("Session CSRF present:", "csrf_token" in session)
        print("Session CSRF token:", session.get("csrf_token"))
        print(
            "Session cookie present:",
            app.config.get("SESSION_COOKIE_NAME", "session")
            in request.cookies
        )
        print("Cookies received:", request.cookies)
        print("================================\n")


csrf = CSRFProtect(app)

init_database()


def login_required(function):

    @wraps(function)
    def decorated_function(*args, **kwargs):

        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))

        return function(*args, **kwargs)

    return decorated_function


@app.route("/")
def index():

    if "user_id" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()

        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return redirect(url_for("register"))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must contain at least 8 characters.", "danger")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)

        connection = get_connection()

        try:

            connection.execute(
                """
                INSERT INTO users
                (username, email, password_hash)
                VALUES (?, ?, ?)
                """,
                (username, email, password_hash)
            )

            connection.commit()

        except sqlite3.IntegrityError:

            connection.close()

            flash(
                "Username or email already exists.",
                "danger"
            )

            return redirect(url_for("register"))

        connection.close()

        flash("Registration successful. Please log in.", "success")

        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        connection = get_connection()

        user = connection.execute(
            """
            SELECT id, username, email, password_hash
            FROM users
            WHERE email = ?
            """,
            (email,)
        ).fetchone()

        connection.close()

        if user and check_password_hash(
            user["password_hash"],
            password
        ):

            session.clear()

            session["user_id"] = user["id"]
            session["username"] = user["username"]

            flash("Login successful.", "success")

            return redirect(url_for("dashboard"))

        flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():

    session.clear()

    flash("You have been logged out.", "success")

    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():

    connection = get_connection()

    credentials = connection.execute(
        """
        SELECT
            id,
            service_name,
            username,
            website_url,
            created_at,
            updated_at
        FROM credentials
        WHERE user_id = ?
        ORDER BY service_name
        """,
        (session["user_id"],)
    ).fetchall()

    connection.close()

    return render_template(
        "dashboard.html",
        credentials=credentials
    )


@app.route("/credential/add", methods=["GET", "POST"])
@login_required
def add_credential():

    if request.method == "POST":

        service_name = request.form.get(
            "service_name",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        website_url = request.form.get(
            "website_url",
            ""
        ).strip()

        if not service_name or not username or not password:
            flash(
                "Service, username and password are required.",
                "danger"
            )

            return redirect(url_for("add_credential"))

        encrypted_password = encrypt_password(password)

        connection = get_connection()

        connection.execute(
            """
            INSERT INTO credentials
            (
                user_id,
                service_name,
                username,
                encrypted_password,
                website_url
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                session["user_id"],
                service_name,
                username,
                encrypted_password,
                website_url
            )
        )

        connection.commit()
        connection.close()

        flash("Credential saved securely.", "success")

        return redirect(url_for("dashboard"))

    return render_template("add_password.html")


@app.route("/credential/<int:credential_id>/view")
@login_required
def view_credential(credential_id):

    connection = get_connection()

    credential = connection.execute(
        """
        SELECT *
        FROM credentials
        WHERE id = ?
        AND user_id = ?
        """,
        (
            credential_id,
            session["user_id"]
        )
    ).fetchone()

    connection.close()

    if credential is None:
        flash("Credential not found.", "danger")
        return redirect(url_for("dashboard"))

    try:
        decrypted_password = decrypt_password(
            credential["encrypted_password"]
        )

    except Exception:
        flash("Unable to decrypt credential.", "danger")
        return redirect(url_for("dashboard"))

    return render_template(
        "dashboard.html",
        credentials=[],
        revealed=credential,
        decrypted_password=decrypted_password
    )


@app.route(
    "/credential/<int:credential_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_credential(credential_id):

    connection = get_connection()

    credential = connection.execute(
        """
        SELECT *
        FROM credentials
        WHERE id = ?
        AND user_id = ?
        """,
        (
            credential_id,
            session["user_id"]
        )
    ).fetchone()

    if credential is None:

        connection.close()

        flash("Credential not found.", "danger")

        return redirect(url_for("dashboard"))

    if request.method == "POST":

        service_name = request.form.get(
            "service_name",
            ""
        ).strip()

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        website_url = request.form.get(
            "website_url",
            ""
        ).strip()

        if not service_name or not username or not password:

            connection.close()

            flash(
                "Service, username and password are required.",
                "danger"
            )

            return redirect(
                url_for(
                    "edit_credential",
                    credential_id=credential_id
                )
            )

        encrypted_password = encrypt_password(password)

        connection.execute(
            """
            UPDATE credentials
            SET
                service_name = ?,
                username = ?,
                encrypted_password = ?,
                website_url = ?,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            AND user_id = ?
            """,
            (
                service_name,
                username,
                encrypted_password,
                website_url,
                credential_id,
                session["user_id"]
            )
        )

        connection.commit()
        connection.close()

        flash("Credential updated.", "success")

        return redirect(url_for("dashboard"))

    connection.close()

    return render_template(
        "edit_password.html",
        credential=credential
    )


@app.route(
    "/credential/<int:credential_id>/delete",
    methods=["POST"]
)
@login_required
def delete_credential(credential_id):

    connection = get_connection()

    connection.execute(
        """
        DELETE FROM credentials
        WHERE id = ?
        AND user_id = ?
        """,
        (
            credential_id,
            session["user_id"]
        )
    )

    connection.commit()
    connection.close()

    flash("Credential deleted.", "success")

    return redirect(url_for("dashboard"))


@app.route("/generate-password")
@login_required
def generate_password_page():

    generated_password = generate_password(16)

    return render_template(
        "add_password.html",
        generated_password=generated_password
    )


if __name__ == "__main__":

    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )