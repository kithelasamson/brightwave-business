
import os
import csv
import io
import sqlite3

from pathlib import Path
from functools import wraps
from contextlib import contextmanager

from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
    Response,
    abort
)

from flask_wtf import FlaskForm, CSRFProtect

from wtforms import (
    StringField,
    PasswordField,
    TextAreaField,
    SubmitField
)

from wtforms.validators import (
    DataRequired,
    Email,
    Length,
    EqualTo,
    Regexp
)

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)


# ============================================================
# 1. APPLICATION CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "contacts.db"

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "dev-only-change-before-deployment"
)

app.config["WTF_CSRF_TIME_LIMIT"] = 3600

app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Enable secure cookies when deploying behind HTTPS.
app.config["SESSION_COOKIE_SECURE"] = (
    os.environ.get("COOKIE_SECURE", "0") == "1"
)

app.config["PERMANENT_SESSION_LIFETIME"] = 1800

# Limit incoming request size to 1 MB.
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

csrf = CSRFProtect(app)


# ============================================================
# 2. DATABASE CONNECTION
# ============================================================

@contextmanager
def get_db():

    connection = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


# ============================================================
# 3. FORM DEFINITIONS
# ============================================================

class ContactForm(FlaskForm):

    name = StringField(
        "Your name",
        validators=[
            DataRequired(),
            Length(min=2, max=100)
        ]
    )

    email = StringField(
        "Email address",
        validators=[
            DataRequired(),
            Email(),
            Length(max=254)
        ]
    )

    message = TextAreaField(
        "How can we help?",
        validators=[
            DataRequired(),
            Length(min=10, max=3000)
        ]
    )

    submit = SubmitField("Send message")


class AdminRegistrationForm(FlaskForm):

    username = StringField(
        "Administrator username",
        validators=[
            DataRequired(),
            Length(min=3, max=40),
            Regexp(
                r"^[A-Za-z0-9_.-]+$",
                message="Use letters, numbers, dots, hyphens or underscores."
            )
        ]
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(min=8, max=128),
            Regexp(
                r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)"
                r"(?=.*[^A-Za-z0-9]).{8,128}$",
                message=(
                    "Password must have at least 8 characters, "
                    "one uppercase letter, one lowercase letter, "
                    "one number and one symbol."
                )
            )
        ]
    )

    confirm_password = PasswordField(
        "Confirm password",
        validators=[
            DataRequired(),
            EqualTo(
                "password",
                message="Passwords do not match."
            )
        ]
    )

    submit = SubmitField("Create administrator account")


class AdminLoginForm(FlaskForm):

    username = StringField(
        "Username",
        validators=[
            DataRequired(),
            Length(max=40)
        ]
    )

    password = PasswordField(
        "Password",
        validators=[
            DataRequired(),
            Length(max=128)
        ]
    )

    submit = SubmitField("Login securely")


class LogoutForm(FlaskForm):

    submit = SubmitField("Logout")


class AdminActionForm(FlaskForm):

    submit = SubmitField("Confirm")


# ============================================================
# 4. DATABASE INITIALIZATION AND MIGRATION
# ============================================================

def init_db():

    with get_db() as connection:

        # Client contact messages.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS contacts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                name TEXT NOT NULL,

                email TEXT NOT NULL,

                message TEXT NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

            )
        """)

        # Only one administrator is permitted.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS admins (

                id INTEGER PRIMARY KEY CHECK (id = 1),

                username TEXT NOT NULL UNIQUE,

                password_hash TEXT NOT NULL,

                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

            )
        """)

        # Upgrade existing contacts table without deleting records.
        columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(contacts)"
            ).fetchall()
        }

        if "is_read" not in columns:

            connection.execute("""
                ALTER TABLE contacts

                ADD COLUMN is_read INTEGER NOT NULL DEFAULT 0
            """)


def admin_account_exists():

    with get_db() as connection:

        admin = connection.execute("""
            SELECT id
            FROM admins
            LIMIT 1
        """).fetchone()

    return admin is not None


# ============================================================
# 5. ADMINISTRATOR ACCESS CONTROL
# IMPORTANT: DEFINE THIS BEFORE USING @admin_required
# ============================================================

def admin_required(view_function):

    @wraps(view_function)
    def wrapped_view(*args, **kwargs):

        admin_id = session.get("admin_id")

        # Check whether the session contains the correct admin ID.
        if admin_id != 1:

            session.clear()

            flash(
                "Please log in to access the administrator dashboard.",
                "error"
            )

            return redirect(url_for("admin_login"))

        # Verify that the administrator still exists.
        with get_db() as connection:

            admin = connection.execute("""
                SELECT id
                FROM admins
                WHERE id = ?
            """, (admin_id,)).fetchone()

        if admin is None:

            session.clear()

            flash(
                "Your session is no longer valid. Please log in again.",
                "error"
            )

            return redirect(url_for("admin_login"))

        return view_function(*args, **kwargs)

    return wrapped_view


# ============================================================
# 6. PUBLIC WEBSITE ROUTES
# ============================================================

@app.route("/")
def home():

    form = ContactForm()

    return render_template(
        "index.html",
        form=form
    )


@app.route("/contact", methods=["POST"])
def contact():

    form = ContactForm()

    if form.validate_on_submit():

        with get_db() as connection:

            connection.execute("""
                INSERT INTO contacts (
                    name,
                    email,
                    message
                )

                VALUES (?, ?, ?)
            """, (
                form.name.data.strip(),
                form.email.data.strip(),
                form.message.data.strip()
            ))

        flash(
            "Thank you! Your message has been received.",
            "success"
        )

    else:

        flash(
            "Please check your details and try again.",
            "error"
        )

    return redirect(
        url_for("home") + "#contact"
    )


# ============================================================
# 7. FIRST ADMINISTRATOR REGISTRATION
# ============================================================

@app.route(
    "/admin/register",
    methods=["GET", "POST"]
)
def admin_register():

    # Registration is disabled after the first admin is created.
    if admin_account_exists():

        flash(
            "An administrator already exists. Registration is disabled.",
            "error"
        )

        return redirect(url_for("admin_login"))

    form = AdminRegistrationForm()

    if form.validate_on_submit():

        password_hash = generate_password_hash(
            form.password.data
        )

        try:

            with get_db() as connection:

                # Prevent simultaneous first-time registrations.
                connection.execute("BEGIN IMMEDIATE")

                existing = connection.execute("""
                    SELECT id
                    FROM admins
                    LIMIT 1
                """).fetchone()

                if existing:

                    flash(
                        "An administrator already exists.",
                        "error"
                    )

                    return redirect(url_for("admin_login"))

                connection.execute("""
                    INSERT INTO admins (
                        id,
                        username,
                        password_hash
                    )

                    VALUES (1, ?, ?)
                """, (
                    form.username.data.strip(),
                    password_hash
                ))

            flash(
                "Administrator account created successfully. "
                "You can now log in.",
                "success"
            )

            return redirect(
                url_for("admin_login")
            )

        except sqlite3.IntegrityError:

            flash(
                "Administrator account could not be created. "
                "An account may already exist.",
                "error"
            )

    return render_template(
        "admin_register.html",
        form=form
    )


# ============================================================
# 8. ADMINISTRATOR LOGIN
# ============================================================

@app.route(
    "/admin/login",
    methods=["GET", "POST"]
)
def admin_login():

    if session.get("admin_id") == 1:

        return redirect(
            url_for("admin_dashboard")
        )

    form = AdminLoginForm()

    if form.validate_on_submit():

        username = form.username.data.strip()

        with get_db() as connection:

            admin = connection.execute("""
                SELECT
                    id,
                    username,
                    password_hash

                FROM admins

                WHERE username = ?
            """, (username,)).fetchone()

        if admin and check_password_hash(
            admin["password_hash"],
            form.password.data
        ):

            # Prevent session fixation.
            session.clear()

            session["admin_id"] = admin["id"]

            session["admin_username"] = admin["username"]

            session.permanent = True

            flash(
                "Welcome to your private administrator dashboard.",
                "success"
            )

            return redirect(
                url_for("admin_dashboard")
            )

        flash(
            "Invalid username or password.",
            "error"
        )

    return render_template(
        "admin_login.html",
        form=form,
        registration_available=not admin_account_exists()
    )


# ============================================================
# 9. ADMINISTRATOR DASHBOARD
# SEARCH, FILTERING AND MESSAGE STATISTICS
# ============================================================

@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():

    query = request.args.get(
        "q", ""
    ).strip()[:100]

    status = request.args.get(
        "status", "all"
    )

    if status not in ("all", "read", "unread"):
        status = "all"

    sql = """
        SELECT
            id,
            name,
            email,
            created_at,
            is_read

        FROM contacts

        WHERE 1 = 1
    """

    params = []

    # Search by client name or email.
    if query:

        sql += """
            AND (
                name LIKE ?
                OR email LIKE ?
            )
        """

        pattern = f"%{query}%"

        params.extend([
            pattern,
            pattern
        ])

    # Filter by read status.
    if status == "read":

        sql += " AND is_read = 1"

    elif status == "unread":

        sql += " AND is_read = 0"

    sql += """
        ORDER BY created_at DESC, id DESC
    """

    with get_db() as connection:

        messages = connection.execute(
            sql,
            params
        ).fetchall()

        total = connection.execute("""
            SELECT COUNT(*) AS count
            FROM contacts
        """).fetchone()["count"]

        unread = connection.execute("""
            SELECT COUNT(*) AS count
            FROM contacts
            WHERE is_read = 0
        """).fetchone()["count"]

        read = connection.execute("""
            SELECT COUNT(*) AS count
            FROM contacts
            WHERE is_read = 1
        """).fetchone()["count"]

    return render_template(
        "admin_dashboard.html",

        messages=messages,

        logout_form=LogoutForm(),

        action_form=AdminActionForm(),

        admin_username=session.get(
            "admin_username",
            "Administrator"
        ),

        query=query,

        status=status,

        total=total,

        unread=unread,

        read=read
    )


# ============================================================
# 10. VIEW INDIVIDUAL CLIENT MESSAGE
# AUTOMATICALLY MARKS THE MESSAGE AS READ
# ============================================================

@app.route(
    "/admin/messages/<int:message_id>"
)
@admin_required
def view_message(message_id):

    with get_db() as connection:

        message = connection.execute("""
            SELECT
                id,
                name,
                email,
                message,
                created_at,
                is_read

            FROM contacts

            WHERE id = ?
        """, (message_id,)).fetchone()

        if message is None:

            flash(
                "The requested contact message was not found.",
                "error"
            )

            return redirect(
                url_for("admin_dashboard")
            )

        connection.execute("""
            UPDATE contacts

            SET is_read = 1

            WHERE id = ?
        """, (message_id,))

    return render_template(
        "admin_message.html",
        message=message
    )


# ============================================================
# 11. MARK CLIENT MESSAGE AS READ
# ============================================================

@app.route(
    "/admin/messages/<int:message_id>/read",
    methods=["POST"]
)
@admin_required
def mark_message_read(message_id):

    form = AdminActionForm()

    if not form.validate_on_submit():

        abort(
            400,
            description="Invalid form submission."
        )

    with get_db() as connection:

        cursor = connection.execute("""
            UPDATE contacts

            SET is_read = 1

            WHERE id = ?
        """, (message_id,))

        if cursor.rowcount == 0:

            abort(404)

    flash(
        "Client message successfully marked as read.",
        "success"
    )

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# 12. EXPORT CLIENT ENQUIRIES TO CSV
# ============================================================

@app.route("/admin/export.csv")
@admin_required
def export_contacts_csv():

    query = request.args.get(
        "q", ""
    ).strip()[:100]

    status = request.args.get(
        "status", "all"
    )

    if status not in ("all", "read", "unread"):
        status = "all"

    sql = """
        SELECT
            id,
            name,
            email,
            message,
            created_at,
            is_read

        FROM contacts

        WHERE 1 = 1
    """

    params = []

    if query:

        sql += """
            AND (
                name LIKE ?
                OR email LIKE ?
            )
        """

        pattern = f"%{query}%"

        params.extend([
            pattern,
            pattern
        ])

    if status == "read":

        sql += " AND is_read = 1"

    elif status == "unread":

        sql += " AND is_read = 0"

    sql += """
        ORDER BY created_at DESC, id DESC
    """

    with get_db() as connection:

        messages = connection.execute(
            sql,
            params
        ).fetchall()

    output = io.StringIO(newline="")

    writer = csv.writer(output)

    writer.writerow([
        "ID",
        "Client Name",
        "Email Address",
        "Message",
        "Date Received",
        "Status"
    ])

    def safe_csv_value(value):
        """Reduce spreadsheet formula-injection risk."""
        value = "" if value is None else str(value)

        if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + value

        return value

    for item in messages:

        writer.writerow([
            item["id"],
            safe_csv_value(item["name"]),
            safe_csv_value(item["email"]),
            safe_csv_value(item["message"]),
            item["created_at"],
            "Read" if item["is_read"] else "Unread"
        ])

    csv_content = "\ufeff" + output.getvalue()

    return Response(
        csv_content,

        mimetype="text/csv; charset=utf-8",

        headers={
            "Content-Disposition":
                'attachment; filename="brightwave_enquiries.csv"',

            "Cache-Control": "no-store"
        }
    )


# ============================================================
# 13. ADMINISTRATOR LOGOUT
# ============================================================

@app.route(
    "/admin/logout",
    methods=["POST"]
)
@admin_required
def admin_logout():

    form = LogoutForm()

    if form.validate_on_submit():

        session.clear()

        flash(
            "You have successfully logged out.",
            "success"
        )

        return redirect(
            url_for("admin_login")
        )

    flash(
        "Invalid logout request. Please try again.",
        "error"
    )

    return redirect(
        url_for("admin_dashboard")
    )


# ============================================================
# 14. HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return {
        "status": "ok",
        "application": "BrightWave Business"
    }, 200


# ============================================================
# 15. ERROR HANDLERS
# ============================================================

@app.errorhandler(400)
def bad_request(error):

    return "Bad request. Please try again.", 400


@app.errorhandler(404)
def page_not_found(error):

    return "The requested page was not found.", 404


@app.errorhandler(413)
def request_too_large(error):

    return "Your request is too large.", 413


@app.errorhandler(500)
def internal_server_error(error):

    return "An internal server error occurred.", 500


# ============================================================
# 16. INITIALIZE DATABASE
# ============================================================

init_db()


# ============================================================
# 17. RUN APPLICATION
# ============================================================

if __name__ == "__main__":

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=True
    )
