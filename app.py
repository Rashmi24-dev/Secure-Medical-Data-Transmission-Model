from ai_summarizer import generate_medical_summary
from security.payload import (
    create_medical_payload,
    extract_medical_payload
)
from security.cover_image import generate_medical_cover
from security.dwt import embed_data as embed_data_dwt
from security.aes import encrypt as aes_encrypt
from security.rsa_keys import encrypt_key as rsa_encrypt_key
from security.hash import generate_sha256
import os
import sqlite3
import secrets
import random
import shutil
import struct
import json  # <--- FOR DECRYPTED METADATA

from dotenv import load_dotenv
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, Response, session, send_file, abort
)

from flask_mail import Mail, Message
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# ============================================================
# SECURITY MODULES
# ============================================================

from Crypto.Random import get_random_bytes

from security.aes import (
    encrypt as aes_encrypt,
    decrypt as aes_decrypt
)

from security.rsa_keys import (
    generate_keys,
    encrypt_key as rsa_encrypt_key,
    decrypt_key as rsa_decrypt_key
)

from security.hash import (
    generate_hash as generate_sha256,
    verify_hash
)

from security.dwt import (
    embed_data as embed_data_dwt,
    extract_data as extract_data_dwt
)

# ============================================================
# LOAD ENVIRONMENT VARIABLES
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

load_dotenv(os.path.join(BASE_DIR, ".env"))
load_dotenv(os.path.join(BASE_DIR, "new.env"))

# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static")
)

app.secret_key = os.getenv(
    "SECRET_KEY",
    "default-secret-key-for-development"
)

# ============================================================
# MAIL CONFIGURATION
# ============================================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USERNAME"] = os.getenv("MAIL_USERNAME", "")
app.config["MAIL_PASSWORD"] = os.getenv("MAIL_PASSWORD", "")
app.config["MAIL_DEFAULT_SENDER"] = os.getenv("MAIL_USERNAME", "")

mail = Mail(app)

# ============================================================
# AUTH DECORATORS
# ============================================================

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "admin_id" not in session:
            flash("Please log in as admin.", "error")
            return redirect(url_for("admin_login"))
        return f(*args, **kwargs)
    return wrapper


def doctor_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "doctor_id" not in session:
            flash("Please log in.", "error")
            return redirect(url_for("doctor_login"))
        if "doctor_id" in kwargs and kwargs["doctor_id"] != session["doctor_id"]:
            abort(403)
        return f(*args, **kwargs)
    return wrapper


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
os.makedirs(INSTANCE_DIR, exist_ok=True)

DATABASE_PATH = os.path.join(INSTANCE_DIR, "medical.db")
LEGACY_DATABASE_PATH = os.path.join(BASE_DIR, "medical.db")


def prepare_database():
    if (not os.path.exists(DATABASE_PATH)
            and os.path.exists(LEGACY_DATABASE_PATH)):
        try:
            shutil.copy2(LEGACY_DATABASE_PATH, DATABASE_PATH)
            print("Existing database copied to:")
            print(DATABASE_PATH)
        except Exception as e:
            print("WARNING: Could not copy existing database.")
            print("Database error:", e)


def get_db_connection():
    conn = sqlite3.connect(DATABASE_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def add_ai_summary_column():
    conn = get_db_connection()
    try:
        columns = [
            row["name"]
            for row in conn.execute("PRAGMA table_info(reports)").fetchall()
        ]
        if "ai_summary" not in columns:
            conn.execute("ALTER TABLE reports ADD COLUMN ai_summary TEXT")
            conn.commit()
            print("AI summary column added successfully.")
    except Exception as e:
        print("AI summary database error:", e)
    finally:
        conn.close()


# Initialize Database
prepare_database()
add_ai_summary_column()


# ============================================================
# HOME
# ============================================================

@app.route("/")
def home():
    return render_template("home.html")


# ============================================================
# ROLE LOGIN
# ============================================================

@app.route("/login")
@app.route("/role_choice")
def login():
    return render_template("login.html")


# ============================================================
# DOCTOR SELF-REGISTRATION (WITH LICENSE UPLOAD)
# ============================================================

@app.route("/register", methods=["GET", "POST"])
def register():
    conn = get_db_connection()

    hospitals = conn.execute(
        "SELECT hospital_id, hospital_name FROM hospitals ORDER BY hospital_name"
    ).fetchall()

    if request.method == "POST":
        try:
            hospital_id = request.form.get("hospital_id", "").strip()
            first_name = request.form.get("first_name", "").strip()
            last_name = request.form.get("last_name", "").strip()
            doctor_name = f"{first_name} {last_name}".strip()
            specialization = request.form.get("specialization", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            confirm_password = request.form.get("confirm_password", "")
            phone = request.form.get("phone", "").strip()
            experience = request.form.get("experience", "0").strip() or "0"
            license_number = request.form.get("license_number", "").strip()
            address = request.form.get("address", "").strip()
            username = email

            # --------------------------------
            # Handle License Document Upload
            # --------------------------------
            license_doc = request.files.get("license_document")
            license_doc_filename = None

            def render_error(msg):
                conn.close()
                flash(msg, "error")
                return render_template(
                    "register.html",
                    hospitals=hospitals,
                    form=request.form
                )

            # --------------------------------
            # Form Validation
            # --------------------------------
            if not hospital_id:
                return render_error("Please select a hospital.")

            if not first_name or not last_name:
                return render_error("Please enter the doctor's full name.")

            if not specialization:
                return render_error("Please enter specialization.")

            if not email:
                return render_error("Please enter your email.")

            if not password:
                return render_error("Please enter a password.")

            if password != confirm_password:
                return render_error("Passwords do not match.")

            if len(password) < 8:
                return render_error(
                    "Password must be at least 8 characters long."
                )

            if not license_doc or not license_doc.filename:
                return render_error(
                    "Please upload a scanned copy of your Medical License."
                )

            # --------------------------------
            # Validate License File
            # --------------------------------
            allowed_extensions = {"pdf", "jpg", "jpeg", "png"}

            ext = (
                license_doc.filename.rsplit(".", 1)[-1].lower()
                if "." in license_doc.filename
                else ""
            )

            if ext not in allowed_extensions:
                return render_error(
                    "License document must be a PDF, JPG, or PNG."
                )

            # --------------------------------
            # Save License Document
            # --------------------------------
            upload_folder = os.path.join(
                app.static_folder, "uploads"
            )

            os.makedirs(upload_folder, exist_ok=True)

            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            safe_name = secure_filename(license_doc.filename)

            license_doc_filename = (
                f"license_{timestamp}_{safe_name}"
            )

            license_doc.save(
                os.path.join(upload_folder, license_doc_filename)
            )

            # --------------------------------
            # Check Duplicate Doctor
            # --------------------------------
            existing = conn.execute(
                """
                SELECT doctor_id FROM doctors
                WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))
                   OR LOWER(TRIM(username)) = LOWER(TRIM(?))
                   OR (
                       license_number IS NOT NULL
                       AND LOWER(TRIM(license_number)) = LOWER(TRIM(?))
                   )
                LIMIT 1
                """,
                (email, username, license_number)
            ).fetchone()

            if existing:
                return render_error(
                    "A doctor with this email, username, "
                    "or license number already exists."
                )

            # --------------------------------
            # Generate RSA Keys
            # --------------------------------
            try:
                print(
                    "Generating RSA-2048 key pair for new registration..."
                )

                private_key, public_key = generate_keys()

                private_key_text = private_key.decode("utf-8")
                public_key_text = public_key.decode("utf-8")

                print("RSA keys generated successfully.")

            except Exception as e:
                print("RSA KEY GENERATION ERROR:", e)

                return render_error(
                    f"Could not generate RSA keys: {str(e)}"
                )

            # --------------------------------
            # Hash Password
            # --------------------------------
            hashed_password = generate_password_hash(password)

            # --------------------------------
            # Insert Doctor into Database
            # --------------------------------
            conn.execute(
                """
                INSERT INTO doctors
                (
                    hospital_id,
                    doctor_name,
                    specialization,
                    email,
                    phone,
                    experience,
                    license_number,
                    username,
                    password,
                    address,
                    public_key,
                    private_key,
                    status,
                    license_document
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    hospital_id,
                    doctor_name,
                    specialization,
                    email,
                    phone,
                    experience,
                    license_number,
                    username,
                    hashed_password,
                    address,
                    public_key_text,
                    private_key_text,
                    "Pending",
                    license_doc_filename
                )
            )

            conn.commit()
            conn.close()

            # --------------------------------
            # Send Registration Email to Doctor
            # --------------------------------
            try:
                msg = Message(
                    subject="MediSecure - Registration Submitted Successfully",
                    recipients=[email],
                    sender=app.config["MAIL_DEFAULT_SENDER"]
                )

                msg.body = f"""
Dear Dr. {doctor_name},

Welcome to MediSecure!

Your doctor registration has been submitted successfully.

Registration Details:

Doctor Name: {doctor_name}
Specialization: {specialization}
Hospital ID: {hospital_id}
Registered Email: {email}

Registration Status: Pending Admin Approval

Your medical license document is currently
waiting for verification by the MediSecure Admin.

You will receive another notification once
your account has been approved.

Thank you for registering with MediSecure.

Regards,
MediSecure Administration
"""

                mail.send(msg)

                print(
                    f"Registration email sent successfully to {email}"
                )

                flash(
                    "Registration submitted successfully! "
                    "A confirmation email has been sent to your registered email. "
                    "Your license is pending Admin approval.",
                    "success"
                )

            except Exception as email_error:
                print(
                    "REGISTRATION EMAIL ERROR:",
                    email_error
                )

                flash(
                    "Registration submitted successfully, "
                    "but the confirmation email could not be sent. "
                    "Please check the email configuration.",
                    "warning"
                )

            return redirect(url_for("doctor_login"))

        except sqlite3.IntegrityError as e:
            conn.rollback()
            conn.close()

            print("REGISTER INTEGRITY ERROR:", e)

            err = str(e).lower()

            if "email" in err:
                msg = "A doctor with this email already exists."
            elif "username" in err:
                msg = "A doctor with this username already exists."
            elif "license_number" in err:
                msg = "A doctor with this license number already exists."
            else:
                msg = f"Registration failed: {str(e)}"

            flash(msg, "error")

            return render_template(
                "register.html",
                hospitals=hospitals,
                form=request.form
            )

        except Exception as e:
            conn.rollback()
            conn.close()

            print("REGISTER ERROR:", e)

            flash(
                f"Registration failed: {str(e)}",
                "error"
            )

            return render_template(
                "register.html",
                hospitals=hospitals,
                form=request.form
            )

    conn.close()

    return render_template(
        "register.html",
        hospitals=hospitals,
        form={}
    )


# ============================================================
# ADMIN LOGIN
# ============================================================

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        login_id = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        try:
            admin = conn.execute(
                """
                SELECT * FROM admins
                WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))
                   OR LOWER(TRIM(username)) = LOWER(TRIM(?))
                LIMIT 1
                """,
                (login_id, login_id)
            ).fetchone()
        finally:
            conn.close()

        if admin and check_password_hash(admin["password"], password):
            session["admin_id"] = admin["admin_id"]
            session["admin_email"] = admin["email"]
            flash("Login successful! Welcome back, Admin.", "success")
            return redirect(url_for("admin_dashboard"))

        flash("Invalid Email/Username or Password. Please try again.", "error")
        return redirect(url_for("admin_login"))

    return render_template("admin_login.html")


# ============================================================
# ADMIN FORGOT PASSWORD
# ============================================================

@app.route("/admin_forgot_password", methods=["GET", "POST"])
def admin_forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            flash("Please enter your email address.", "error")
            return redirect(url_for("admin_forgot_password"))

        conn = get_db_connection()
        admin = conn.execute(
            """
            SELECT * FROM admins
            WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))
            LIMIT 1
            """,
            (email,)
        ).fetchone()

        if admin:
            otp = str(secrets.randbelow(900000) + 100000)
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

            try:
                try:
                    conn.execute(
                        "DELETE FROM password_resets WHERE admin_id = ?",
                        (admin["admin_id"],)
                    )
                except Exception:
                    conn.execute(
                        "DELETE FROM password_resets WHERE email = ?",
                        (email,)
                    )

                try:
                    conn.execute(
                        """
                        INSERT INTO password_resets
                        (admin_id, email, token, otp,
                         expires_at, used, is_verified)
                        VALUES (?, ?, ?, ?, ?, 0, 0)
                        """,
                        (admin["admin_id"], email,
                         "admin_otp_verification", otp, expires_at)
                    )
                except Exception:
                    conn.execute(
                        """
                        INSERT INTO password_resets
                        (email, token, otp,
                         expires_at, used, is_verified)
                        VALUES (?, ?, ?, ?, 0, 0)
                        """,
                        (email, "admin_otp_verification", otp, expires_at)
                    )

                conn.commit()
            except Exception as e:
                conn.rollback()
                conn.close()
                print("ADMIN PASSWORD RESET DATABASE ERROR:", e)
                flash(f"Unable to create password reset: {str(e)}", "error")
                return redirect(url_for("admin_forgot_password"))

            conn.close()

            try:
                msg = Message(
                    subject="Your OTP for Admin Password Reset - MediSecure",
                    recipients=[email]
                )
                msg.body = f"""
Hello Admin,

Your One-Time Password (OTP) for password reset is:

{otp}

This OTP is valid for 10 minutes.

Best regards,
MediSecure Team
"""
                mail.send(msg)
                flash("OTP has been sent to your email.", "success")
                return redirect(url_for("admin_verify_otp", email=email))

            except Exception as e:
                print("MAIL ERROR:", e)
                flash("Unable to send OTP email. Check your mail configuration.", "error")
                return redirect(url_for("admin_forgot_password"))

        else:
            conn.close()
            flash("If an account exists with this email, an OTP has been sent.", "success")
            return redirect(url_for("admin_forgot_password"))

    return render_template("admin_forgot_password.html")


# ============================================================
# ADMIN VERIFY OTP
# ============================================================

@app.route("/admin_verify_otp/<email>", methods=["GET", "POST"])
def admin_verify_otp(email):
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        conn = get_db_connection()

        admin = conn.execute(
            "SELECT * FROM admins WHERE LOWER(TRIM(email)) = LOWER(TRIM(?)) LIMIT 1",
            (email,)
        ).fetchone()

        if not admin:
            conn.close()
            flash("Account not found!", "error")
            return redirect(url_for("admin_forgot_password"))

        reset_record = conn.execute(
            """
            SELECT * FROM password_resets
            WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))
              AND used = 0
              AND is_verified = 0
              AND expires_at > ?
            """,
            (email, datetime.now(timezone.utc))
        ).fetchone()

        if not reset_record:
            conn.close()
            flash("OTP has expired. Please request a new one.", "error")
            return redirect(url_for("admin_forgot_password"))

        if reset_record["otp"] == entered_otp:
            conn.execute(
                "UPDATE password_resets SET is_verified = 1 WHERE reset_id = ?",
                (reset_record["reset_id"],)
            )
            conn.commit()
            conn.close()
            flash("OTP verified successfully!", "success")
            return redirect(url_for("admin_reset_password",
                                    reset_id=reset_record["reset_id"]))

        conn.close()
        flash("Invalid OTP. Please try again.", "error")
        return render_template("admin_verify_otp.html", email=email)

    return render_template("admin_verify_otp.html", email=email)


# ============================================================
# ADMIN RESET PASSWORD
# ============================================================

@app.route("/admin_reset_password/<int:reset_id>", methods=["GET", "POST"])
def admin_reset_password(reset_id):
    conn = get_db_connection()
    reset_record = conn.execute(
        """
        SELECT * FROM password_resets
        WHERE reset_id = ? AND is_verified = 1 AND used = 0
        """,
        (reset_id,)
    ).fetchone()

    if not reset_record:
        conn.close()
        flash("Invalid or expired verification.", "error")
        return redirect(url_for("admin_forgot_password"))

    admin = conn.execute(
        "SELECT * FROM admins WHERE admin_id = ?",
        (reset_record["admin_id"],)
    ).fetchone()

    if not admin:
        admin = conn.execute(
            "SELECT * FROM admins WHERE LOWER(TRIM(email)) = LOWER(TRIM(?)) LIMIT 1",
            (reset_record["email"],)
        ).fetchone()

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            conn.close()
            flash("Passwords do not match!", "error")
            return render_template("admin_reset_password.html", reset_id=reset_id)

        if len(new_password) < 8:
            conn.close()
            flash("Password must be at least 8 characters long.", "error")
            return render_template("admin_reset_password.html", reset_id=reset_id)

        if admin:
            try:
                hashed_password = generate_password_hash(new_password)
                conn.execute(
                    "UPDATE admins SET password = ? WHERE admin_id = ?",
                    (hashed_password, admin["admin_id"])
                )
                conn.execute(
                    "UPDATE password_resets SET used = 1 WHERE reset_id = ?",
                    (reset_id,)
                )
                conn.commit()
                conn.close()
                flash("Password reset successfully! Please login with your new password.", "success")
                return redirect(url_for("admin_login"))
            except Exception as e:
                conn.rollback()
                conn.close()
                flash(f"Password reset failed: {str(e)}", "error")
                return redirect(url_for("admin_forgot_password"))

        conn.close()
        flash("Admin account not found!", "error")
        return redirect(url_for("admin_forgot_password"))

    conn.close()
    return render_template("admin_reset_password.html", reset_id=reset_id)


# ============================================================
# ADMIN DASHBOARD
# ============================================================

@app.route("/admin_dashboard")
def admin_dashboard():
    conn = get_db_connection()

    total_hospitals = conn.execute("SELECT COUNT(*) FROM hospitals").fetchone()[0]
    total_doctors = conn.execute("SELECT COUNT(*) FROM doctors").fetchone()[0]
    total_reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]

    pending_doctors = conn.execute(
        "SELECT COUNT(*) FROM doctors WHERE status = 'Pending'"
    ).fetchone()[0]

    try:
        active_doctors = conn.execute(
            "SELECT COUNT(*) FROM doctors WHERE LOWER(TRIM(status)) = 'active'"
        ).fetchone()[0]
    except Exception:
        active_doctors = total_doctors

    try:
        recent_transmissions = conn.execute(
            """
            SELECT
                r.report_id, r.patient_name, r.sent_date, r.status,
                d1.doctor_name AS sender_name,
                d2.doctor_name AS receiver_name,
                h1.hospital_name AS from_hospital,
                h2.hospital_name AS to_hospital
            FROM reports r
            LEFT JOIN doctors d1 ON r.sender_id = d1.doctor_id
            LEFT JOIN doctors d2 ON r.receiver_id = d2.doctor_id
            LEFT JOIN hospitals h1 ON d1.hospital_id = h1.hospital_id
            LEFT JOIN hospitals h2 ON d2.hospital_id = h2.hospital_id
            WHERE LOWER(r.status) IN ('sent', 'delivered', 'seen', 'decrypted')
            ORDER BY r.sent_date DESC
            LIMIT 5
            """
        ).fetchall()
    except Exception:
        recent_transmissions = []

    conn.close()

    return render_template(
        "admin_dashboard.html",
        total_hospitals=total_hospitals,
        total_doctors=total_doctors,
        total_reports=total_reports,
        active_doctors=active_doctors,
        recent_transmissions=recent_transmissions,
        pending_doctors=pending_doctors
    )


# ============================================================
# ADD HOSPITAL (Requires PDF)
# ============================================================

@app.route("/add_hospital", methods=["GET", "POST"])
def add_hospital():
    if request.method == "POST":
        hospital_name = request.form.get("hospital_name", "").strip()
        registration_id = request.form.get("registration_id", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        location = request.form.get("location", "").strip()
        address = request.form.get("address", "").strip()
        specialization = request.form.get("specialization", "").strip()
        
        doctor_pdf = request.files.get("doctor_pdf")

        if not doctor_pdf or doctor_pdf.filename == "":
            flash("Error: You must upload a Doctor Details PDF to register.", "error")
            return redirect(url_for("add_hospital"))

        if not doctor_pdf.filename.lower().endswith(".pdf"):
            flash("Error: Only PDF files are allowed for Doctor Details.", "error")
            return redirect(url_for("add_hospital"))

        if not hospital_name:
            flash("Hospital name is required.", "error")
            return redirect(url_for("add_hospital"))

        upload_folder = os.path.join(app.static_folder, "uploads")
        os.makedirs(upload_folder, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        safe_filename = secure_filename(doctor_pdf.filename)
        pdf_filename = f"hospital_doc_{timestamp}_{safe_filename}"
        pdf_path = os.path.join(upload_folder, pdf_filename)
        
        doctor_pdf.save(pdf_path)

        conn = get_db_connection()
        try:
            conn.execute(
                """
                INSERT INTO hospitals
                (hospital_name, registration_id, email, phone,
                 location, address, specialization, doctor_pdf)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (hospital_name, registration_id, email, phone,
                 location, address, specialization, pdf_filename)
            )
            conn.commit()
            conn.close()
            flash("Hospital and Doctor PDF added successfully!", "success")
            return redirect(url_for("add_hospital"))
            
        except sqlite3.IntegrityError as e:
            conn.rollback()
            conn.close()
            print("ADD HOSPITAL INTEGRITY ERROR:", e)
            flash(f"Hospital could not be added: {str(e)}", "error")
            return redirect(url_for("add_hospital"))
        except Exception as e:
            conn.rollback()
            conn.close()
            print("ADD HOSPITAL DATABASE ERROR:", e)
            flash(f"Error while adding hospital: {str(e)}", "error")
            return redirect(url_for("add_hospital"))

    return render_template("add_hospital.html")


# ============================================================
# VIEW HOSPITAL
# ============================================================

@app.route("/view_hospital")
def view_hospital():
    conn = get_db_connection()
    hospitals = conn.execute("SELECT * FROM hospitals ORDER BY hospital_name").fetchall()
    conn.close()
    return render_template("view_hospital.html", hospitals=hospitals)


# ============================================================
# VIEW HOSPITAL PDF
# ============================================================

@app.route("/view_hospital_pdf/<int:hospital_id>")
def view_hospital_pdf(hospital_id):
    conn = get_db_connection()
    hospital = conn.execute(
        "SELECT doctor_pdf FROM hospitals WHERE hospital_id = ?", 
        (hospital_id,)
    ).fetchone()
    conn.close()

    if hospital and hospital["doctor_pdf"]:
        filepath = os.path.join(app.static_folder, "uploads", hospital["doctor_pdf"])
        
        if os.path.exists(filepath):
            return send_file(filepath, mimetype='application/pdf')
        else:
            flash("The PDF file is missing from the server.", "error")
            return redirect(url_for("view_hospital"))
    else:
        flash("No PDF was uploaded for this hospital.", "error")
        return redirect(url_for("view_hospital"))


# ============================================================
# EDIT HOSPITAL
# ============================================================

@app.route("/edit_hospital/<int:hospital_id>", methods=["GET", "POST"])
def edit_hospital(hospital_id):
    conn = get_db_connection()

    if request.method == "POST":
        hospital_name = request.form.get("hospital_name", "").strip()
        registration_id = request.form.get("registration_id", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        location = request.form.get("location", "").strip()
        address = request.form.get("address", "").strip()
        specialization = request.form.get("specialization", "").strip()
        
        new_pdf = request.files.get("doctor_pdf")
        pdf_filename = None

        if new_pdf and new_pdf.filename != "":
            if not new_pdf.filename.lower().endswith(".pdf"):
                flash("Error: Only PDF files are allowed for Doctor Details.", "error")
                return redirect(url_for("edit_hospital", hospital_id=hospital_id))
            
            upload_folder = os.path.join(app.static_folder, "uploads")
            os.makedirs(upload_folder, exist_ok=True)
            
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            safe_filename = secure_filename(new_pdf.filename)
            pdf_filename = f"hospital_doc_{timestamp}_{safe_filename}"
            pdf_path = os.path.join(upload_folder, pdf_filename)
            new_pdf.save(pdf_path)

        try:
            if pdf_filename:
                conn.execute(
                    """
                    UPDATE hospitals SET
                        hospital_name = ?, registration_id = ?, email = ?,
                        phone = ?, location = ?, address = ?, specialization = ?,
                        doctor_pdf = ?
                    WHERE hospital_id = ?
                    """,
                    (hospital_name, registration_id, email, phone,
                     location, address, specialization, pdf_filename, hospital_id)
                )
            else:
                conn.execute(
                    """
                    UPDATE hospitals SET
                        hospital_name = ?, registration_id = ?, email = ?,
                        phone = ?, location = ?, address = ?, specialization = ?
                    WHERE hospital_id = ?
                    """,
                    (hospital_name, registration_id, email, phone,
                     location, address, specialization, hospital_id)
                )
                
            conn.commit()
            conn.close()
            flash("Hospital updated successfully!", "success")
            return redirect(url_for("view_hospital"))
            
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Error updating hospital: {str(e)}", "error")
            return redirect(url_for("edit_hospital", hospital_id=hospital_id))

    hospital = conn.execute(
        "SELECT * FROM hospitals WHERE hospital_id = ?", (hospital_id,)
    ).fetchone()
    conn.close()

    if not hospital:
        flash("Hospital not found!", "error")
        return redirect(url_for("view_hospital"))

    return render_template("edit_hospital.html", hospital=hospital)


# ============================================================
# DELETE HOSPITAL PDF
# ============================================================

@app.route("/delete_hospital_pdf/<int:hospital_id>")
def delete_hospital_pdf(hospital_id):
    conn = get_db_connection()
    
    hospital = conn.execute(
        "SELECT doctor_pdf FROM hospitals WHERE hospital_id = ?", 
        (hospital_id,)
    ).fetchone()

    if hospital and hospital["doctor_pdf"]:
        filepath = os.path.join(app.static_folder, "uploads", hospital["doctor_pdf"])
        if os.path.exists(filepath):
            os.remove(filepath)

        conn.execute(
            "UPDATE hospitals SET doctor_pdf = NULL WHERE hospital_id = ?", 
            (hospital_id,)
        )
        conn.commit()
        flash("Doctor PDF deleted successfully. You can now upload a new one.", "success")
    else:
        flash("No PDF found to delete.", "error")

    conn.close()
    return redirect(url_for("edit_hospital", hospital_id=hospital_id))


# ============================================================
# DELETE HOSPITAL
# ============================================================

@app.route("/delete_hospital/<int:hospital_id>")
def delete_hospital(hospital_id):
    conn = get_db_connection()
    hospital = conn.execute(
        "SELECT hospital_name FROM hospitals WHERE hospital_id = ?",
        (hospital_id,)
    ).fetchone()

    if hospital:
        try:
            conn.execute("DELETE FROM hospitals WHERE hospital_id = ?", (hospital_id,))
            conn.commit()
            flash(f'Hospital "{hospital["hospital_name"]}" deleted successfully!', "warning")
        except Exception as e:
            conn.rollback()
            flash(f"Unable to delete hospital: {str(e)}", "error")
    else:
        flash("Hospital not found!", "error")

    conn.close()
    return redirect(url_for("view_hospital"))


# ============================================================
# ADD DOCTOR (admin)
# ============================================================

@app.route("/add_doctor", methods=["GET", "POST"])
def add_doctor():
    conn = get_db_connection()
    hospitals = conn.execute(
        "SELECT hospital_id, hospital_name FROM hospitals ORDER BY hospital_name"
    ).fetchall()
    conn.close()

    if request.method == "POST":
        conn = get_db_connection()
        try:
            hospital_id = request.form.get("hospital_id")
            first_name = request.form.get("first_name", "").strip()
            last_name = request.form.get("last_name", "").strip()
            doctor_name = f"{first_name} {last_name}".strip()
            specialization = request.form.get("specialization", "").strip()
            email = request.form.get("email", "").strip()
            password = request.form.get("password", "")
            phone = request.form.get("phone", "").strip()
            experience = request.form.get("experience", 0)
            status = request.form.get("status", "Active").strip()
            license_number = request.form.get("license_number", "").strip()
            address = request.form.get("address", "").strip()
            username = email

            if not hospital_id:
                flash("Please select a hospital.", "error")
                conn.close()
                return render_template("add_doctor.html", hospitals=hospitals)
            if not first_name or not last_name:
                flash("Please enter the doctor's full name.", "error")
                conn.close()
                return render_template("add_doctor.html", hospitals=hospitals)
            if not specialization:
                flash("Please enter specialization.", "error")
                conn.close()
                return render_template("add_doctor.html", hospitals=hospitals)
            if not email:
                flash("Please enter doctor's email.", "error")
                conn.close()
                return render_template("add_doctor.html", hospitals=hospitals)
            if not password:
                flash("Please enter password.", "error")
                conn.close()
                return render_template("add_doctor.html", hospitals=hospitals)

            existing = conn.execute(
                """
                SELECT doctor_id FROM doctors
                WHERE LOWER(TRIM(email)) = LOWER(TRIM(?))
                   OR LOWER(TRIM(username)) = LOWER(TRIM(?))
                LIMIT 1
                """,
                (email, username)
            ).fetchone()

            if existing:
                conn.close()
                flash("A doctor with this email or username already exists!", "error")
                return render_template("add_doctor.html", hospitals=hospitals)

            print("Generating RSA-2048 key pair...")
            private_key, public_key = generate_keys()
            private_key_text = private_key.decode("utf-8")
            public_key_text = public_key.decode("utf-8")
            print("RSA keys generated successfully.")

            hashed_password = generate_password_hash(password)

            conn.execute(
                """
                INSERT INTO doctors
                (hospital_id, doctor_name, specialization, email, phone,
                 experience, license_number, username, password, address,
                 public_key, private_key, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (hospital_id, doctor_name, specialization, email, phone,
                 experience, license_number, username, hashed_password,
                 address, public_key_text, private_key_text, status)
            )
            conn.commit()
            conn.close()
            flash(f'✅ Doctor "{doctor_name}" added successfully! RSA-2048 public/private keys generated.', "success")
            return redirect(url_for("add_doctor"))

        except sqlite3.IntegrityError as e:
            conn.rollback()
            conn.close()
            print("DATABASE INTEGRITY ERROR:", e)
            error_text = str(e).lower()
            if "email" in error_text:
                message = "A doctor with this email already exists."
            elif "username" in error_text:
                message = "A doctor with this username already exists."
            elif "license_number" in error_text:
                message = "A doctor with this license number already exists."
            else:
                message = f"Doctor could not be added: {str(e)}"
            flash(message, "error")
            return render_template("add_doctor.html", hospitals=hospitals)

        except Exception as e:
            conn.rollback()
            conn.close()
            print("ERROR ADDING DOCTOR:", e)
            flash(f"Error while adding doctor: {str(e)}", "error")
            return render_template("add_doctor.html", hospitals=hospitals)

    return render_template("add_doctor.html", hospitals=hospitals)


# ============================================================
# VIEW DOCTORS
# ============================================================

@app.route("/view_doctors")
def view_doctors():
    conn = get_db_connection()

    search = request.args.get("search", "")
    status = request.args.get("status", "all")
    spec = request.args.get("specialization", "all")

    query = """
        SELECT doctors.*, hospitals.hospital_name
        FROM doctors
        LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
        WHERE 1 = 1
    """
    params = []

    if search:
        query += """
            AND (doctors.doctor_name LIKE ?
                 OR doctors.specialization LIKE ?
                 OR hospitals.hospital_name LIKE ?
                 OR doctors.email LIKE ?)
        """
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param, search_param])

    if status != "all":
        query += " AND doctors.status = ?"
        params.append(status)

    if spec != "all":
        query += " AND doctors.specialization = ?"
        params.append(spec)

    query += " ORDER BY CASE WHEN doctors.status = 'Pending' THEN 1 ELSE 2 END, doctors.doctor_name"

    doctors = conn.execute(query, params).fetchall()
    conn.close()

    return render_template(
        "view_doctor.html",
        doctors=doctors,
        search_query=search,
        status_filter=status,
        spec_filter=spec
    )


# ============================================================
# VIEW SINGLE DOCTOR
# ============================================================

@app.route("/view_doctor/<int:doctor_id>")
def view_doctor(doctor_id):
    conn = get_db_connection()
    doctor = conn.execute(
        """
        SELECT doctors.*, hospitals.hospital_name
        FROM doctors
        LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
        WHERE doctors.doctor_id = ?
        """,
        (doctor_id,)
    ).fetchone()
    conn.close()

    if not doctor:
        flash("Doctor not found!", "error")
        return redirect(url_for("view_doctors"))

    return render_template("view_single_doctor.html", doctor=doctor)


# ============================================================
# ADMIN APPROVE DOCTOR (fixed)
# ============================================================

@app.route("/approve_doctor/<int:doctor_id>", methods=["POST"])
@admin_required
def approve_doctor(doctor_id):
    conn = get_db_connection()
    try:
        doctor = conn.execute(
            "SELECT doctor_id, doctor_name, email, status "
            "FROM doctors WHERE doctor_id = ?",
            (doctor_id,)
        ).fetchone()

        if not doctor:
            flash("Doctor not found!", "error")
            return redirect(url_for("view_doctors"))

        if (doctor["status"] or "").strip().lower() == "active":
            flash(
                f"Dr. {doctor['doctor_name']} is already approved.",
                "info"
            )
            return redirect(url_for("view_doctors"))

        recipient = (doctor["email"] or "").strip()
        if not recipient or "@" not in recipient or "." not in recipient.split("@")[-1]:
            flash(
                f"Cannot approve: Dr. {doctor['doctor_name']} has an invalid "
                f"or missing email address ({recipient!r}). "
                f"Update the doctor's email first.",
                "error"
            )
            return redirect(url_for("view_doctor", doctor_id=doctor_id))

        sender = app.config.get("MAIL_DEFAULT_SENDER") or app.config.get("MAIL_USERNAME")

        try:
            msg = Message(
                subject="Your MediSecure Account Has Been Approved",
                recipients=[recipient],
                sender=sender,
                reply_to=sender,
            )

            msg.body = (
                f"Hello Dr. {doctor['doctor_name']},\n\n"
                f"Your medical license has been verified and your account "
                f"is now active. You may log in here:\n\n"
                f"{url_for('doctor_login', _external=True)}\n\n"
                f"If you did not register with MediSecure, please ignore this email.\n\n"
                f"Regards,\n"
                f"MediSecure Administration\n"
            )

            msg.html = (
                f"<p>Hello Dr. {doctor['doctor_name']},</p>"
                f"<p>Your medical license has been verified and your account "
                f"is now <strong>active</strong>. You may log in here:</p>"
                f"<p><a href=\"{url_for('doctor_login', _external=True)}\">"
                f"{url_for('doctor_login', _external=True)}</a></p>"
                f"<p style='color:#666;font-size:12px;'>"
                f"If you did not register with MediSecure, please ignore this email.</p>"
                f"<p>Regards,<br><strong>MediSecure Administration</strong></p>"
            )

            mail.send(msg)

            app.logger.info(
                "APPROVAL EMAIL SENT | to=%s | from=%s | doctor_id=%s",
                recipient, sender, doctor_id
            )

        except Exception as mail_err:
            app.logger.error(
                "APPROVAL EMAIL FAILED | to=%s | from=%s | doctor_id=%s | error=%s",
                recipient, sender, doctor_id, mail_err
            )
            flash(
                f"Approval email to {recipient} could not be sent: {mail_err}. "
                f"The doctor was NOT approved. Fix mail configuration and retry, "
                f"or use 'Force approve without email'.",
                "error"
            )
            return redirect(url_for("view_doctor", doctor_id=doctor_id))

        conn.execute(
            "UPDATE doctors SET status = 'Active' WHERE doctor_id = ?",
            (doctor_id,)
        )
        conn.commit()

        flash(
            f"✅ Dr. {doctor['doctor_name']} approved. "
            f"Approval email sent to {recipient}.",
            "success"
        )
        return redirect(url_for("view_doctors"))

    except Exception as e:
        conn.rollback()
        app.logger.error("APPROVE_DOCTOR ERROR | doctor_id=%s | error=%s", doctor_id, e)
        flash(f"Error approving doctor: {e}", "error")
        return redirect(url_for("view_doctors"))

    finally:
        conn.close()


# ============================================================
# ADMIN FORCE APPROVE (no email)
# ============================================================

@app.route("/force_approve_doctor/<int:doctor_id>", methods=["POST"])
@admin_required
def force_approve_doctor(doctor_id):
    conn = get_db_connection()
    try:
        doctor = conn.execute(
            "SELECT doctor_name, email FROM doctors WHERE doctor_id = ?",
            (doctor_id,)
        ).fetchone()

        if not doctor:
            flash("Doctor not found!", "error")
            return redirect(url_for("view_doctors"))

        conn.execute(
            "UPDATE doctors SET status = 'Active' WHERE doctor_id = ?",
            (doctor_id,)
        )
        conn.commit()

        app.logger.warning(
            "FORCE APPROVE (no email) | doctor_id=%s | email=%s | by admin_id=%s",
            doctor_id, doctor["email"], session.get("admin_id")
        )

        flash(
            f"⚠️ Dr. {doctor['doctor_name']} force-approved WITHOUT email notification. "
            f"Please contact them manually at {doctor['email']}.",
            "warning"
        )
        return redirect(url_for("view_doctors"))

    except Exception as e:
        conn.rollback()
        app.logger.error("FORCE_APPROVE ERROR | doctor_id=%s | error=%s", doctor_id, e)
        flash(f"Error: {e}", "error")
        return redirect(url_for("view_doctors"))

    finally:
        conn.close()


# ============================================================
# DOWNLOAD PRIVATE RSA KEY
# ============================================================

@app.route("/download_private_key/<int:doctor_id>")
def download_private_key(doctor_id):
    conn = get_db_connection()
    doctor = conn.execute(
        "SELECT doctor_name, private_key FROM doctors WHERE doctor_id = ?",
        (doctor_id,)
    ).fetchone()
    conn.close()

    if not doctor:
        flash("Doctor not found!", "error")
        return redirect(url_for("doctor_login"))

    if not doctor["private_key"]:
        flash("Private key not found!", "error")
        return redirect(url_for("doctor_profile", doctor_id=doctor_id))

    doctor_name = doctor["doctor_name"].replace(" ", "_")
    filename = f"{doctor_name}_private_key.pem"

    return Response(
        doctor["private_key"],
        mimetype="application/x-pem-file",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# ============================================================
# EDIT DOCTOR (admin)
# ============================================================

@app.route("/edit_doctor/<int:doctor_id>", methods=["GET", "POST"])
def edit_doctor(doctor_id):
    conn = get_db_connection()

    if request.method == "POST":
        try:
            hospital_id = request.form.get("hospital_id")
            doctor_name = request.form.get("doctor_name", "").strip()
            specialization = request.form.get("specialization", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            experience = request.form.get("experience", 0)
            status = request.form.get("status", "Active").strip()
            license_number = request.form.get("license_number", "").strip()
            address = request.form.get("address", "").strip()

            conn.execute(
                """
                UPDATE doctors SET
                    hospital_id = ?, doctor_name = ?, specialization = ?,
                    email = ?, phone = ?, experience = ?,
                    license_number = ?, address = ?, status = ?
                WHERE doctor_id = ?
                """,
                (hospital_id, doctor_name, specialization, email, phone,
                 experience, license_number, address, status, doctor_id)
            )
            conn.commit()
            conn.close()
            flash("Doctor updated successfully!", "success")
            return redirect(url_for("view_doctors"))
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Error: {str(e)}", "error")
            return redirect(url_for("edit_doctor", doctor_id=doctor_id))

    doctor = conn.execute(
        """
        SELECT doctors.*, hospitals.hospital_name
        FROM doctors
        LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
        WHERE doctors.doctor_id = ?
        """,
        (doctor_id,)
    ).fetchone()

    hospitals = conn.execute(
        "SELECT hospital_id, hospital_name FROM hospitals ORDER BY hospital_name"
    ).fetchall()

    conn.close()

    if not doctor:
        flash("Doctor not found!", "error")
        return redirect(url_for("view_doctors"))

    return render_template("edit_doctor.html", doctor=doctor, hospitals=hospitals)


# ============================================================
# DELETE DOCTOR
# ============================================================

@app.route("/delete_doctor/<int:doctor_id>")
def delete_doctor(doctor_id):
    conn = get_db_connection()
    doctor = conn.execute(
        "SELECT doctor_name FROM doctors WHERE doctor_id = ?", (doctor_id,)
    ).fetchone()

    if doctor:
        try:
            conn.execute("DELETE FROM doctors WHERE doctor_id = ?", (doctor_id,))
            conn.commit()
            flash(f'Doctor "{doctor["doctor_name"]}" deleted successfully!', "warning")
        except Exception as e:
            conn.rollback()
            flash(f"Unable to delete doctor: {str(e)}", "error")
    else:
        flash("Doctor not found!", "error")

    conn.close()
    return redirect(url_for("view_doctors"))


# ============================================================
# REPORTS - ADMIN
# ============================================================

@app.route("/reports")
def reports():
    conn = get_db_connection()

    search = request.args.get("search", "")
    status_filter = request.args.get("status", "all")
    date_filter = request.args.get("date_filter", "all")

    query = """
        SELECT
            r.report_id, r.patient_name, r.sent_date, r.upload_date, r.status,
            d1.doctor_name AS sender_name,
            d2.doctor_name AS receiver_name,
            h1.hospital_name AS from_hospital,
            h2.hospital_name AS to_hospital
        FROM reports r
        LEFT JOIN doctors d1 ON r.sender_id = d1.doctor_id
        LEFT JOIN doctors d2 ON r.receiver_id = d2.doctor_id
        LEFT JOIN hospitals h1 ON d1.hospital_id = h1.hospital_id
        LEFT JOIN hospitals h2 ON d2.hospital_id = h2.hospital_id
        WHERE 1 = 1
    """
    params = []

    if search:
        query += """
            AND (r.patient_name LIKE ?
                 OR h1.hospital_name LIKE ?
                 OR h2.hospital_name LIKE ?
                 OR r.report_id LIKE ?)
        """
        search_param = f"%{search}%"
        params.extend([search_param, search_param, search_param, search_param])

    if status_filter != "all":
        query += " AND LOWER(r.status) = ?"
        params.append(status_filter.lower())

    if date_filter == "today":
        query += " AND DATE(r.sent_date) = DATE('now')"
    elif date_filter == "week":
        query += " AND DATE(r.sent_date) >= DATE('now', '-7 days')"
    elif date_filter == "month":
        query += " AND DATE(r.sent_date) >= DATE('now', '-30 days')"

    query += " ORDER BY r.sent_date DESC"

    reports_data = conn.execute(query, params).fetchall()

    total_reports = conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    sent_count = conn.execute("SELECT COUNT(*) FROM reports WHERE LOWER(status) IN ('delivered', 'sent')").fetchone()[0]
    received_count = conn.execute("SELECT COUNT(*) FROM reports WHERE LOWER(status) IN ('seen', 'decrypted')").fetchone()[0]
    pending_count = conn.execute("SELECT COUNT(*) FROM reports WHERE LOWER(status) = 'pending'").fetchone()[0]
    failed_count = 0

    conn.close()

    return render_template(
        "reports.html",
        reports=reports_data,
        total_reports=total_reports,
        sent_count=sent_count,
        received_count=received_count,
        pending_count=pending_count,
        failed_count=failed_count,
        search_query=search,
        status_filter=status_filter,
        date_filter=date_filter
    )


# ============================================================
# VIEW REPORT - ADMIN
# ============================================================

@app.route("/admin_view_report/<int:report_id>")
def admin_view_report(report_id):
    conn = get_db_connection()
    report = conn.execute(
        """
        SELECT r.*,
            d1.doctor_name AS sender_name,
            d2.doctor_name AS receiver_name,
            h1.hospital_name AS from_hospital,
            h2.hospital_name AS to_hospital
        FROM reports r
        LEFT JOIN doctors d1 ON r.sender_id = d1.doctor_id
        LEFT JOIN doctors d2 ON r.receiver_id = d2.doctor_id
        LEFT JOIN hospitals h1 ON d1.hospital_id = h1.hospital_id
        LEFT JOIN hospitals h2 ON d2.hospital_id = h2.hospital_id
        WHERE r.report_id = ?
        """,
        (report_id,)
    ).fetchone()
    conn.close()

    if not report:
        flash("Report not found!", "error")
        return redirect(url_for("reports"))

    return render_template(
        "view_report.html",
        report=report,
        doctor_id=report["sender_id"],
        admin_view=True
    )


# ============================================================
# VIEW REPORT - DOCTOR
# ============================================================

@app.route("/view_report/<int:report_id>")
def view_report(report_id):
    conn = get_db_connection()
    report = conn.execute(
        """
        SELECT r.*,
            d1.doctor_name AS sender_name,
            d2.doctor_name AS receiver_name,
            h1.hospital_name AS from_hospital,
            h2.hospital_name AS to_hospital
        FROM reports r
        LEFT JOIN doctors d1 ON r.sender_id = d1.doctor_id
        LEFT JOIN doctors d2 ON r.receiver_id = d2.doctor_id
        LEFT JOIN hospitals h1 ON d1.hospital_id = h1.hospital_id
        LEFT JOIN hospitals h2 ON d2.hospital_id = h2.hospital_id
        WHERE r.report_id = ?
        """,
        (report_id,)
    ).fetchone()
    conn.close()

    if not report:
        flash("Report not found!", "error")
        return redirect(url_for("reports"))

    return render_template(
        "view_report.html",
        report=report,
        doctor_id=report["sender_id"],
        admin_view=False
    )


# ============================================================
# DOWNLOAD REPORT
# ============================================================

@app.route("/download_report/<int:report_id>")
def download_report(report_id):
    conn = get_db_connection()
    report = conn.execute(
        """
        SELECT r.*,
            d1.doctor_name AS sender_name,
            d2.doctor_name AS receiver_name,
            h1.hospital_name AS from_hospital,
            h2.hospital_name AS to_hospital
        FROM reports r
        LEFT JOIN doctors d1 ON r.sender_id = d1.doctor_id
        LEFT JOIN doctors d2 ON r.receiver_id = d2.doctor_id
        LEFT JOIN hospitals h1 ON d1.hospital_id = h1.hospital_id
        LEFT JOIN hospitals h2 ON d2.hospital_id = h2.hospital_id
        WHERE r.report_id = ?
        """,
        (report_id,)
    ).fetchone()
    conn.close()

    if not report:
        flash("Report not found!", "error")
        return redirect(url_for("reports"))

    content = f"""
========================================
          MEDICAL REPORT
========================================

Report ID:     #{str(report_id).zfill(4)}

Patient:       {report["patient_name"] or "N/A"}
Sender:        {report["sender_name"] or "N/A"}
Receiver:      {report["receiver_name"] or "N/A"}
From Hospital: {report["from_hospital"] or "N/A"}
To Hospital:   {report["to_hospital"] or "N/A"}
Date:          {report["sent_date"] or "N/A"}
Status:        {report["status"] or "Pending"}

SHA-256:
{report["sha256_hash"] or "N/A"}

========================================
"""

    return Response(
        content,
        mimetype="text/plain",
        headers={"Content-Disposition": f"attachment;filename=report_{report_id}.txt"}
    )


# ============================================================
# DELETE REPORT
# ============================================================

@app.route("/delete_report/<int:report_id>")
def delete_report(report_id):
    conn = get_db_connection()
    report = conn.execute(
        "SELECT patient_name, sender_id, receiver_id FROM reports WHERE report_id = ?",
        (report_id,)
    ).fetchone()

    if report:
        try:
            conn.execute("DELETE FROM reports WHERE report_id = ?", (report_id,))
            conn.commit()
            flash(f'Report for "{report["patient_name"]}" deleted successfully!', "warning")
            referrer = request.referrer or ""
            if "view_my_reports" in referrer and report["sender_id"]:
                redirect_url = url_for("view_my_reports", doctor_id=report["sender_id"])
            elif "sent_reports" in referrer and report["sender_id"]:
                redirect_url = url_for("sent_reports", doctor_id=report["sender_id"])
            elif "received_reports" in referrer and report["receiver_id"]:
                redirect_url = url_for("received_reports", doctor_id=report["receiver_id"])
            elif "reports" in referrer:
                redirect_url = url_for("reports")
            else:
                redirect_url = url_for("reports")
        except Exception as e:
            conn.rollback()
            flash(f"Unable to delete report: {str(e)}", "error")
            redirect_url = url_for("reports")
    else:
        flash("Report not found!", "error")
        redirect_url = url_for("reports")

    conn.close()
    return redirect(redirect_url)


# ============================================================
# SEARCH PATIENT
# ============================================================

@app.route("/search_patient")
@app.route("/search_patient/<int:doctor_id>")
def search_patient(doctor_id=None):
    return render_template("search_patient.html", doctor_id=doctor_id)


# ============================================================
# PATIENT DETAILS
# ============================================================

@app.route("/patient_details/<int:doctor_id>")
def patient_details(doctor_id):
    return render_template("patient_details.html", doctor_id=doctor_id)


# ============================================================
# FORGOT PASSWORD - DOCTOR
# ============================================================

@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        if not email:
            flash("Please enter your email address.", "error")
            return redirect(url_for("forgot_password"))

        conn = get_db_connection()
        doctor = conn.execute(
            "SELECT * FROM doctors WHERE LOWER(TRIM(email)) = LOWER(TRIM(?)) LIMIT 1",
            (email,)
        ).fetchone()

        if doctor:
            otp = str(secrets.randbelow(900000) + 100000)
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=10)

            try:
                conn.execute(
                    "DELETE FROM password_resets WHERE doctor_id = ?",
                    (doctor["doctor_id"],)
                )
                conn.execute(
                    """
                    INSERT INTO password_resets
                    (doctor_id, token, otp, expires_at, used, is_verified)
                    VALUES (?, ?, ?, ?, 0, 0)
                    """,
                    (doctor["doctor_id"], "otp_verification", otp, expires_at)
                )
                conn.commit()
            except Exception as e:
                conn.rollback()
                conn.close()
                print("DOCTOR PASSWORD RESET DATABASE ERROR:", e)
                flash(f"Unable to create password reset: {str(e)}", "error")
                return redirect(url_for("forgot_password"))

            conn.close()

            try:
                msg = Message(
                    subject="Your OTP for Password Reset - Secure Medical Center",
                    recipients=[doctor["email"]]
                )
                msg.body = f"""
Hello {doctor["doctor_name"]},

Your One-Time Password (OTP) for password reset is:

{otp}

This OTP is valid for 10 minutes.

Best regards,
MediSecure
"""
                mail.send(msg)
                flash("OTP has been sent to your email.", "success")
                return redirect(url_for("verify_otp", email=doctor["email"]))
            except Exception as e:
                print("MAIL ERROR:", e)
                flash("Unable to send OTP email. Check your mail configuration.", "error")
                return redirect(url_for("forgot_password"))

        else:
            conn.close()
            flash("If an account exists for this email, an OTP has been sent.", "success")
            return redirect(url_for("forgot_password"))

    return render_template("forgot_password.html")


# ============================================================
# VERIFY OTP - DOCTOR (Forgot Password)
# ============================================================

@app.route("/verify-otp/<email>", methods=["GET", "POST"])
def verify_otp(email):
    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()
        conn = get_db_connection()

        doctor = conn.execute(
            "SELECT * FROM doctors WHERE LOWER(TRIM(email)) = LOWER(TRIM(?)) LIMIT 1",
            (email,)
        ).fetchone()

        if not doctor:
            conn.close()
            flash("Account not found!", "error")
            return redirect(url_for("forgot_password"))

        reset_record = conn.execute(
            """
            SELECT * FROM password_resets
            WHERE doctor_id = ? AND used = 0 AND is_verified = 0 AND expires_at > ?
            """,
            (doctor["doctor_id"], datetime.now(timezone.utc))
        ).fetchone()

        if not reset_record:
            conn.close()
            flash("OTP has expired. Please request a new one.", "error")
            return redirect(url_for("forgot_password"))

        if reset_record["otp"] == entered_otp:
            conn.execute(
                "UPDATE password_resets SET is_verified = 1 WHERE reset_id = ?",
                (reset_record["reset_id"],)
            )
            conn.commit()
            conn.close()
            flash("OTP verified successfully!", "success")
            return redirect(url_for("reset_password",
                                    reset_id=reset_record["reset_id"]))

        conn.close()
        flash("Invalid OTP. Please try again.", "error")
        return render_template("verify_otp.html", email=email)

    return render_template("verify_otp.html", email=email)


# ============================================================
# RESET PASSWORD - DOCTOR
# ============================================================

@app.route("/reset_password/<int:reset_id>", methods=["GET", "POST"])
def reset_password(reset_id):
    conn = get_db_connection()
    reset_record = conn.execute(
        """
        SELECT * FROM password_resets
        WHERE reset_id = ? AND is_verified = 1 AND used = 0
        """,
        (reset_id,)
    ).fetchone()

    if not reset_record:
        conn.close()
        flash("Invalid or expired verification.", "error")
        return redirect(url_for("forgot_password"))

    doctor = conn.execute(
        "SELECT * FROM doctors WHERE doctor_id = ?",
        (reset_record["doctor_id"],)
    ).fetchone()

    if not doctor:
        conn.close()
        flash("Doctor account not found.", "error")
        return redirect(url_for("forgot_password"))

    if request.method == "POST":
        new_password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if new_password != confirm_password:
            conn.close()
            flash("Passwords do not match!", "error")
            return render_template("reset_password.html", reset_id=reset_id)

        if len(new_password) < 8:
            conn.close()
            flash("Password must be at least 8 characters long.", "error")
            return render_template("reset_password.html", reset_id=reset_id)

        try:
            hashed_password = generate_password_hash(new_password)
            conn.execute(
                "UPDATE doctors SET password = ? WHERE doctor_id = ?",
                (hashed_password, doctor["doctor_id"])
            )
            conn.execute(
                "UPDATE password_resets SET used = 1 WHERE reset_id = ?",
                (reset_id,)
            )
            conn.commit()
            conn.close()
            flash("Password reset successfully!", "success")
            return redirect(url_for("doctor_login"))
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Password reset failed: {str(e)}", "error")
            return redirect(url_for("forgot_password"))

    conn.close()
    return render_template("reset_password.html", reset_id=reset_id)


# ============================================================
# DOCTOR LOGIN
# ============================================================

@app.route("/doctor_login", methods=["GET", "POST"])
def doctor_login():
    if request.method == "POST":
        login_id = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        conn = get_db_connection()
        doctor = conn.execute(
            """
            SELECT * FROM doctors
            WHERE (LOWER(TRIM(email)) = LOWER(TRIM(?))
                OR LOWER(TRIM(username)) = LOWER(TRIM(?)))
            LIMIT 1
            """,
            (login_id, login_id)
        ).fetchone()
        conn.close()

        if not doctor or not check_password_hash(doctor["password"], password):
            flash("Invalid email or password! Please try again.", "error")
            return redirect(url_for("doctor_login"))

        if doctor["status"] == "Pending":
            flash(
                "Your account is pending Admin approval. Please try again later.",
                "error"
            )
            return redirect(url_for("doctor_login"))

        if doctor["status"] != "Active":
            flash(
                "Your account is not active. Please contact the administrator.",
                "error"
            )
            return redirect(url_for("doctor_login"))

        session["doctor_id"] = doctor["doctor_id"]
        session["doctor_email"] = doctor["email"]
        session["doctor_name"] = doctor["doctor_name"]
        flash(f"Welcome back, Dr. {doctor['doctor_name']}!", "success")
        return redirect(url_for("doctor_dashboard", doctor_id=doctor["doctor_id"]))

    return render_template("doctor_login.html")


# ============================================================
# DOCTOR DASHBOARD
# ============================================================

@app.route("/doctor_dashboard/<int:doctor_id>")
def doctor_dashboard(doctor_id):
    conn = get_db_connection()

    doctor = conn.execute(
        """
        SELECT doctors.*, hospitals.hospital_name
        FROM doctors
        LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
        WHERE doctors.doctor_id = ?
        """,
        (doctor_id,)
    ).fetchone()

    if not doctor:
        conn.close()
        flash("Doctor not found!", "error")
        return redirect(url_for("doctor_login"))

    total_reports = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE sender_id = ?",
        (doctor_id,)
    ).fetchone()[0]

    received_reports = conn.execute(
        "SELECT COUNT(*) FROM reports WHERE receiver_id = ?",
        (doctor_id,)
    ).fetchone()[0]

    sent_reports = conn.execute(
        """
        SELECT COUNT(*) FROM reports
        WHERE sender_id = ?
          AND LOWER(status) IN ('delivered', 'seen', 'decrypted')
        """,
        (doctor_id,)
    ).fetchone()[0]

    recent_activity = []

    recent_sent = conn.execute(
        """
        SELECT patient_name, sent_date 
        FROM reports 
        WHERE sender_id = ? AND status IN ('Delivered', 'Seen', 'Decrypted')
        ORDER BY sent_date DESC LIMIT 1
        """, (doctor_id,)
    ).fetchall()

    for row in recent_sent:
        recent_activity.append({
            'type': 'sent',
            'title': 'Report Sent Successfully',
            'desc': f"Sent report for {row['patient_name']}.",
            'time': row['sent_date'] or 'Just now',
            'icon': 'fa-paper-plane',
            'color': ''
        })

    recent_received = conn.execute(
        """
        SELECT patient_name, sent_date 
        FROM reports 
        WHERE receiver_id = ? 
        ORDER BY sent_date DESC LIMIT 1
        """, (doctor_id,)
    ).fetchall()

    for row in recent_received:
        recent_activity.append({
            'type': 'received',
            'title': 'New Report Received',
            'desc': f"Received report for {row['patient_name']}.",
            'time': row['sent_date'] or 'Just now',
            'icon': 'fa-inbox',
            'color': 'purple'
        })

    recent_uploads = conn.execute(
        """
        SELECT patient_name, upload_date 
        FROM reports 
        WHERE sender_id = ? AND status = 'Pending'
        ORDER BY upload_date DESC LIMIT 1
        """, (doctor_id,)
    ).fetchall()

    for row in recent_uploads:
        recent_activity.append({
            'type': 'upload',
            'title': 'Report Uploaded',
            'desc': f"Uploaded new report for {row['patient_name']}.",
            'time': row['upload_date'] or 'Just now',
            'icon': 'fa-cloud-arrow-up',
            'color': 'blue'
        })

    recent_activity.sort(key=lambda x: str(x['time']), reverse=True)
    recent_activity = recent_activity[:3]

    conn.close()

    return render_template(
        "doctor_dashboard.html",
        doctor=doctor,
        total_reports=total_reports,
        sent_reports=sent_reports,
        received_reports=received_reports,
        recent_activity=recent_activity 
    )


# ============================================================
# VIEW MY REPORTS
# ============================================================

@app.route("/view_my_reports/<int:doctor_id>")
def view_my_reports(doctor_id):
    conn = get_db_connection()
    reports = conn.execute(
        """
        SELECT * FROM reports
        WHERE sender_id = ?
        ORDER BY upload_date DESC
        """,
        (doctor_id,)
    ).fetchall()
    conn.close()

    return render_template(
        "view_my_reports.html",
        doctor_id=doctor_id,
        reports=reports
    )


# ============================================================
# DOCTOR PROFILE
# ============================================================

@app.route("/doctor_profile/<int:doctor_id>")
def doctor_profile(doctor_id):
    conn = get_db_connection()
    doctor = conn.execute(
        """
        SELECT doctors.*, hospitals.hospital_name
        FROM doctors
        LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
        WHERE doctors.doctor_id = ?
        """,
        (doctor_id,)
    ).fetchone()
    conn.close()

    if not doctor:
        flash("Doctor not found!", "error")
        return redirect(url_for("doctor_login"))

    return render_template("doctor_profile.html", doctor=doctor)


# ============================================================
# EDIT DOCTOR PROFILE
# ============================================================

@app.route("/edit_doctor_profile/<int:doctor_id>", methods=["GET", "POST"])
def edit_doctor_profile(doctor_id):
    conn = get_db_connection()
    doctor = conn.execute(
        """
        SELECT doctors.*, hospitals.hospital_name
        FROM doctors
        LEFT JOIN hospitals ON doctors.hospital_id = hospitals.hospital_id
        WHERE doctors.doctor_id = ?
        """,
        (doctor_id,)
    ).fetchone()

    if not doctor:
        conn.close()
        flash("Doctor not found!", "error")
        return redirect(url_for("doctor_login"))

    if request.method == "POST":
        try:
            doctor_name = request.form.get("doctor_name", "").strip()
            specialization = request.form.get("specialization", "").strip()
            email = request.form.get("email", "").strip()
            phone = request.form.get("phone", "").strip()
            experience = request.form.get("experience", 0)
            license_number = request.form.get("license_number", "").strip()
            address = request.form.get("address", "").strip()

            if "profile_pic" in request.files:
                file = request.files["profile_pic"]
                if file and file.filename:
                    filename = secure_filename(file.filename)
                    filename = f"doc_{doctor_id}_{filename}"
                    upload_folder = os.path.join(app.static_folder, "uploads")
                    os.makedirs(upload_folder, exist_ok=True)
                    file.save(os.path.join(upload_folder, filename))
                    conn.execute(
                        "UPDATE doctors SET profile_pic = ? WHERE doctor_id = ?",
                        (filename, doctor_id)
                    )

            conn.execute(
                """
                UPDATE doctors SET
                    doctor_name = ?, specialization = ?, email = ?,
                    phone = ?, experience = ?, license_number = ?, address = ?
                WHERE doctor_id = ?
                """,
                (doctor_name, specialization, email, phone,
                 experience, license_number, address, doctor_id)
            )
            conn.commit()
            conn.close()
            flash("Profile updated successfully!", "success")
            return redirect(url_for("doctor_profile", doctor_id=doctor_id))
        except Exception as e:
            conn.rollback()
            conn.close()
            flash(f"Error: {str(e)}", "error")
            return redirect(url_for("edit_doctor_profile", doctor_id=doctor_id))

    conn.close()
    return render_template("edit_doctor_profile.html", doctor=doctor)


# ============================================================
# UPLOAD MEDICAL REPORT
# ============================================================

@app.route("/upload_report/<int:doctor_id>", methods=["GET", "POST"])
def upload_report(doctor_id):
    if request.method == "POST":
        patient_name = request.form.get("patient_name", "").strip()
        patient_id = request.form.get("patient_id", "").strip()
        age = request.form.get("age", "").strip()
        gender = request.form.get("gender", "").strip()
        diagnosis = request.form.get("diagnosis", "").strip()
        prescription = request.form.get("prescription", "").strip()
        pdf_file = request.files.get("pdf")
        image_file = request.files.get("image")

        if not patient_name:
            flash("Please enter patient name.", "error")
            return redirect(url_for("upload_report", doctor_id=doctor_id))

        if not pdf_file or not pdf_file.filename:
            flash("Please select a medical report.", "error")
            return redirect(url_for("upload_report", doctor_id=doctor_id))

        allowed_report_extensions = {"pdf", "jpg", "jpeg", "png"}
        report_extension = (pdf_file.filename.rsplit(".", 1)[-1].lower()
                            if "." in pdf_file.filename else "")
        if report_extension not in allowed_report_extensions:
            flash("Medical report must be PDF, JPG, JPEG or PNG.", "error")
            return redirect(url_for("upload_report", doctor_id=doctor_id))

        allowed_image_extensions = {"jpg", "jpeg", "png"}
        image_filename = None

        if image_file and image_file.filename:
            image_extension = (image_file.filename.rsplit(".", 1)[-1].lower()
                               if "." in image_file.filename else "")
            if image_extension not in allowed_image_extensions:
                flash("X-ray/MRI/CT image must be JPG, JPEG or PNG.", "error")
                return redirect(url_for("upload_report", doctor_id=doctor_id))

        upload_folder = os.path.join(app.static_folder, "uploads")
        os.makedirs(upload_folder, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        pdf_original_name = secure_filename(pdf_file.filename)
        pdf_filename = f"{timestamp}_{pdf_original_name}"
        pdf_path = os.path.join(upload_folder, pdf_filename)
        pdf_file.save(pdf_path)

        print("Medical report saved:", pdf_filename)

        if image_file and image_file.filename:
            image_original_name = secure_filename(image_file.filename)
            image_filename = f"{timestamp}_{image_original_name}"
            image_path = os.path.join(upload_folder, image_filename)
            image_file.save(image_path)
            print("Medical image saved:", image_filename)
        else:
            image_filename = None
            print("No X-ray/MRI/CT image uploaded.")

        with open(pdf_path, "rb") as f:
            pdf_data = f.read()

        sha256_hash = generate_sha256(pdf_data)
        print("SHA-256:", sha256_hash)

        conn = get_db_connection()
        try:
            conn.execute(
                """
                INSERT INTO reports
                (sender_id, patient_name, patient_number, age, gender,
                 diagnosis, prescription, report_file, xray_image,
                 sha256_hash, status, upload_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (doctor_id, patient_name, patient_id, age, gender,
                 diagnosis, prescription, pdf_filename, image_filename,
                 sha256_hash, "Pending",
                 datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            print("UPLOAD DATABASE ERROR:", e)
            conn.close()
            flash(f"Could not save medical report: {str(e)}", "error")
            return redirect(url_for("upload_report", doctor_id=doctor_id))

        conn.close()

        if image_filename:
            flash("Medical report and X-ray/MRI image uploaded successfully.", "success")
        else:
            flash("Medical report uploaded successfully. X-ray/MRI image was not provided.", "success")

        return redirect(url_for("send_secure_report", doctor_id=doctor_id))

    return render_template("upload_report.html", doctor_id=doctor_id)


# ============================================================
# SEND SECURE REPORT
# ============================================================

@app.route("/send_secure_report/<int:doctor_id>", methods=["GET", "POST"])
def send_secure_report(doctor_id):
    if request.method == "POST":
        report_id = request.form.get("report_id", "").strip()
        receiver_id = request.form.get("receiver_id", "").strip()

        if not report_id:
            flash("Please select a medical report.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        if not receiver_id:
            flash("Please select a receiver doctor.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        conn = get_db_connection()
        report = conn.execute(
            "SELECT * FROM reports WHERE report_id = ? AND sender_id = ?",
            (report_id, doctor_id)
        ).fetchone()

        if not report:
            conn.close()
            flash("Medical report not found.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        receiver = conn.execute(
            "SELECT * FROM doctors WHERE doctor_id = ?", (receiver_id,)
        ).fetchone()

        if not receiver:
            conn.close()
            flash("Receiver doctor not found.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        receiver_public_key = receiver["public_key"]

        if not receiver_public_key:
            conn.close()
            flash("Receiver does not have a public key.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        upload_folder = os.path.join(app.static_folder, "uploads")
        os.makedirs(upload_folder, exist_ok=True)

        report_filename = report["report_file"]

        if not report_filename:
            conn.close()
            flash("Medical report file is missing.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        report_path = os.path.join(upload_folder, report_filename)

        if not os.path.exists(report_path):
            conn.close()
            flash("Medical report file could not be found.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        xray_filename = report["xray_image"]
        xray_data = None

        if xray_filename:
            xray_path = os.path.join(upload_folder, xray_filename)
            if not os.path.exists(xray_path):
                conn.close()
                flash("X-ray/MRI/CT image could not be found.", "error")
                return redirect(url_for("send_secure_report", doctor_id=doctor_id))
            with open(xray_path, "rb") as file:
                xray_data = file.read()

        with open(report_path, "rb") as file:
            report_data = file.read()

        prescription = report["prescription"] or ""
        patient_name = report["patient_name"] or ""
        patient_id_val = report["patient_number"] or ""
        age = report["age"] or ""
        gender = report["gender"] or ""
        diagnosis = report["diagnosis"] or ""

        try:
            medical_payload = create_medical_payload(
                report_data=report_data,
                report_filename=report_filename,
                xray_data=xray_data,
                xray_filename=xray_filename,
                prescription=prescription,
                patient_name=patient_name,
                patient_id=patient_id_val,
                age=age,
                gender=gender,
                diagnosis=diagnosis
            )
        except Exception as e:
            conn.close()
            flash(f"Could not create medical payload: {str(e)}", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        sha256_hash = generate_sha256(medical_payload)
        aes_key = get_random_bytes(32)

        try:
            encrypted_payload = aes_encrypt(medical_payload, aes_key)
        except Exception as e:
            conn.close()
            flash(f"AES encryption failed: {str(e)}", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        try:
            encrypted_aes_key = rsa_encrypt_key(
                aes_key, receiver_public_key.encode("utf-8")
            )
        except Exception as e:
            conn.close()
            flash(f"RSA encryption failed: {str(e)}", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        encrypted_envelope = (
            struct.pack(">I", len(encrypted_aes_key))
            + encrypted_aes_key
            + encrypted_payload
        )

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S%f")
        cover_filename = f"medical_cover_{report_id}_{timestamp}.png"
        cover_path = os.path.join(upload_folder, cover_filename)

        try:
            generate_medical_cover(output_path=cover_path,
                                    payload_size=len(encrypted_envelope))
        except Exception as e:
            conn.close()
            flash(f"Could not generate medical cover image: {str(e)}", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        stego_filename = f"stego_report_{report_id}_{timestamp}.png"
        stego_path = os.path.join(upload_folder, stego_filename)

        try:
            embed_data_dwt(cover_path, encrypted_envelope, stego_path)
        except Exception as e:
            if os.path.exists(cover_path):
                os.remove(cover_path)
            conn.close()
            flash(f"Steganography failed: {str(e)}", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        encrypted_filename = f"encrypted_payload_{report_id}_{timestamp}.enc"
        encrypted_path = os.path.join(upload_folder, encrypted_filename)

        try:
            with open(encrypted_path, "wb") as file:
                file.write(encrypted_payload)
        except Exception as e:
            if os.path.exists(cover_path):
                os.remove(cover_path)
            if os.path.exists(stego_path):
                os.remove(stego_path)
            conn.close()
            flash(f"Could not save encrypted payload: {str(e)}", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        encrypted_aes_key_hex = encrypted_aes_key.hex()

        try:
            conn.execute(
                """
                UPDATE reports
                SET receiver_id = ?,
                    encrypted_file = ?,
                    stego_image = ?,
                    encrypted_aes_key = ?,
                    sha256_hash = ?,
                    status = ?,
                    sent_date = ?
                WHERE report_id = ? AND sender_id = ?
                """,
                (receiver_id, encrypted_filename, stego_filename,
                 encrypted_aes_key_hex, sha256_hash,
                 "Delivered",
                 datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                 report_id, doctor_id)
            )
            conn.commit()
        except Exception as e:
            conn.rollback()
            conn.close()
            for file_path in [cover_path, stego_path, encrypted_path]:
                if os.path.exists(file_path):
                    os.remove(file_path)
            flash(f"Could not update report: {str(e)}", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        if os.path.exists(cover_path):
            os.remove(cover_path)

        conn.close()

        flash(
            "✅ Message sent successfully! The medical report, X-ray/MRI/CT and prescription "
            "were encrypted and securely hidden inside the medical-themed image.",
            "success"
        )

        return redirect(url_for("send_secure_report", doctor_id=doctor_id))

    conn = get_db_connection()
    reports = conn.execute(
        """
        SELECT * FROM reports
        WHERE sender_id = ?
          AND status NOT IN ('Delivered', 'Seen', 'Decrypted')
        ORDER BY upload_date DESC
        """,
        (doctor_id,)
    ).fetchall()

    doctors = conn.execute(
        """
        SELECT doctor_id, doctor_name, email, specialization, public_key
        FROM doctors
        WHERE doctor_id != ?
        ORDER BY doctor_name
        """,
        (doctor_id,)
    ).fetchall()

    conn.close()

    selected_report_id = request.args.get("report_id")

    return render_template(
        "send_secure_report.html",
        doctor_id=doctor_id,
        reports=reports,
        doctors=doctors,
        selected_report_id=selected_report_id
    )


# ============================================================
# GENERATE AI MEDICAL REPORT SUMMARY
# ============================================================

@app.route(
    "/generate_ai_summary/<int:doctor_id>/<int:report_id>",
    methods=["POST"]
)
def generate_ai_summary_route(doctor_id, report_id):
    conn = get_db_connection()
    try:
        report = conn.execute(
            """
            SELECT report_id, report_file, ai_summary
            FROM reports
            WHERE report_id = ? AND sender_id = ?
            """,
            (report_id, doctor_id)
        ).fetchone()

        if not report:
            flash("Medical report not found.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        if report["ai_summary"]:
            flash("AI summary is already available.", "success")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id, report_id=report_id))

        report_filename = report["report_file"]

        if not report_filename:
            flash("Medical report file is missing.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        if not report_filename.lower().endswith(".pdf"):
            flash("AI summarization currently supports PDF reports only.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        upload_folder = os.path.join(app.static_folder, "uploads")
        report_path = os.path.join(upload_folder, report_filename)

        if not os.path.isfile(report_path):
            flash("Medical report file could not be found.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        summary = generate_medical_summary(report_path)

        if not summary or not summary.strip():
            flash("AI could not generate a summary.", "error")
            return redirect(url_for("send_secure_report", doctor_id=doctor_id))

        conn.execute(
            """
            UPDATE reports
            SET ai_summary = ?
            WHERE report_id = ? AND sender_id = ?
            """,
            (summary, report_id, doctor_id)
        )
        conn.commit()
        flash("AI medical report summary generated successfully!", "success")

    except Exception as e:
        conn.rollback()
        print("AI SUMMARY ERROR:", str(e))
        flash(f"AI summarization failed: {str(e)}", "error")

    finally:
        conn.close()

    return redirect(url_for("send_secure_report", doctor_id=doctor_id, report_id=report_id))


# ============================================================
# SENT REPORTS
# ============================================================

@app.route("/sent_reports/<int:doctor_id>", methods=["GET"])
def sent_reports(doctor_id):
    conn = get_db_connection()
    search = request.args.get("search", "")
    status_filter = request.args.get("status", "all")

    query = """
        SELECT
            r.report_id, r.patient_name, r.sent_date, r.status,
            NULL AS report_type,
            d2.doctor_name AS receiver_name,
            h2.hospital_name AS to_hospital
        FROM reports r
        LEFT JOIN doctors d2 ON r.receiver_id = d2.doctor_id
        LEFT JOIN hospitals h2 ON d2.hospital_id = h2.hospital_id
        WHERE r.sender_id = ?
          AND r.status IN ('Pending', 'Delivered', 'Seen', 'Decrypted')
    """
    params = [doctor_id]

    if search:
        query += """
            AND (r.patient_name LIKE ? OR r.report_id LIKE ?)
        """
        search_param = f"%{search}%"
        params.extend([search_param, search_param])

    if status_filter != "all":
        query += " AND LOWER(r.status) = ?"
        params.append(status_filter.lower())

    query += " ORDER BY r.sent_date DESC"

    reports_data = conn.execute(query, params).fetchall()
    conn.close()

    return render_template(
        "sent_reports.html",
        doctor_id=doctor_id,
        reports=reports_data,
        search_query=search,
        status_filter=status_filter
    )


# ============================================================
# RECEIVED REPORTS
# ============================================================

@app.route("/received_reports/<int:doctor_id>")
def received_reports(doctor_id):
    conn = get_db_connection()
    try:
        reports_data = conn.execute(
            """
            SELECT
                r.report_id, r.patient_name, r.sent_date, r.status,
                r.stego_image, r.encrypted_file, r.encrypted_aes_key,
                d1.doctor_name AS sender_name,
                d2.doctor_name AS receiver_name,
                h1.hospital_name AS from_hospital,
                h2.hospital_name AS to_hospital
            FROM reports r
            LEFT JOIN doctors d1 ON r.sender_id = d1.doctor_id
            LEFT JOIN doctors d2 ON r.receiver_id = d2.doctor_id
            LEFT JOIN hospitals h1 ON d1.hospital_id = h1.hospital_id
            LEFT JOIN hospitals h2 ON d2.hospital_id = h2.hospital_id
            WHERE r.receiver_id = ?
            ORDER BY r.sent_date DESC
            """,
            (doctor_id,)
        ).fetchall()
    except Exception as e:
        print("RECEIVED REPORTS ERROR:", e)
        conn.close()
        flash("Unable to load received reports.", "error")
        return redirect(url_for("doctor_dashboard", doctor_id=doctor_id))

    conn.close()

    return render_template(
        "received_reports.html",
        doctor_id=doctor_id,
        reports=reports_data
    )


# ============================================================
# DECRYPT REPORT
# ============================================================

@app.route("/decrypt_report/<int:doctor_id>", methods=["GET", "POST"])
def decrypt_report(doctor_id):
    report_id = request.args.get("report_id") or request.form.get("report_id")
    
    if not report_id:
        flash("Please select a report.", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))

    conn = get_db_connection()
    
    report = conn.execute(
        """
        SELECT r.*, 
               d1.doctor_name AS sender_name,
               h1.hospital_name AS from_hospital
        FROM reports r
        LEFT JOIN doctors d1 ON r.sender_id = d1.doctor_id
        LEFT JOIN hospitals h1 ON d1.hospital_id = h1.hospital_id
        WHERE r.report_id = ? AND r.receiver_id = ?
        """,
        (report_id, doctor_id)
    ).fetchone()
    
    if not report:
        conn.close()
        flash("Report not found or unauthorized.", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))

    if request.method == "GET":
        if report["status"] in ["Decrypted", "Seen"] and report["decrypted_metadata"]:
            metadata = json.loads(report["decrypted_metadata"])
            conn.close()
            return render_template(
                "decrypt_report.html",
                doctor_id=doctor_id,
                report=report,
                reports=[report],
                patient_info=metadata.get("patient_info"),
                prescription=metadata.get("prescription"),
                decrypted_report_filename=metadata.get("report_file"),
                decrypted_xray_filename=metadata.get("xray_file"),
                hash_verified=True,
                is_view_mode=True,
                ai_summary=report["ai_summary"]
            )
        else:
            conn.close()
            return render_template(
                "decrypt_report.html",
                doctor_id=doctor_id,
                report=report,
                reports=[report]
            )

    private_key_file = request.files.get("private_key_file")
    if not private_key_file or not private_key_file.filename:
        flash("Please upload your private RSA key (.pem).", "error")
        return redirect(url_for("decrypt_report", doctor_id=doctor_id, report_id=report_id))

    if not report["stego_image"]:
        conn.close()
        flash("Stego image is missing.", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))

    if not report["encrypted_file"]:
        conn.close()
        flash("Encrypted file information is missing.", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))

    if not report["encrypted_aes_key"]:
        conn.close()
        flash("Encrypted AES key is missing from the database.", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))

    upload_folder = os.path.join(app.static_folder, "uploads")
    stego_path = os.path.join(upload_folder, report["stego_image"])
    encrypted_path = os.path.join(upload_folder, report["encrypted_file"])

    if not os.path.exists(stego_path) or not os.path.exists(encrypted_path):
        conn.close()
        flash("Encrypted files not found on server.", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))

    try:
        private_key_data = private_key_file.read()
        if not private_key_data:
            raise Exception("Private key file is empty.")

        envelope = extract_data_dwt(stego_path)
        rsa_key_len = struct.unpack(">I", envelope[:4])[0]
        encrypted_aes_key = envelope[4:4 + rsa_key_len]
        encrypted_data = envelope[4 + rsa_key_len:]

        aes_key = rsa_decrypt_key(encrypted_aes_key, private_key_data)
        decrypted_data = aes_decrypt(encrypted_data, aes_key)

        is_valid = verify_hash(decrypted_data, report["sha256_hash"])
        if not is_valid:
            print("SHA-256 verification FAILED.")
            conn.close()
            flash("❌ Hash verification failed! The medical data may have been modified.", "error")
            return redirect(url_for("received_reports", doctor_id=doctor_id))

        contents = extract_medical_payload(decrypted_data)

        original_report_filename = (
            contents["report_filename"]
            or report["report_file"]
            or "medical_report.pdf"
        )

        if "." in original_report_filename:
            original_ext = original_report_filename.rsplit(".", 1)[-1].lower()
        else:
            original_ext = "bin"

        decrypted_report_filename = f"decrypted_report_{report['report_id']}.{original_ext}"
        decrypted_report_path = os.path.join(upload_folder, decrypted_report_filename)

        with open(decrypted_report_path, "wb") as f:
            f.write(contents["report_data"] or b"")

        decrypted_xray_filename = None

        if contents["xray_data"] and contents["xray_filename"]:
            xray_name = secure_filename(contents["xray_filename"])
            if "." in xray_name:
                xray_ext = xray_name.rsplit(".", 1)[-1].lower()
            else:
                xray_ext = "png"

            decrypted_xray_filename = f"decrypted_xray_{report['report_id']}.{xray_ext}"
            decrypted_xray_path = os.path.join(upload_folder, decrypted_xray_filename)

            with open(decrypted_xray_path, "wb") as f:
                f.write(contents["xray_data"])

        metadata_to_save = {
            "patient_info": contents["patient_information"],
            "prescription": contents["prescription"],
            "report_file": decrypted_report_filename,
            "xray_file": decrypted_xray_filename
        }
        
        conn.execute(
            """
            UPDATE reports 
            SET status = 'Decrypted', decrypted_metadata = ? 
            WHERE report_id = ?
            """,
            (json.dumps(metadata_to_save), report["report_id"])
        )
        conn.commit()
        conn.close()

        return render_template(
            "decrypt_report.html",
            doctor_id=doctor_id,
            report=report,
            reports=[report],
            decrypted_report_filename=decrypted_report_filename,
            decrypted_xray_filename=decrypted_xray_filename,
            patient_info=contents["patient_information"],
            prescription=contents["prescription"],
            hash_verified=True,
            ai_summary=report["ai_summary"]
        )

    except ValueError as e:
        conn.close()
        print("PRIVATE KEY / DATA ERROR:", e)
        flash("Invalid private key or encrypted data.", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))

    except Exception as e:
        conn.close()
        print("========================================")
        print("DECRYPTION ERROR:")
        print(str(e))
        print("========================================")
        flash(f"Decryption failed: {str(e)}", "error")
        return redirect(url_for("received_reports", doctor_id=doctor_id))


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("home"))


# ============================================================
# RUN FLASK
# ============================================================

if __name__ == "__main__":
    app.run(debug=True)