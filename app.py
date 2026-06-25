"""
Institutional Gate Pass and Visitor Management System
======================================================
Main application module: models, routes, and API endpoints.
SQLAlchemy models are written for SQLite (dev) with full MySQL compatibility.
"""

import csv
import io
import logging
import os
import re
import smtplib
import ssl
import threading
import urllib.parse
import uuid
from datetime import datetime, date, timedelta
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from functools import wraps

import qrcode
import base64
from flask import (
    Flask, render_template, request, redirect, url_for,
    session, jsonify, abort, send_file
)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

# ---------------------------------------------------------------------------
# App & DB Configuration
# ---------------------------------------------------------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-in-production-32chars!")

_db_url = os.environ.get("DATABASE_URL", "sqlite:///" + os.path.join(BASE_DIR, "gatepass.db"))
if _db_url.startswith("mysql://"):
    _db_url = _db_url.replace("mysql://", "mysql+pymysql://", 1)
app.config["SQLALCHEMY_DATABASE_URI"] = _db_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 28800  # 8-hour session timeout

db = SQLAlchemy(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQLAlchemy Models
# ---------------------------------------------------------------------------

class User(db.Model):
    """Authenticated system users: internal requesters, admins, and guards."""
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    login_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # role: 'internal' | 'admin' | 'guard'
    role = db.Column(db.String(32), nullable=False, default="internal")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.login_id} [{self.role}]>"


class PassRequest(db.Model):
    """Gate pass request submitted by an internal user (student/staff)."""
    __tablename__ = "pass_requests"

    id = db.Column(db.Integer, primary_key=True)
    requester_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False)
    requester_name = db.Column(db.String(128), nullable=False)
    requester_type = db.Column(db.String(64), nullable=False)  # e.g. Student / Staff
    destination = db.Column(db.String(256), nullable=False)
    visit_date = db.Column(db.Date, nullable=False)
    time_window = db.Column(db.String(64), nullable=False)  # e.g. "09:00 - 18:00"
    reason = db.Column(db.Text, nullable=False)
    visitor_name = db.Column(db.String(128), nullable=True)
    visitor_national_id = db.Column(db.String(64), nullable=True)
    visitor_phone = db.Column(db.String(32), nullable=True)
    visitor_email = db.Column(db.String(128), nullable=True)
    visitor_vehicle_reg = db.Column(db.String(32), nullable=True)
    # status: 'Pending' | 'Approved' | 'Rejected' | 'Expired'
    status = db.Column(db.String(32), nullable=False, default="Pending")
    comments = db.Column(db.Text, nullable=True)
    qr_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    requester = db.relationship("User", backref="pass_requests")

    def __repr__(self):
        return f"<PassRequest {self.id} [{self.status}]>"


class VisitorRequest(db.Model):
    """Gate pass request submitted by an external visitor via the public portal."""
    __tablename__ = "visitor_requests"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    national_id = db.Column(db.String(64), nullable=False, index=True)
    phone = db.Column(db.String(32), nullable=False)
    email = db.Column(db.String(128), nullable=False)
    visit_date = db.Column(db.Date, nullable=False)
    vehicle_reg = db.Column(db.String(32), nullable=True)
    department = db.Column(db.String(128), nullable=False)
    purpose = db.Column(db.Text, nullable=False)
    # status: 'Pending' | 'Approved' | 'Rejected' | 'Expired'
    status = db.Column(db.String(32), nullable=False, default="Pending")
    qr_token = db.Column(db.String(64), unique=True, nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<VisitorRequest {self.id} [{self.status}]>"


class AuditLog(db.Model):
    """Immutable security ledger recording every scan event at the gate."""
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    # scan_type: 'ENTRY' | 'EXIT' | 'WALK-IN'
    scan_type = db.Column(db.String(20), nullable=False)
    guard_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    qr_token = db.Column(db.String(64), nullable=False)
    # pass_type: 'internal' | 'visitor' | 'unknown'
    pass_type = db.Column(db.String(20), nullable=False, default="internal")
    # result: 'VALID' | 'INVALID' | 'BLACKLISTED'
    result = db.Column(db.String(20), nullable=False)
    note = db.Column(db.Text, nullable=True)
    scanned_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AuditLog {self.id} [{self.result}]>"


class Blacklist(db.Model):
    """Individuals permanently banned from campus access."""
    __tablename__ = "blacklist"

    id = db.Column(db.Integer, primary_key=True)
    national_id = db.Column(db.String(64), unique=True, nullable=False, index=True)
    name = db.Column(db.String(128), nullable=False)
    reason = db.Column(db.Text, nullable=True)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Blacklist {self.national_id}>"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_SCAN_TYPES = {"ENTRY", "EXIT", "WALK-IN"}
VALID_PASS_TYPES = {"internal", "visitor"}

DEPARTMENTS = [
    "Administration", "Admissions", "Computer Science", "Engineering",
    "Finance Office", "Human Resources", "ICT Support", "Library",
    "Medical Centre", "Registry", "Security", "Student Affairs",
]

# ---------------------------------------------------------------------------
# Brute-force login protection (in-memory; resets on server restart)
# ---------------------------------------------------------------------------

_login_lock = threading.Lock()
_login_attempts: dict = {}   # login_id -> {"count": int, "locked_until": datetime|None}
_MAX_ATTEMPTS = 5
_LOCKOUT_MINUTES = 15


def _check_rate_limit(login_id: str):
    with _login_lock:
        entry = _login_attempts.get(login_id)
        if not entry:
            return None
        locked_until = entry.get("locked_until")
        if locked_until and datetime.utcnow() < locked_until:
            mins = int((locked_until - datetime.utcnow()).total_seconds() / 60) + 1
            return f"Too many failed attempts. Try again in {mins} minute(s)."
        return None


def _record_failure(login_id: str):
    with _login_lock:
        entry = _login_attempts.setdefault(login_id, {"count": 0, "locked_until": None})
        if entry.get("locked_until") and datetime.utcnow() >= entry["locked_until"]:
            entry["count"] = 0
            entry["locked_until"] = None
        entry["count"] += 1
        if entry["count"] >= _MAX_ATTEMPTS:
            entry["locked_until"] = datetime.utcnow() + timedelta(minutes=_LOCKOUT_MINUTES)
            entry["count"] = 0
            logger.warning("Login account locked after repeated failures: %s", login_id)


def _clear_rate_limit(login_id: str):
    with _login_lock:
        _login_attempts.pop(login_id, None)


# ---------------------------------------------------------------------------
# Input validation helpers
# ---------------------------------------------------------------------------

_FIELD_MAX_LEN = {
    "destination": 256, "time_window": 64, "reason": 2000,
    "visitor_name": 128, "visitor_national_id": 64, "visitor_phone": 32,
    "visitor_email": 128, "name": 128, "national_id": 64,
    "phone": 32, "email": 128, "department": 128, "purpose": 2000,
}


def _validate_lengths(data: dict):
    for field, maxlen in _FIELD_MAX_LEN.items():
        val = data.get(field)
        if val and len(str(val)) > maxlen:
            return f"Field '{field}' exceeds maximum length ({maxlen} characters)."
    return None


def _normalize_national_id(national_id: str) -> str:
    """Strip whitespace and uppercase for consistent blacklist matching."""
    return re.sub(r"\s+", "", (national_id or "").strip().upper())


def _get_blacklist_entry(national_id: str):
    """Return a Blacklist row if the ID matches (case/whitespace-insensitive)."""
    normalized = _normalize_national_id(national_id)
    if not normalized:
        return None
    for entry in Blacklist.query.all():
        if _normalize_national_id(entry.national_id) == normalized:
            return entry
    return None


def _pass_record_national_id(record, pass_type: str) -> str:
    """Extract the visitor national ID from an internal or public pass record."""
    if pass_type == "internal":
        return record.visitor_national_id or ""
    return record.national_id or ""


_BLACKLIST_MSG = "Access denied. This ID is on the security blacklist."


def sweep_expired_passes():
    """Mark approved passes as Expired once their visit date is in the past."""
    today = date.today()
    for req in PassRequest.query.filter_by(status="Approved").all():
        if req.visit_date < today:
            req.status = "Expired"
    for req in VisitorRequest.query.filter_by(status="Approved").all():
        if req.visit_date < today:
            req.status = "Expired"
    db.session.commit()


# ---------------------------------------------------------------------------
# Auth decorators
# ---------------------------------------------------------------------------

def role_required(role):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("index"))
            _u = User.query.get(session["user_id"])
            if not _u or _u.role != role:
                session.clear()
                abort(403)
            return f(*args, **kwargs)
        return wrapped
    return decorator


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("index"))
        if not User.query.get(session["user_id"]):
            session.clear()
            return redirect(url_for("index"))
        return f(*args, **kwargs)
    return wrapped


# ---------------------------------------------------------------------------
# Email delivery helper
# ---------------------------------------------------------------------------

def send_gatepass_email(visitor_email, visitor_name, qr_token, visit_date):
    """Send a professional gate pass confirmation email via Brevo HTTP API."""
    import urllib.request
    import json
    import base64
    import os
    import qrcode
    import io

    api_key = os.environ.get("BREVO_API_KEY")
    sender_email = os.environ.get("MAIL_USERNAME")

    if not api_key or not sender_email:
        logger.warning("BREVO_API_KEY or MAIL_USERNAME not configured — email skipped.")
        return

    visit_str = (
        visit_date.strftime("%A, %d %B %Y")
        if hasattr(visit_date, "strftime")
        else str(visit_date)
    )

    # Generate QR code image bytes
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(qr_token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    img_b64 = base64.b64encode(buf.getvalue()).decode()

    html_body = f"""<!DOCTYPE html>
    <html><body style="margin:0;padding:0;background:#f1f5f9;font-family:Arial,sans-serif;">
    <div style="max-width:600px;margin:0 auto;background:#ffffff;padding:32px;border-radius:8px;border:1px solid #e2e8f0;margin-top:32px;">
      <h2 style="color:#0f172a;margin-top:0;">Kabarak University Gate Pass</h2>
      <p style="color:#475569;font-size:15px;">Dear <strong>{visitor_name}</strong>,</p>
      <p style="color:#475569;font-size:15px;">Your gate pass request for <strong>{visit_str}</strong> has been approved.</p>

      <div style="background:#f8fafc;padding:24px;border-radius:8px;text-align:center;border:1px solid #e2e8f0;margin:24px 0;">
        <p style="font-weight:bold;color:#1e293b;margin-bottom:16px;">Gate Pass QR Code</p>
        <img src="data:image/png;base64,{img_b64}" alt="QR Code" style="width:200px;height:200px;" />
        <p style="font-size:13px;color:#64748b;margin-top:16px;">
          * A high-quality copy of this QR code is also attached to this email.
        </p>
        <p style="font-weight:bold;color:#1e293b;margin:24px 0 8px;">Gate Pass Token</p>
        <p style="font-family:Consolas,Monaco,monospace;font-size:14px;color:#0f172a;background:#ffffff;
                  border:1px dashed #cbd5e1;border-radius:6px;padding:12px 16px;word-break:break-all;
                  letter-spacing:0.5px;margin:0;">{qr_token}</p>
        <p style="font-size:12px;color:#64748b;margin-top:12px;">
          If scanning fails, give this token to security for manual entry at the gate.
        </p>
      </div>

      <p style="color:#475569;font-size:14px;">Present this QR code or token to the security officer at the main campus gate upon arrival.</p>
    </div>
    </body></html>"""

    # Build the Brevo API JSON payload
    payload = {
        "sender": {"name": "Kabarak University Security", "email": sender_email},
        "to": [{"email": visitor_email, "name": visitor_name}],
        "subject": f"Gate Pass Approved — {visit_str}",
        "htmlContent": html_body,
        "attachment": [{"content": img_b64, "name": "GatePass_QRCode.png"}]
    }

    req = urllib.request.Request(
        "https://api.brevo.com/v3/smtp/email",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "api-key": api_key,
            "Content-Type": "application/json",
            "Accept": "application/json"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req) as response:
            logger.info("Email sent via API to %s. Status: %s", visitor_email, response.status)
    except Exception as exc:
        logger.error("Failed to send email via API to %s: %s", visitor_email, exc)


# ---------------------------------------------------------------------------
# QR code helper
# ---------------------------------------------------------------------------

def generate_qr_base64(token: str) -> str:
    """Return a base64-encoded PNG data URI for the given QR token."""
    qr = qrcode.QRCode(box_size=8, border=2)
    qr.add_data(token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()


@app.route("/pass/<qr_token>/qr")
def pass_qr_image(qr_token):
    """Generate and serve a QR code PNG for the given pass token (in-memory, no disk write)."""
    qr = qrcode.QRCode(version=1, box_size=8, border=2)
    qr.add_data(qr_token)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return send_file(buf, mimetype="image/png")


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Root: redirect logged-in users by role, otherwise go to overview."""
    if "user_id" in session:
        role = session.get("role", "")
        if role == "admin":
            return redirect(url_for("admin_page"))
        if role == "guard":
            return redirect(url_for("guard_page"))
        return redirect(url_for("requester_page"))
    return redirect(url_for("auth_page"))


@app.route("/auth", methods=["GET", "POST"])
def auth_page():
    if request.method == "GET":
        return render_template("auth.html")

    login_id = request.form.get("login_id", "").strip()
    password = request.form.get("password", "").strip()

    lock_err = _check_rate_limit(login_id)
    if lock_err:
        return render_template("auth.html", error=lock_err)

    user = User.query.filter_by(login_id=login_id).first()
    if not user or not user.check_password(password):
        _record_failure(login_id)
        return render_template("auth.html", error="Invalid credentials. Please try again.")

    _clear_rate_limit(login_id)
    session["user_id"] = user.id
    session["role"] = user.role
    session["user_name"] = user.name

    if user.role == "admin":
        return redirect(url_for("admin_page"))
    if user.role == "guard":
        return redirect(url_for("guard_page"))
    return redirect(url_for("requester_page"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/admin")
@role_required("admin")
def admin_page():
    sweep_expired_passes()
    search = request.args.get("search", "").strip()
    internal_page = request.args.get("internal_page", 1, type=int)
    visitor_page = request.args.get("visitor_page", 1, type=int)

    pending_internal = (
        PassRequest.query.filter_by(status="Pending")
        .order_by(PassRequest.created_at.desc()).all()
    )
    pending_visitor = (
        VisitorRequest.query.filter_by(status="Pending")
        .order_by(VisitorRequest.created_at.desc()).all()
    )
    pending_count = len(pending_internal) + len(pending_visitor)

    recent_audit = AuditLog.query.order_by(AuditLog.scanned_at.desc()).limit(20).all()
    blacklist = Blacklist.query.order_by(Blacklist.added_at.desc()).all()
    all_users = User.query.order_by(User.role, User.name).all()

    internal_q = PassRequest.query.order_by(PassRequest.created_at.desc())
    visitor_q = VisitorRequest.query.order_by(VisitorRequest.created_at.desc())

    if search:
        internal_q = internal_q.filter(
            db.or_(
                PassRequest.requester_name.ilike(f"%{search}%"),
                PassRequest.visitor_name.ilike(f"%{search}%"),
                PassRequest.visitor_national_id.ilike(f"%{search}%"),
                PassRequest.qr_token.ilike(f"%{search}%"),
            )
        )
        visitor_q = visitor_q.filter(
            db.or_(
                VisitorRequest.name.ilike(f"%{search}%"),
                VisitorRequest.national_id.ilike(f"%{search}%"),
                VisitorRequest.qr_token.ilike(f"%{search}%"),
            )
        )

    all_internal = internal_q.limit(50).all()
    all_visitor = visitor_q.limit(50).all()

    today = date.today()
    # ── Analytics: on_campus ─────────────────────────────────────────────────────
    checked_in_count = (
        PassRequest.query.filter_by(status="Checked In").count()
        + VisitorRequest.query.filter_by(status="Checked In").count()
    )
    walkin_today = AuditLog.query.filter(
        AuditLog.scan_type == "WALK-IN",
        db.func.date(AuditLog.scanned_at) == today,
    ).count()
    on_campus = checked_in_count + walkin_today

    # ── Analytics: approved_not_arrived ───────────────────────────────────────────
    approved_not_arrived = (
        PassRequest.query.filter(
            PassRequest.status == "Approved",
            PassRequest.visit_date == today,
        ).count()
        + VisitorRequest.query.filter(
            VisitorRequest.status == "Approved",
            VisitorRequest.visit_date == today,
        ).count()
    )

    # ── Chart data: Pass Requests by Department/Destination ────────────────────────
    dept_counts = {}
    for req in PassRequest.query.all():
        dest = req.destination or "Other"
        dept_counts[dest] = dept_counts.get(dest, 0) + 1
    for req in VisitorRequest.query.all():
        dept = req.department or "Other"
        dept_counts[dept] = dept_counts.get(dept, 0) + 1
    chart_labels = list(dept_counts.keys())
    chart_data = list(dept_counts.values())

    return render_template(
        "admin.html",
        pending_internal=pending_internal,
        pending_visitor=pending_visitor,
        pending_count=pending_count,
        all_internal=all_internal,
        all_visitor=all_visitor,
        recent_audit=recent_audit,
        blacklist=blacklist,
        search=search,
        on_campus=on_campus,
        approved_not_arrived=approved_not_arrived,
        all_users=all_users,
        chart_labels=chart_labels,
        chart_data=chart_data,
    )


@app.route("/requester")
@login_required
def requester_page():
    user = User.query.get(session["user_id"])
    today = date.today()
    all_passes = (
        PassRequest.query.filter_by(requester_id=user.id)
        .order_by(PassRequest.created_at.desc()).all()
    )
    active_passes = [p for p in all_passes if p.status in ("Approved", "Checked In") and p.visit_date >= today]
    pending_passes = [p for p in all_passes if p.status == "Pending"]
    expired_passes = [
        p for p in all_passes
        if p.status in ("Rejected", "Expired", "Checked Out") or (p.status in ("Approved", "Checked In") and p.visit_date < today)
    ]
    qr_map = {p.id: generate_qr_base64(p.qr_token) for p in active_passes if p.qr_token}

    return render_template(
        "requester.html",
        user=user,
        active_passes=active_passes,
        pending_passes=pending_passes,
        expired_passes=expired_passes,
        qr_map=qr_map,
        departments=DEPARTMENTS,
    )


@app.route("/public")
def public_page():
    return render_template("public.html", departments=DEPARTMENTS)


@app.route("/guard")
@role_required("guard")
def guard_page():
    user = User.query.get(session["user_id"])
    return render_template("guard.html", user=user, departments=DEPARTMENTS)


@app.route("/audit")
@role_required("admin")
def audit_page():
    scan_type_filter = request.args.get("scan_type", "").strip()
    result_filter = request.args.get("result", "").strip()
    date_filter = request.args.get("date", "").strip()
    page = request.args.get("page", 1, type=int)

    q = AuditLog.query.order_by(AuditLog.scanned_at.desc())
    if scan_type_filter:
        q = q.filter(AuditLog.scan_type == scan_type_filter)
    if result_filter:
        q = q.filter(AuditLog.result == result_filter)
    if date_filter:
        try:
            fd = datetime.strptime(date_filter, "%Y-%m-%d").date()
            q = q.filter(db.func.date(AuditLog.scanned_at) == fd)
        except ValueError:
            pass

    pagination = q.paginate(page=page, per_page=25, error_out=False)
    return render_template(
        "audit.html",
        logs=pagination.items,
        pagination=pagination,
        scan_type_filter=scan_type_filter,
        result_filter=result_filter,
        date_filter=date_filter,
    )


# ---------------------------------------------------------------------------
# API — Internal pass request
# ---------------------------------------------------------------------------

@app.route("/api/pass/request", methods=["POST"])
@login_required
def api_pass_request():
    """Internal: submit a new gate pass request with visitor pre-registration."""
    data = request.get_json(force=True)
    required = [
        "destination", "visit_date", "time_window", "reason",
        "visitor_name", "visitor_national_id", "visitor_phone",
        "visitor_email",
    ]
    for field in required:
        if not data.get(field):
            return jsonify({"success": False, "message": f"Field '{field}' is required."}), 400

    len_err = _validate_lengths(data)
    if len_err:
        return jsonify({"success": False, "message": len_err}), 400

    try:
        visit_date = datetime.strptime(data["visit_date"], "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"success": False, "message": "Invalid date format. Use YYYY-MM-DD."}), 400

    if visit_date < date.today():
        return jsonify({"success": False, "message": "Visit date cannot be in the past."}), 400

    visitor_national_id = _normalize_national_id(data["visitor_national_id"])
    if _get_blacklist_entry(visitor_national_id):
        return jsonify({
            "success": False,
            "blacklisted": True,
            "message": _BLACKLIST_MSG,
        }), 403

    user = User.query.get(session["user_id"])
    if user.role == "internal":
        requester_type = "Student" if "student" in user.login_id.lower() else "Staff"
    else:
        requester_type = "Admin"

    v_name = data["visitor_name"].strip()
    v_phone = data["visitor_phone"].strip()
    v_email = data["visitor_email"].strip()
    v_vehicle_reg = data.get("visitor_vehicle_reg", "").strip() or None

    pass_req = PassRequest(
        requester_id=user.id,
        requester_name=user.name,
        requester_type=requester_type,
        destination=data["destination"].strip(),
        visit_date=visit_date,
        time_window=data["time_window"].strip(),
        reason=data["reason"].strip(),
        visitor_name=v_name,
        visitor_national_id=visitor_national_id,
        visitor_phone=v_phone,
        visitor_email=v_email,
        visitor_vehicle_reg=v_vehicle_reg,
        status="Pending",
    )
    db.session.add(pass_req)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Pass request submitted. Awaiting admin approval.",
        "request_id": pass_req.id,
    }), 201


# ---------------------------------------------------------------------------
# API — Admin actions
# ---------------------------------------------------------------------------

@app.route("/api/admin/approve", methods=["POST"])
@role_required("admin")
def api_admin_approve():
    data = request.get_json(force=True)
    pass_type = (data.get("pass_type") or "internal").strip().lower()
    if pass_type not in VALID_PASS_TYPES:
        return jsonify({"success": False, "message": "Invalid pass_type."}), 400
    model = PassRequest if pass_type == "internal" else VisitorRequest
    record = model.query.get(data.get("id"))
    if not record:
        return jsonify({"success": False, "message": "Record not found."}), 404

    if _get_blacklist_entry(_pass_record_national_id(record, pass_type)):
        return jsonify({
            "success": False,
            "blacklisted": True,
            "message": _BLACKLIST_MSG,
        }), 403

    token = uuid.uuid4().hex[:32]
    record.status = "Approved"
    record.qr_token = token
    record.comments = data.get("comments", "")
    db.session.commit()

    # ── Email notification on approval ────────────────────────────────────────
    if pass_type == "internal":
        v_email = record.visitor_email
        v_name = record.visitor_name
    else:
        v_email = record.email
        v_name = record.name

    if v_email:
        # Run directly! The Brevo API is fast enough to not freeze the UI.
        send_gatepass_email(v_email, v_name, token, record.visit_date)
        
    return jsonify({"success": True, "qr_token": token, "message": "Pass approved and email sent."})


@app.route("/api/admin/reject", methods=["POST"])
@role_required("admin")
def api_admin_reject():
    data = request.get_json(force=True)
    pass_type = (data.get("pass_type") or "internal").strip().lower()
    if pass_type not in VALID_PASS_TYPES:
        return jsonify({"success": False, "message": "Invalid pass_type."}), 400
    model = PassRequest if pass_type == "internal" else VisitorRequest
    record = model.query.get(data.get("id"))
    if not record:
        return jsonify({"success": False, "message": "Record not found."}), 404

    record.status = "Rejected"
    record.comments = data.get("comments", "")
    db.session.commit()

    return jsonify({"success": True, "message": "Pass rejected."})


@app.route("/api/admin/bulk-approve", methods=["POST"])
@role_required("admin")
def api_bulk_approve():
    data = request.get_json(force=True)
    ids = data.get("ids", [])
    if not isinstance(ids, list):
        return jsonify({"success": False, "message": "ids must be a list."}), 400
    ids = [int(i) for i in ids if isinstance(i, int)][:100]
    pass_type = (data.get("pass_type") or "internal").strip().lower()
    if pass_type not in VALID_PASS_TYPES:
        return jsonify({"success": False, "message": "Invalid pass_type."}), 400
    model = PassRequest if pass_type == "internal" else VisitorRequest
    approved = 0
    skipped_blacklisted = 0
    for pid in ids:
        record = model.query.get(pid)
        if record and record.status == "Pending":
            if _get_blacklist_entry(_pass_record_national_id(record, pass_type)):
                skipped_blacklisted += 1
                continue
            record.status = "Approved"
            record.qr_token = uuid.uuid4().hex[:32]
            approved += 1
    db.session.commit()
    return jsonify({
        "success": True,
        "approved": approved,
        "skipped_blacklisted": skipped_blacklisted,
    })


@app.route("/api/admin/blacklist", methods=["POST"])
@role_required("admin")
def api_blacklist_add():
    data = request.get_json(force=True)
    if not data.get("national_id") or not data.get("name"):
        return jsonify({"success": False, "message": "national_id and name are required."}), 400
    national_id = _normalize_national_id(data["national_id"])
    if _get_blacklist_entry(national_id):
        return jsonify({"success": False, "message": "This ID is already blacklisted."}), 409
    db.session.add(Blacklist(
        national_id=national_id,
        name=data["name"].strip(),
        reason=data.get("reason", "").strip() or None,
    ))
    db.session.commit()
    return jsonify({"success": True, "message": "Individual added to blacklist."})


@app.route("/api/admin/blacklist/<int:entry_id>", methods=["DELETE"])
@role_required("admin")
def api_blacklist_remove(entry_id):
    entry = Blacklist.query.get_or_404(entry_id)
    db.session.delete(entry)
    db.session.commit()
    return jsonify({"success": True, "message": "Removed from blacklist."})


# ---------------------------------------------------------------------------
# API — CSV Export
# ---------------------------------------------------------------------------

@app.route("/api/admin/export/csv", methods=["GET"])
@role_required("admin")
def api_export_csv():
    logs = AuditLog.query.order_by(AuditLog.scanned_at.desc()).all()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Timestamp", "Scan Type", "Token", "Pass Type", "Result", "Notes"])
    for log in logs:
        writer.writerow([
            log.id,
            log.scanned_at.strftime("%Y-%m-%d %H:%M:%S") if log.scanned_at else "",
            log.scan_type,
            log.qr_token,
            log.pass_type,
            log.result,
            log.note or "",
        ])
    from flask import Response
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=gate_activity_export.csv"},
    )


# ---------------------------------------------------------------------------
# API — User Management
# ---------------------------------------------------------------------------

@app.route("/api/admin/users", methods=["POST"])
@role_required("admin")
def api_user_create():
    data = request.get_json(force=True)
    required = ["login_id", "name", "password", "role"]
    for field in required:
        if not data.get(field):
            return jsonify({"success": False, "message": f"Field '{field}' is required."}), 400

    if data["role"] not in ("admin", "guard", "internal"):
        return jsonify({"success": False, "message": "Invalid role."}), 400

    if User.query.filter_by(login_id=data["login_id"].strip()).first():
        return jsonify({"success": False, "message": "Login ID already exists."}), 409

    user = User(
        login_id=data["login_id"].strip(),
        name=data["name"].strip(),
        role=data["role"],
    )
    user.set_password(data["password"].strip())
    db.session.add(user)
    db.session.commit()
    return jsonify({"success": True, "message": "User created successfully."})


@app.route("/api/admin/users/<int:target_id>", methods=["DELETE"])
@role_required("admin")
def api_user_delete(target_id):
    if target_id == session["user_id"]:
        return jsonify({"success": False, "message": "You cannot delete your own account."}), 403
    user = User.query.get_or_404(target_id)
    db.session.delete(user)
    db.session.commit()
    return jsonify({"success": True, "message": "User deleted successfully."})


# ---------------------------------------------------------------------------
# API — Public visitor request
# ---------------------------------------------------------------------------

@app.route("/api/visitor/request", methods=["POST"])
def api_visitor_request():
    data = request.get_json(force=True)
    required = ["name", "national_id", "phone", "email", "visit_date", "department", "purpose"]
    for field in required:
        if not data.get(field):
            return jsonify({"success": False, "message": f"Field '{field}' is required."}), 400

    if _get_blacklist_entry(data["national_id"]):
        return jsonify({
            "success": False,
            "blacklisted": True,
            "message": _BLACKLIST_MSG,
        }), 403

    len_err = _validate_lengths(data)
    if len_err:
        return jsonify({"success": False, "message": len_err}), 400

    try:
        visit_date = datetime.strptime(data["visit_date"], "%Y-%m-%d").date()
    except ValueError:
        return jsonify({"success": False, "message": "Invalid date format."}), 400

    if visit_date < date.today():
        return jsonify({"success": False, "message": "Visit date cannot be in the past."}), 400

    visitor = VisitorRequest(
        name=data["name"].strip(),
        national_id=_normalize_national_id(data["national_id"]),
        phone=data["phone"].strip(),
        email=data["email"].strip(),
        visit_date=visit_date,
        vehicle_reg=data.get("vehicle_reg", "").strip() or None,
        department=data["department"].strip(),
        purpose=data["purpose"].strip(),
        status="Pending",
    )
    db.session.add(visitor)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "Visitor request submitted successfully. You will be contacted upon approval.",
        "request_id": visitor.id,
    }), 201


# ---------------------------------------------------------------------------
# API — Guard QR scan
# ---------------------------------------------------------------------------

@app.route("/api/guard/scan", methods=["POST"])
@role_required("guard")
def api_guard_scan():
    data = request.get_json(force=True)
    token = (data.get("token") or "").strip()
    scan_type = (data.get("scan_type") or "ENTRY").strip().upper()
    if scan_type not in VALID_SCAN_TYPES:
        return jsonify({"success": False, "message": "Invalid scan_type."}), 400

    if not token:
        return jsonify({"success": False, "message": "Token is required."}), 400

    record = PassRequest.query.filter_by(qr_token=token).first()
    pass_type = "internal"
    if not record:
        record = VisitorRequest.query.filter_by(qr_token=token).first()
        pass_type = "visitor"

    def _log(result, note):
        db.session.add(AuditLog(
            scan_type=scan_type,
            guard_id=session.get("user_id"),
            qr_token=token,
            pass_type=pass_type if record else "unknown",
            result=result,
            note=note,
        ))
        db.session.commit()

    if not record:
        _log("INVALID", "Token not found in the system.")
        return jsonify({"success": False, "result": "INVALID", "message": "Token not recognised."}), 404

    if scan_type == "ENTRY":
        bl_entry = _get_blacklist_entry(_pass_record_national_id(record, pass_type))
        if bl_entry:
            visitor_name = record.visitor_name if pass_type == "internal" else record.name
            _log("BLACKLISTED", f"Blacklisted individual denied entry: {visitor_name}.")
            return jsonify({
                "success": False,
                "result": "BLACKLISTED",
                "blacklisted": True,
                "message": f"ACCESS DENIED: {bl_entry.name} is on the security blacklist.",
            }), 403

    # ── State transition logic ───────────────────────────────────────────────────
    if scan_type == "ENTRY":
        if record.status == "Checked In":
            _log("INVALID", "Visitor is already on campus.")
            return jsonify({"success": False, "result": "INVALID", "message": "Visitor is already on campus."}), 403
        if record.status != "Approved":
            _log("INVALID", f"Pass status is '{record.status}', not Approved.")
            return jsonify({
                "success": False, "result": "INVALID",
                "message": f"Pass is {record.status}.",
            }), 403
        record.status = "Checked In"
        db.session.commit()

    elif scan_type == "EXIT":
        if record.status == "Checked Out":
            _log("INVALID", "Visitor already checked out.")
            return jsonify({"success": False, "result": "INVALID", "message": "Visitor already checked out."}), 403
        if record.status != "Checked In":
            _log("INVALID", "Visitor must be Checked In to Exit.")
            return jsonify({
                "success": False, "result": "INVALID",
                "message": "Visitor must be Checked In to Exit.",
            }), 403
        record.status = "Checked Out"
        db.session.commit()

    name = record.requester_name if pass_type == "internal" else record.name
    _log("VALID", f"{scan_type} scan recorded for {name}.")

    if scan_type == "ENTRY":
        success_msg = f"Entry successful \u2014 {name}"
    elif scan_type == "EXIT":
        success_msg = f"Exit successful \u2014 {name}"
    else:
        success_msg = f"Walk-In cleared \u2014 {name}"

    return jsonify({
        "success": True, "result": "VALID",
        "message": success_msg,
        "name": name, "pass_type": pass_type,
    })


# ---------------------------------------------------------------------------
# API — Guard walk-in registry
# ---------------------------------------------------------------------------

@app.route("/api/guard/walkin", methods=["POST"])
@role_required("guard")
def api_guard_walkin():
    data = request.get_json(force=True)
    name = (data.get("name") or "").strip()
    national_id = _normalize_national_id(data.get("national_id") or "")
    if not name or not national_id:
        return jsonify({"success": False, "message": "Name and National ID are required."}), 400

    if _get_blacklist_entry(national_id):
        return jsonify({
            "success": False, "blacklisted": True,
            "message": "ACCESS DENIED: This individual is on the security blacklist.",
        }), 403

    note = f"Walk-in: {name} | {data.get('department', '')} | {data.get('purpose', '')}"
    db.session.add(AuditLog(
        scan_type="WALK-IN",
        guard_id=session.get("user_id"),
        qr_token=f"WALKIN-{uuid.uuid4().hex}",
        pass_type="visitor",
        result="VALID",
        note=note,
    ))
    db.session.commit()
    return jsonify({"success": True, "message": f"Walk-in for {name} cleared and logged."})


# ---------------------------------------------------------------------------
# Security response headers
# ---------------------------------------------------------------------------

@app.after_request
def set_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    return response


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.route("/api/login", methods=["POST"])
def api_login():
    """JSON login endpoint consumed by the auth.html fetch form."""
    data = request.get_json(force=True)
    login_id = (data.get("login_id") or "").strip()
    password = (data.get("password") or "").strip()

    lock_err = _check_rate_limit(login_id)
    if lock_err:
        return jsonify({"success": False, "message": lock_err}), 429

    user = User.query.filter_by(login_id=login_id).first()
    if not user or not user.check_password(password):
        _record_failure(login_id)
        return jsonify({"success": False, "message": "Invalid credentials."}), 401

    _clear_rate_limit(login_id)
    session["user_id"] = user.id
    session["role"] = user.role
    session["user_name"] = user.name
    redirects = {"admin": "/admin", "guard": "/guard"}
    return jsonify({
        "success": True,
        "message": f"Welcome, {user.name}.",
        "redirect": redirects.get(user.role, "/requester"),
    })


@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"success": True})


@app.errorhandler(403)
def forbidden(e):
    return render_template("auth.html"), 403


@app.errorhandler(404)
def not_found(e):
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# DB initialisation & demo seed
# ---------------------------------------------------------------------------

def seed_demo_data():
    if User.query.first():
        return
    users = [
        {"login_id": "admin",     "name": "Mrs. Grace Nwosu",    "role": "admin",    "password": "admin123"},
        {"login_id": "guard01",   "name": "Officer Daniel Kofi", "role": "guard",    "password": "guard123"},
        {"login_id": "student01", "name": "Amina Yusuf",         "role": "internal", "password": "student123"},
        {"login_id": "staff01",   "name": "Dr. Kevin Mensah",    "role": "internal", "password": "staff123"},
    ]
    for u in users:
        user = User(login_id=u["login_id"], name=u["name"], role=u["role"])
        user.set_password(u["password"])
        db.session.add(user)
    db.session.commit()
    logger.info("Demo seed data created.")


# ---------------------------------------------------------------------------
# Context processor — injects stats and helpers into every template
# ---------------------------------------------------------------------------

@app.context_processor
def inject_globals():
    today = date.today()
    stats = {
        "active": PassRequest.query.filter(
            PassRequest.status == "Approved",
            PassRequest.visit_date >= today,
        ).count(),
        "pending": (
            PassRequest.query.filter_by(status="Pending").count()
            + VisitorRequest.query.filter_by(status="Pending").count()
        ),
        "visitors": VisitorRequest.query.count(),
        "audit": AuditLog.query.count(),
    }
    is_authenticated = "user_id" in session
    current_user = User.query.get(session["user_id"]) if is_authenticated else None
    return {
        "stats": stats,
        "now_year": datetime.utcnow().year,
        "is_authenticated": is_authenticated,
        "current_user": current_user,
    }


with app.app_context():
    db.create_all()
    seed_demo_data()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
