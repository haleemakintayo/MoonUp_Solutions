"""
MoonUp Solutions - FastAPI Backend & Admin Management System
Serves website pages, provides REST API endpoints, stores inquiries in SQLite,
dispatches asynchronous emails, and secures the admin dashboard with authentication.
"""

import os
import sqlite3
import smtplib
import secrets
import hashlib
import hmac
import time
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, BackgroundTasks, Request, Query, Form, Depends, status
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, Field
from dotenv import load_dotenv

# Load environment variables from .env file if available
load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "inquiries.db")

# Configuration
SMTP_SERVER = os.getenv("SMTP_SERVER", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
SMTP_USERNAME = os.getenv("SMTP_USERNAME", "").strip()
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "").strip()
NOTIFICATION_RECIPIENT = os.getenv("NOTIFICATION_RECIPIENT", "inquiries@moonupsolutions.com").strip()

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin").strip() or "admin"
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "MoonUpAdmin2026!").strip() or "MoonUpAdmin2026!"
ADMIN_SECRET_KEY = os.getenv("ADMIN_SECRET_KEY", "moonup-secret-key-change-in-production").strip()
SESSION_EXPIRE_HOURS = int(os.getenv("SESSION_EXPIRE_HOURS", 24))


# ==============================================================================
# Cryptographic & Authentication Utilities
# ==============================================================================
def hash_password(password: str, salt: Optional[str] = None) -> str:
    """Hash password using salted PBKDF2-HMAC-SHA256 (100,000 rounds)."""
    if not salt:
        salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
    return f"{salt}:{hashed}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password in constant-time against stored salt:hash."""
    try:
        salt, hashed = stored_hash.split(":", 1)
        check = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100000).hex()
        return secrets.compare_digest(hashed, check)
    except Exception:
        return False


def create_session_token(username: str, expire_hours: int = SESSION_EXPIRE_HOURS) -> str:
    """Generate a tamper-proof HMAC-SHA256 signed session token."""
    expiry = int(time.time()) + (expire_hours * 3600)
    payload = f"{username}:{expiry}"
    sig = hmac.new(ADMIN_SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"


def verify_session_token(token: str) -> Optional[str]:
    """Validate token signature and expiration; returns username if valid."""
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None
        username, expiry_str, sig = parts
        expiry = int(expiry_str)
        if time.time() > expiry:
            return None
        payload = f"{username}:{expiry}"
        expected_sig = hmac.new(ADMIN_SECRET_KEY.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
        if secrets.compare_digest(sig, expected_sig):
            return username
        return None
    except Exception:
        return None


def get_current_admin(request: Request) -> Optional[str]:
    """
    Extract authenticated admin username from:
    1. 'admin_session' HTTP-only cookie
    2. 'Authorization: Bearer <token>' header
    3. 'X-Admin-Key' secret header
    """
    # 1. Cookie check
    token = request.cookies.get("admin_session")
    if token:
        user = verify_session_token(token)
        if user:
            return user

    # 2. Authorization header check
    auth = request.headers.get("Authorization")
    if auth and auth.startswith("Bearer "):
        token = auth.split(" ", 1)[1]
        user = verify_session_token(token)
        if user:
            return user

    # 3. Secret key check
    admin_key = request.headers.get("X-Admin-Key")
    if admin_key and admin_key == ADMIN_SECRET_KEY and ADMIN_SECRET_KEY != "moonup-admin-secret":
        return "api_admin"

    return None


# ==============================================================================
# Database Layer
# ==============================================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        # Inquiries table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS inquiries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                organization TEXT,
                service_needed TEXT NOT NULL,
                message TEXT NOT NULL,
                status TEXT DEFAULT 'new'
            )
        """)
        # Admins table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS admins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()

        # Seed initial admin if none exists
        cursor.execute("SELECT COUNT(*) as count FROM admins")
        if cursor.fetchone()["count"] == 0:
            cursor.execute(
                "INSERT INTO admins (username, hashed_password) VALUES (?, ?)",
                (ADMIN_USERNAME, hash_password(ADMIN_PASSWORD))
            )
            conn.commit()
            print(f"[MoonUp API] Initial administrator created: '{ADMIN_USERNAME}'")

    print(f"[MoonUp API] SQLite database initialized at: {DB_PATH}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield

# Ensure DB is ready on import
init_db()


# ==============================================================================
# FastAPI Application Initialization
# ==============================================================================
app = FastAPI(
    title="MoonUp Solutions API",
    description="FastAPI service for MoonUp Solutions website, inquiries, and admin auth",
    version="1.1.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ==============================================================================
# Pydantic Schemas
# ==============================================================================
class InquiryCreate(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100)
    email: EmailStr
    organization: Optional[str] = Field(default="", max_length=150)
    service_needed: str = Field(..., min_length=2, max_length=100)
    message: str = Field(..., min_length=5, max_length=5000)


class InquiryResponse(BaseModel):
    success: bool
    message: str
    inquiry_id: Optional[int] = None
    created_at: Optional[str] = None


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., pattern="^(new|contacted|archived)$")


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6, max_length=100)


# ==============================================================================
# Background Email Worker
# ==============================================================================
def send_inquiry_email(inquiry_id: int, full_name: str, email: str, organization: str, service: str, message: str):
    if not SMTP_USERNAME or not SMTP_PASSWORD:
        print(f"[MoonUp API] SMTP credentials not set. Inquiry #{inquiry_id} from {full_name} stored in SQLite only.")
        return

    subject = f"[New MoonUp Inquiry #{inquiry_id}] {service} - {full_name}"
    html_content = f"""
    <html>
      <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #111827; max-width: 600px;">
        <div style="background: #071a2e; color: #ffffff; padding: 20px; border-radius: 8px 8px 0 0;">
          <h2 style="margin: 0; color: #38bdf8;">MoonUp Solutions</h2>
          <p style="margin: 5px 0 0; font-size: 14px; color: #cbd5e1;">New Client Consultation Request</p>
        </div>
        <div style="padding: 24px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 8px 8px;">
          <p><strong>Inquiry ID:</strong> #{inquiry_id}</p>
          <p><strong>Name:</strong> {full_name}</p>
          <p><strong>Email:</strong> <a href="mailto:{email}">{email}</a></p>
          <p><strong>Organization:</strong> {organization or 'N/A'}</p>
          <p><strong>Service Requested:</strong> {service}</p>
          <hr style="border: 0; border-top: 1px solid #e2e8f0; margin: 20px 0;">
          <h4>Project Details / Message:</h4>
          <div style="background: #f8fafc; padding: 15px; border-radius: 6px; border: 1px solid #e2e8f0; white-space: pre-wrap;">{message}</div>
          <p style="font-size: 12px; color: #64748b; margin-top: 24px;">Sent automatically by MoonUp Solutions FastAPI Backend.</p>
        </div>
      </body>
    </html>
    """
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = SMTP_USERNAME
        msg["To"] = NOTIFICATION_RECIPIENT
        msg.attach(MIMEText(html_content, "html"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT, timeout=10) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        print(f"[MoonUp API] Email notification sent for Inquiry #{inquiry_id} to {NOTIFICATION_RECIPIENT}")
    except Exception as e:
        print(f"[MoonUp API] Warning: Failed to send email for Inquiry #{inquiry_id}: {e}")


# ==============================================================================
# Public API Endpoints
# ==============================================================================
@app.post("/api/inquiries", response_model=InquiryResponse, status_code=201)
async def submit_inquiry(inquiry: InquiryCreate, background_tasks: BackgroundTasks):
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO inquiries (full_name, email, organization, service_needed, message, status, created_at)
                VALUES (?, ?, ?, ?, ?, 'new', ?)
            """, (
                inquiry.full_name,
                inquiry.email,
                inquiry.organization or "",
                inquiry.service_needed,
                inquiry.message,
                now
            ))
            conn.commit()
            inquiry_id = cursor.lastrowid

        background_tasks.add_task(
            send_inquiry_email,
            inquiry_id=inquiry_id,
            full_name=inquiry.full_name,
            email=inquiry.email,
            organization=inquiry.organization or "",
            service=inquiry.service_needed,
            message=inquiry.message
        )

        return InquiryResponse(
            success=True,
            message="Thank you! Your project inquiry has been received. Our team will review your requirements and respond within 24 business hours.",
            inquiry_id=inquiry_id,
            created_at=now
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "database": os.path.exists(DB_PATH)
    }


# ==============================================================================
# Protected API Endpoints (Admin Required)
# ==============================================================================
@app.get("/api/inquiries")
async def list_inquiries(
    request: Request,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status_filter: Optional[str] = Query(None)
):
    admin_user = get_current_admin(request)
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin authentication required")

    with get_db() as conn:
        cursor = conn.cursor()
        if status_filter:
            cursor.execute("""
                SELECT id, created_at, full_name, email, organization, service_needed, message, status
                FROM inquiries
                WHERE status = ?
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """, (status_filter, limit, offset))
            rows = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) as total FROM inquiries WHERE status = ?", (status_filter,))
        else:
            cursor.execute("""
                SELECT id, created_at, full_name, email, organization, service_needed, message, status
                FROM inquiries
                ORDER BY id DESC
                LIMIT ? OFFSET ?
            """, (limit, offset))
            rows = cursor.fetchall()
            cursor.execute("SELECT COUNT(*) as total FROM inquiries")

        total = cursor.fetchone()["total"]

    return {
        "authenticated_as": admin_user,
        "total": total,
        "limit": limit,
        "offset": offset,
        "inquiries": [dict(r) for r in rows]
    }


@app.post("/api/inquiries/{inquiry_id}/status")
async def update_inquiry_status(inquiry_id: int, req: StatusUpdateRequest, request: Request):
    admin_user = get_current_admin(request)
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin authentication required")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE inquiries SET status = ? WHERE id = ?", (req.status, inquiry_id))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Inquiry not found")

    return {"success": True, "inquiry_id": inquiry_id, "new_status": req.status}


@app.delete("/api/inquiries/{inquiry_id}")
async def delete_inquiry(inquiry_id: int, request: Request):
    admin_user = get_current_admin(request)
    if not admin_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin authentication required")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM inquiries WHERE id = ?", (inquiry_id,))
        conn.commit()
        if cursor.rowcount == 0:
            raise HTTPException(status_code=404, detail="Inquiry not found")

    return {"success": True, "deleted_id": inquiry_id}


@app.post("/api/admin/change-password")
async def change_admin_password(req: ChangePasswordRequest, request: Request):
    admin_user = get_current_admin(request)
    if not admin_user or admin_user == "api_admin":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Admin authentication required")

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM admins WHERE username = ?", (admin_user,))
        row = cursor.fetchone()
        if not row or not verify_password(req.current_password, row["hashed_password"]):
            raise HTTPException(status_code=400, detail="Current password is incorrect")

        new_hash = hash_password(req.new_password)
        cursor.execute("UPDATE admins SET hashed_password = ? WHERE username = ?", (new_hash, admin_user))
        conn.commit()

    return {"success": True, "message": "Password changed successfully"}


# ==============================================================================
# Admin Authentication Web Views (Login, Logout, Dashboard)
# ==============================================================================
@app.get("/admin/login", response_class=HTMLResponse)
async def admin_login_page(request: Request, error: Optional[str] = None, next: Optional[str] = "/admin/inquiries"):
    # If already logged in, redirect directly to dashboard
    if get_current_admin(request):
        return RedirectResponse(url=next or "/admin/inquiries", status_code=status.HTTP_303_SEE_OTHER)

    error_html = ""
    if error:
        error_html = f"""
        <div style="background: #fef2f2; color: #991b1b; border: 1px solid #fecaca; padding: 12px 16px; border-radius: 8px; font-size: 14px; margin-bottom: 20px;">
          <strong>Error:</strong> {error}
        </div>
        """

    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>MoonUp Solutions | Admin Login</title>
    <link rel="stylesheet" href="/style.css">
    <style>
      body {{
        background: linear-gradient(135deg, #050e1a 0%, #0a172a 100%);
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 20px;
        margin: 0;
        font-family: Inter, system-ui, sans-serif;
        color: #f8fafc;
      }}
      .login-box {{
        width: 100%;
        max-width: 420px;
        background: #0d1b2e;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 18px;
        padding: 40px;
        box-shadow: 0 25px 60px rgba(0, 0, 0, 0.5);
      }}
      .login-header {{
        text-align: center;
        margin-bottom: 30px;
      }}
      .login-header h2 {{
        margin: 16px 0 6px;
        font-size: 1.5rem;
        color: #f8fafc;
      }}
      .login-header p {{
        font-size: 0.9rem;
        color: #94a3b8;
        margin: 0;
      }}
      .form-group {{
        margin-bottom: 20px;
      }}
      .form-group label {{
        display: block;
        font-size: 0.85rem;
        font-weight: 700;
        color: #f8fafc;
        margin-bottom: 6px;
      }}
      .form-group input {{
        width: 100%;
        padding: 12px 14px;
        border: 1px solid #1c3350;
        border-radius: 10px;
        background: #091524;
        color: #f8fafc;
        font-size: 0.95rem;
        outline: none;
        box-sizing: border-box;
      }}
      .form-group input:focus {{
        border-color: #38bdf8;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.2);
      }}
      .btn-submit {{
        width: 100%;
        padding: 13px;
        background: #2563eb;
        color: #ffffff;
        border: none;
        border-radius: 10px;
        font-weight: 700;
        font-size: 1rem;
        cursor: pointer;
        transition: 0.2s;
      }}
      .btn-submit:hover {{
        background: #1d4ed8;
      }}
      .login-footer {{
        margin-top: 24px;
        text-align: center;
        font-size: 0.85rem;
      }}
      .login-footer a {{
        color: #94a3b8;
        text-decoration: none;
      }}
      .login-footer a:hover {{
        color: #38bdf8;
      }}
    </style>
  </head>
  <body>
    <div class="login-box">
      <div class="login-header">
        <div style="display: flex; justify-content: center; margin-bottom: 10px;">
          <a class="brand-logo" href="/" aria-label="MoonUp Solutions">
            <span class="brand-mark" aria-hidden="true"></span>
          </a>
        </div>
        <h2>Admin Authentication</h2>
        <p>Sign in to manage client inquiries</p>
      </div>

      {error_html}

      <form action="/admin/login" method="POST">
        <input type="hidden" name="next" value="{next or '/admin/inquiries'}">
        <div class="form-group">
          <label for="username">Administrator Username</label>
          <input type="text" id="username" name="username" placeholder="e.g. admin" required autofocus>
        </div>
        <div class="form-group">
          <label for="password">Password</label>
          <input type="password" id="password" name="password" placeholder="••••••••••••" required>
        </div>
        <button type="submit" class="btn-submit">Sign In to Dashboard</button>
      </form>

      <div class="login-footer">
        <a href="/">&larr; Return to MoonUp Solutions Website</a>
      </div>
    </div>
  </body>
</html>
"""
    return HTMLResponse(content=html)


@app.post("/admin/login")
async def admin_login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next: Optional[str] = Form("/admin/inquiries")
):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hashed_password FROM admins WHERE username = ?", (username.strip(),))
        row = cursor.fetchone()

    if not row or not verify_password(password, row["hashed_password"]):
        return RedirectResponse(
            url=f"/admin/login?error=Invalid%20username%20or%20password&next={next or '/admin/inquiries'}",
            status_code=status.HTTP_303_SEE_OTHER
        )

    # Issue session token
    session_token = create_session_token(username.strip())
    redirect_url = next if (next and next.startswith("/admin")) else "/admin/inquiries"

    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="admin_session",
        value=session_token,
        max_age=SESSION_EXPIRE_HOURS * 3600,
        httponly=True,
        samesite="lax",
        secure=False  # Allow http on localhost; browsers will upgrade automatically on https
    )
    return response


@app.get("/admin/logout")
@app.post("/admin/logout")
async def admin_logout():
    response = RedirectResponse(url="/admin/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(key="admin_session")
    return response


@app.get("/admin/inquiries", response_class=HTMLResponse)
async def admin_inquiries_dashboard(request: Request, filter: Optional[str] = None):
    admin_user = get_current_admin(request)
    if not admin_user:
        return RedirectResponse(url="/admin/login?next=/admin/inquiries", status_code=status.HTTP_303_SEE_OTHER)

    with get_db() as conn:
        cursor = conn.cursor()
        if filter in ["new", "contacted", "archived"]:
            cursor.execute("SELECT * FROM inquiries WHERE status = ? ORDER BY id DESC", (filter,))
        else:
            cursor.execute("SELECT * FROM inquiries ORDER BY id DESC")
        rows = cursor.fetchall()

        cursor.execute("SELECT COUNT(*) as total FROM inquiries")
        total_count = cursor.fetchone()["total"]
        cursor.execute("SELECT COUNT(*) as count FROM inquiries WHERE status = 'new'")
        new_count = cursor.fetchone()["count"]
        cursor.execute("SELECT COUNT(*) as count FROM inquiries WHERE status = 'contacted'")
        contacted_count = cursor.fetchone()["count"]

    table_rows = ""
    for r in rows:
        status_val = r["status"] or "new"
        if status_val == "new":
            badge_style = "background: #e0f2fe; color: #0369a1;"
        elif status_val == "contacted":
            badge_style = "background: #dcfce7; color: #15803d;"
        else:
            badge_style = "background: #f1f5f9; color: #475569;"

        table_rows += f"""
        <tr id="row-{r['id']}">
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); font-weight: bold; color: #f8fafc;">#{r['id']}</td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); font-size: 13px; color: #94a3b8;">{r['created_at']}</td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); font-weight: 600; color: #f8fafc;">{r['full_name']}</td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><a href="mailto:{r['email']}" style="color: #38bdf8; font-weight: 500;">{r['email']}</a></td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); color: #cbd5e1;">{r['organization'] or 'N/A'}</td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08);"><span style="background: #12233a; color: #e2e8f0; border: 1px solid rgba(255, 255, 255, 0.1); padding: 4px 8px; border-radius: 6px; font-size: 12px; font-weight: 600;">{r['service_needed']}</span></td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
            <span id="badge-{r['id']}" style="{badge_style} padding: 4px 8px; border-radius: 999px; font-size: 12px; font-weight: 700; text-transform: uppercase;">{status_val}</span>
          </td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); max-width: 260px; font-size: 13px; white-space: pre-wrap; color: #cbd5e1;">{r['message']}</td>
          <td style="padding: 12px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); white-space: nowrap;">
            <button onclick="updateStatus({r['id']}, 'contacted')" style="background: #10b981; color: white; border: none; padding: 6px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer; margin-right: 4px;">Contacted</button>
            <button onclick="deleteInquiry({r['id']})" style="background: #ef4444; color: white; border: none; padding: 6px 10px; border-radius: 6px; font-size: 12px; font-weight: 600; cursor: pointer;">Delete</button>
          </td>
        </tr>
        """

    if not rows:
        table_rows = """<tr><td colspan="9" style="padding: 40px; text-align: center; color: #94a3b8; font-size: 15px;">No inquiries found matching this view.</td></tr>"""

    html = f"""<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>MoonUp Solutions | Admin Inquiries Dashboard</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <link rel="stylesheet" href="/style.css">
    <style>
      .stat-card {{
        background: #12233a;
        border: 1px solid rgba(255, 255, 255, 0.08);
        border-radius: 12px;
        padding: 18px 24px;
        flex: 1;
        min-width: 160px;
      }}
      .stat-val {{
        font-size: 1.8rem;
        font-weight: 800;
        color: #f8fafc;
        margin-top: 4px;
      }}
      .filter-btn {{
        padding: 6px 14px;
        border-radius: 999px;
        font-size: 13px;
        font-weight: 600;
        text-decoration: none;
        border: 1px solid rgba(255, 255, 255, 0.12);
        color: #94a3b8;
        background: #091524;
      }}
      .filter-btn.active {{
        background: #2563eb;
        color: #fff;
        border-color: #2563eb;
      }}
    </style>
  </head>
  <body style="background: #07111e; color: #f8fafc; padding: 30px 16px; margin: 0; font-family: Inter, system-ui, sans-serif;">
    <div style="max-width: 1240px; margin: 0 auto; background: #0d1b2e; border-radius: 16px; border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 10px 30px rgba(0,0,0,0.4); overflow: hidden;">
      
      <!-- Dashboard Top Bar -->
      <div style="background: #071a2e; color: #ffffff; padding: 22px 30px; display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.08);">
        <div style="display: flex; align-items: center; gap: 16px;">
          <a class="brand-logo" href="/" aria-label="MoonUp Solutions" style="text-decoration: none;">
            <span class="brand-mark" aria-hidden="true"></span>
          </a>
          <div>
            <h2 style="margin: 0; color: #ffffff; font-size: 20px; font-weight: 800;">MoonUp Solutions | Admin Portal</h2>
            <div style="font-size: 13px; color: #94a3b8; margin-top: 2px;">
              Logged in as: <span style="background: rgba(6, 182, 212, 0.2); color: #38bdf8; padding: 2px 8px; border-radius: 4px; font-weight: 700;">{admin_user}</span>
            </div>
          </div>
        </div>
        
        <div style="display: flex; align-items: center; gap: 10px;">
          <a href="/" target="_blank" class="btn sm secondary" style="border-color: rgba(255,255,255,0.2); background: rgba(255,255,255,0.05); color: #fff;">Visit Site &rarr;</a>
          <a href="/admin/logout" class="btn sm" style="background: #dc2626; border-color: #dc2626; color: #fff;">Log Out</a>
        </div>
      </div>

      <!-- Stats Bar -->
      <div style="padding: 24px 30px; border-bottom: 1px solid rgba(255, 255, 255, 0.08); display: flex; gap: 16px; flex-wrap: wrap; background: #0d1b2e;">
        <div class="stat-card">
          <div style="font-size: 13px; font-weight: 600; color: #94a3b8;">Total Inquiries</div>
          <div class="stat-val">{total_count}</div>
        </div>
        <div class="stat-card">
          <div style="font-size: 13px; font-weight: 600; color: #38bdf8;">New Leads</div>
          <div class="stat-val" style="color: #38bdf8;">{new_count}</div>
        </div>
        <div class="stat-card">
          <div style="font-size: 13px; font-weight: 600; color: #34d399;">Contacted</div>
          <div class="stat-val" style="color: #34d399;">{contacted_count}</div>
        </div>
      </div>

      <!-- Filter Controls -->
      <div style="padding: 16px 30px; background: #091524; border-bottom: 1px solid rgba(255, 255, 255, 0.08); display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
        <div style="display: flex; gap: 8px; align-items: center;">
          <span style="font-size: 13px; font-weight: 700; color: #94a3b8; margin-right: 4px;">Filter:</span>
          <a href="/admin/inquiries" class="filter-btn {'active' if not filter else ''}">All ({total_count})</a>
          <a href="/admin/inquiries?filter=new" class="filter-btn {'active' if filter == 'new' else ''}">New ({new_count})</a>
          <a href="/admin/inquiries?filter=contacted" class="filter-btn {'active' if filter == 'contacted' else ''}">Contacted ({contacted_count})</a>
        </div>
        <div style="font-size: 13px; color: #64748b;">
          Database: <code>inquiries.db</code>
        </div>
      </div>

      <!-- Inquiries Table -->
      <div style="overflow-x: auto; padding: 10px 30px 30px;">
        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 14px;">
          <thead>
            <tr style="background: #0d1b2e; color: #f8fafc; border-bottom: 2px solid rgba(255, 255, 255, 0.12);">
              <th style="padding: 14px 10px;">ID</th>
              <th style="padding: 14px 10px;">Received (UTC)</th>
              <th style="padding: 14px 10px;">Client Name</th>
              <th style="padding: 14px 10px;">Email</th>
              <th style="padding: 14px 10px;">Organization</th>
              <th style="padding: 14px 10px;">Service</th>
              <th style="padding: 14px 10px;">Status</th>
              <th style="padding: 14px 10px;">Message</th>
              <th style="padding: 14px 10px;">Actions</th>
            </tr>
          </thead>
          <tbody>
            {table_rows}
          </tbody>
        </table>
      </div>
    </div>

    <script>
      async function updateStatus(id, newStatus) {{
        try {{
          const res = await fetch(`/api/inquiries/${{id}}/status`, {{
            method: 'POST',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{ status: newStatus }})
          }});
          if (res.ok) {{
            const badge = document.getElementById(`badge-${{id}}`);
            if (badge) {{
              badge.textContent = newStatus.toUpperCase();
              badge.style.background = '#dcfce7';
              badge.style.color = '#15803d';
            }}
          }} else {{
            alert('Failed to update status.');
          }}
        }} catch (e) {{
          alert('Network error updating status.');
        }}
      }}

      async function deleteInquiry(id) {{
        if (!confirm(`Are you sure you want to delete Inquiry #${{id}}? This action cannot be undone.`)) return;
        try {{
          const res = await fetch(`/api/inquiries/${{id}}`, {{
            method: 'DELETE'
          }});
          if (res.ok) {{
            const row = document.getElementById(`row-${{id}}`);
            if (row) row.remove();
          }} else {{
            alert('Failed to delete inquiry.');
          }}
        }} catch (e) {{
          alert('Network error deleting inquiry.');
        }}
      }}
    </script>
  </body>
</html>
"""
    return HTMLResponse(content=html)


# ==============================================================================
# Static File & Page Serving Routes
# ==============================================================================
@app.get("/", response_class=FileResponse)
@app.get("/index.html", response_class=FileResponse)
async def serve_home():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))


@app.get("/about", response_class=FileResponse)
@app.get("/about.html", response_class=FileResponse)
async def serve_about():
    return FileResponse(os.path.join(BASE_DIR, "about.html"))


@app.get("/services", response_class=FileResponse)
@app.get("/services.html", response_class=FileResponse)
async def serve_services():
    return FileResponse(os.path.join(BASE_DIR, "services.html"))


@app.get("/contact", response_class=FileResponse)
@app.get("/contact.html", response_class=FileResponse)
async def serve_contact():
    return FileResponse(os.path.join(BASE_DIR, "contact.html"))


@app.get("/style.css")
async def serve_css():
    return FileResponse(os.path.join(BASE_DIR, "style.css"), media_type="text/css")


@app.get("/main.js")
async def serve_js():
    return FileResponse(os.path.join(BASE_DIR, "main.js"), media_type="application/javascript")


# Entrypoint
if __name__ == "__main__":
    import uvicorn
    host = os.getenv("HOST", "127.0.0.1")
    port = int(os.getenv("PORT", 8000))
    print(f"Starting MoonUp Solutions FastAPI server on http://{host}:{port}")
    uvicorn.run("app:app", host=host, port=port, reload=True)
