"""services/otp_service.py — TOTP, Email OTP, SMS OTP."""

import os
import base64
import hashlib
import secrets
import smtplib
from datetime import datetime, timedelta, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from io import BytesIO

import pyotp
import qrcode
import config


# ---- TOTP ----

def generate_totp_secret():
    return pyotp.random_base32()

def totp_provisioning_uri(secret, username):
    return pyotp.TOTP(secret).provisioning_uri(
        name=username, issuer_name="RBA-2FA System"
    )

def totp_uri_to_qr_data_url(uri):
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + \
           base64.b64encode(buf.getvalue()).decode()

def verify_totp(secret, code):
    if not code:
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


# ---- Shared helpers ----

def _generate_otp():
    return str(
        secrets.randbelow(10 ** config.OTP_LENGTH_DIGITS)
    ).zfill(config.OTP_LENGTH_DIGITS)

def _hash(code):
    return hashlib.sha256(code.encode()).hexdigest()

def _expiry():
    return (
        datetime.now(timezone.utc) +
        timedelta(minutes=config.OTP_EXPIRY_MINUTES)
    ).isoformat()

def _expired(ts):
    return not ts or \
           datetime.fromisoformat(ts) < datetime.now(timezone.utc)

def verify_hashed_otp(submitted, stored_hash, expiry):
    if not submitted or not stored_hash or _expired(expiry):
        return False
    return _hash(submitted) == stored_hash


# ---- Email sending ----

def _send_email(to, subject, html_content, plain_content):
    """
    Tries Resend API first — works everywhere including PythonAnywhere.
    Falls back to Mailgun API.
    Falls back to Gmail SMTP for local development.
    """

    # Method 1 — Resend API (best — works everywhere)
    resend_key = getattr(config, "RESEND_API_KEY", "") or \
                 os.environ.get("RESEND_API_KEY", "")

    if resend_key:
        try:
            import requests as _req
            response = _req.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": f"Bearer {resend_key}",
                    "Content-Type":  "application/json",
                },
                json={
                    "from":    "RBA-2FA System <onboarding@resend.dev>",
                    "to":      [to],
                    "subject": subject,
                    "text":    plain_content,
                    "html":    html_content,
                }
            )
            if response.status_code in (200, 201, 202):
                print(
                    f"[EMAIL SENT via Resend] "
                    f"Status {response.status_code} → {to}"
                )
                return
            else:
                print(
                    f"[RESEND ERROR] "
                    f"Status {response.status_code}: {response.text}"
                )
        except Exception as e:
            print(f"[RESEND EXCEPTION] {e}")

    # Method 2 — Mailgun API
    mailgun_key    = getattr(config, "MAILGUN_API_KEY", "")
    mailgun_domain = getattr(config, "MAILGUN_DOMAIN", "")

    if mailgun_key and mailgun_domain:
        try:
            import requests as _req
            response = _req.post(
                f"https://api.mailgun.net/v3/{mailgun_domain}/messages",
                auth=("api", mailgun_key),
                data={
                    "from":    getattr(config, "MAILGUN_FROM", "")
                               or f"RBA-2FA <postmaster@{mailgun_domain}>",
                    "to":      [to],
                    "subject": subject,
                    "text":    plain_content,
                    "html":    html_content,
                }
            )
            if response.status_code in (200, 201, 202):
                print(
                    f"[EMAIL SENT via Mailgun] "
                    f"Status {response.status_code} → {to}"
                )
                return
            else:
                print(
                    f"[MAILGUN ERROR] "
                    f"Status {response.status_code}: {response.text}"
                )
        except Exception as e:
            print(f"[MAILGUN EXCEPTION] {e}")

    # Method 3 — Gmail SMTP port 587
    if config.SMTP_USER and config.SMTP_PASS:
        try:
            mime = MIMEMultipart("alternative")
            mime["Subject"] = subject
            mime["From"]    = config.SMTP_FROM
            mime["To"]      = to
            mime.attach(MIMEText(plain_content, "plain"))
            mime.attach(MIMEText(html_content,  "html"))
            with smtplib.SMTP(config.SMTP_HOST, 587) as s:
                s.ehlo()
                s.starttls()
                s.login(config.SMTP_USER, config.SMTP_PASS)
                s.sendmail(config.SMTP_FROM, to, mime.as_string())
                print(f"[EMAIL SENT via Gmail SMTP] → {to}")
            return
        except Exception as e:
            print(f"[GMAIL SMTP ERROR] {e}")

    raise Exception("All email methods failed")


# ---- Email OTP ----

def send_email_otp(email):
    code = _generate_otp()

    subject = f"Your Login Verification Code — {code}"
    plain   = (
        f"Your RBA-2FA verification code is: {code}\n"
        f"Expires in {config.OTP_EXPIRY_MINUTES} minutes.\n"
        f"Do not share this code with anyone."
    )
    html = f"""<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f4f6fb;
             font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0">
<tr><td align="center" style="padding:40px 0;">
<table width="520"
       style="background:#fff;border-radius:16px;
              box-shadow:0 4px 24px rgba(0,0,0,0.08);">

  <tr><td style="background:linear-gradient(135deg,#1a3c8f,#2f5df0);
                 padding:32px 40px;
                 border-radius:16px 16px 0 0;
                 text-align:center;">
    <h1 style="margin:0;color:#fff;font-size:22px;">
      🔐 RBA-2FA Security System
    </h1>
    <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">
      Login Verification Code
    </p>
  </td></tr>

  <tr><td style="padding:40px;">
    <p style="color:#374151;font-size:15px;margin-bottom:8px;">Hello,</p>
    <p style="color:#6b7386;font-size:14px;line-height:1.6;">
      A login attempt was detected on your account.
      Use the code below to complete your verification.
    </p>
    <div style="text-align:center;margin:28px 0;">
      <span style="display:inline-block;
                   background:#f0f4ff;
                   border:2px solid #2f5df0;
                   border-radius:12px;
                   padding:18px 40px;
                   font-size:38px;
                   font-weight:800;
                   letter-spacing:10px;
                   color:#1a3c8f;">
        {code}
      </span>
    </div>
    <p style="color:#6b7386;font-size:13px;text-align:center;">
      ⏱ This code expires in
      <strong>{config.OTP_EXPIRY_MINUTES} minutes</strong>
    </p>
    <div style="background:#fff8e1;border:1px solid #ffd54f;
                border-radius:10px;padding:14px 18px;margin-top:20px;">
      <p style="margin:0;color:#856404;font-size:13px;">
        🔒 Never share this code with anyone.
      </p>
    </div>
    <hr style="border:none;border-top:1px solid #eef0f5;margin:28px 0;">
    <p style="color:#9aa3b5;font-size:12px;text-align:center;">
      If you did not attempt to log in please ignore this email.
    </p>
  </td></tr>

  <tr><td style="background:#f8f9fc;padding:20px;
                 border-radius:0 0 16px 16px;
                 text-align:center;">
    <p style="margin:0;color:#c0c5d0;font-size:11px;">
      RBA-2FA System — UNAM Undergraduate Research Project 2026
    </p>
  </td></tr>

</table></td></tr></table>
</body></html>"""

    try:
        _send_email(email, subject, html, plain)
    except Exception as e:
        print(f"[EMAIL FAILED] {e}")
        print(f"[CONSOLE OTP] Email OTP for {email}: {code}")

    return code, _hash(code), _expiry()


# ---- SMS OTP ----

def send_sms_otp(phone):
    code = _generate_otp()
    if config.TWILIO_ACCOUNT_SID and \
       config.TWILIO_AUTH_TOKEN and phone:
        try:
            from twilio.rest import Client
            Client(
                config.TWILIO_ACCOUNT_SID,
                config.TWILIO_AUTH_TOKEN
            ).messages.create(
                body=(
                    f"RBA-2FA Code: {code}\n"
                    f"Expires in {config.OTP_EXPIRY_MINUTES} min. "
                    f"Do not share."
                ),
                from_=config.TWILIO_FROM_NUMBER,
                to=phone
            )
            print(f"[SMS SENT] OTP delivered to {phone}")
        except Exception as e:
            print(f"[SMS ERROR] {e}")
            print(f"[CONSOLE OTP] SMS OTP for {phone}: {code}")
    else:
        print(f"[MOCK SMS] OTP for {phone or '(no phone)'}: {code}")

    return code, _hash(code), _expiry()