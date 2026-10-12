import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY     = os.environ.get("SECRET_KEY", "rba2fa-litu-joseph-201705632-unam-2026")
PORT           = int(os.environ.get("PORT", 3000))
ALLOW_DEBUG_IP = os.environ.get("ALLOW_DEBUG_IP", "true").lower() == "true"

USE_REAL_GEOLOCATION = os.environ.get("USE_REAL_GEOLOCATION", "false").lower() == "true"

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", 587))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_FROM = os.environ.get("SMTP_FROM", SMTP_USER)

TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN  = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM_NUMBER = os.environ.get("TWILIO_FROM_NUMBER", "")

RISK_WEIGHTS = {
    "new_country":          65,
    "new_city":             30,
    "new_device":           25,
    "unusual_time":         10,
    "high_frequency":       20,
    "consecutive_failures": 25,
    "impossible_travel":    40,
}

RISK_TIERS = {
    "LOW":      {"max_score": 29,  "requires": ["password"]},
    "MEDIUM":   {"max_score": 59,  "requires": ["password", "otp_any"]},
    "HIGH":     {"max_score": 84,  "requires": ["password", "totp", "email_otp"]},
    "CRITICAL": {"max_score": 100, "requires": ["blocked"]},
}
FREQUENCY_WINDOW_MINUTES      = 10
FREQUENCY_MAX_ATTEMPTS        = 5
CONSECUTIVE_FAILURE_THRESHOLD = 3
HARD_BLOCK_AFTER_FAILURES     = 5
IMPOSSIBLE_TRAVEL_SPEED_KMH   = 900
OTP_LENGTH_DIGITS              = 6
OTP_EXPIRY_MINUTES             = 5