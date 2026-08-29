"""services/device_service.py — Device fingerprinting (Risk Indicator 3)."""
import hashlib
from flask import request

def compute_device_hash():
    ua   = request.headers.get("User-Agent", "unknown")
    lang = request.headers.get("Accept-Language", "unknown")
    return hashlib.sha256(f"{ua}::{lang}".encode()).hexdigest()