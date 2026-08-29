"""services/geo_service.py — IP geolocation (Risk Indicators 1, 2 & 7)."""

import math
import requests
from flask import request
import config

DEMO_GEO_DB = {
    "8.8.8.8":      {"country":"United States", "region":"California",    "city":"Mountain View", "lat":37.3860,  "lon":-122.0838,"isp":"Google LLC",      "timezone":"America/Los_Angeles"},
    "1.1.1.1":      {"country":"Australia",     "region":"New South Wales","city":"Sydney",        "lat":-33.8688,"lon":151.2093, "isp":"Cloudflare",      "timezone":"Australia/Sydney"},
    "41.182.0.1":   {"country":"Namibia",       "region":"Khomas",         "city":"Windhoek",      "lat":-22.5594,"lon":17.0832,  "isp":"Telecom Namibia", "timezone":"Africa/Windhoek"},
    "41.182.0.2":   {"country":"Namibia",       "region":"Erongo",         "city":"Swakopmund",    "lat":-22.6784,"lon":14.5266,  "isp":"Telecom Namibia", "timezone":"Africa/Windhoek"},
    "41.182.0.3":   {"country":"Namibia",       "region":"Erongo",         "city":"Walvis Bay",    "lat":-22.9576,"lon":14.5052,  "isp":"MTC Namibia",     "timezone":"Africa/Windhoek"},
    "41.182.0.4":   {"country":"Namibia",       "region":"Oshana",         "city":"Oshakati",      "lat":-17.7833,"lon":15.7000,  "isp":"Telecom Namibia", "timezone":"Africa/Windhoek"},
    "41.182.0.5":   {"country":"Namibia",       "region":"Kavango East",   "city":"Rundu",         "lat":-17.9167,"lon":19.7667,  "isp":"Telecom Namibia", "timezone":"Africa/Windhoek"},
    "41.182.0.6":   {"country":"Namibia",       "region":"Zambezi",        "city":"Katima Mulilo", "lat":-17.5000,"lon":24.2667,  "isp":"Telecom Namibia", "timezone":"Africa/Windhoek"},
    "196.216.2.1":  {"country":"South Africa",  "region":"Gauteng",        "city":"Johannesburg",  "lat":-26.2041,"lon":28.0473,  "isp":"Africom",         "timezone":"Africa/Johannesburg"},
    "196.216.2.2":  {"country":"South Africa",  "region":"Western Cape",   "city":"Cape Town",     "lat":-33.9249,"lon":18.4241,  "isp":"Africom",         "timezone":"Africa/Johannesburg"},
    "203.0.113.5":  {"country":"Japan",         "region":"Tokyo",          "city":"Tokyo",         "lat":35.6762, "lon":139.6503, "isp":"NTT",             "timezone":"Asia/Tokyo"},
    "198.51.100.7": {"country":"United Kingdom","region":"England",        "city":"London",         "lat":51.5074, "lon":-0.1278,  "isp":"BT",              "timezone":"Europe/London"},
    "192.0.2.9":    {"country":"Brazil",        "region":"Sao Paulo",      "city":"Sao Paulo",     "lat":-23.5505,"lon":-46.6333, "isp":"Vivo",            "timezone":"America/Sao_Paulo"},
    "41.63.64.1":   {"country":"Kenya",         "region":"Nairobi Area",   "city":"Nairobi",       "lat":-1.2921, "lon":36.8219,  "isp":"Safaricom",       "timezone":"Africa/Nairobi"},
    "105.112.0.1":  {"country":"Nigeria",       "region":"Lagos",          "city":"Lagos",         "lat":6.5244,  "lon":3.3792,   "isp":"MTN Nigeria",     "timezone":"Africa/Lagos"},
}

def resolve_client_ip():
    if config.ALLOW_DEBUG_IP:
        debug_ip = request.args.get("debug_ip") or request.headers.get("X-Debug-IP")
        if debug_ip:
            return debug_ip
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "127.0.0.1"

def lookup_geo(ip_address):
    if _is_private_ip(ip_address):
        return {"ip":ip_address,"country":None,"region":None,"city":"Local Network","lat":None,"lon":None,"isp":"Private Network","timezone":None}
    if config.USE_REAL_GEOLOCATION:
        result = _lookup_real(ip_address)
        if result:
            return result
    demo = DEMO_GEO_DB.get(ip_address)
    if demo:
        return {"ip":ip_address, **demo}
    return {"ip":ip_address,"country":None,"region":None,"city":"Unknown","lat":None,"lon":None,"isp":None,"timezone":None}

def _lookup_real(ip_address):
    try:
        url  = f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,lat,lon,isp,timezone,query"
        data = requests.get(url, timeout=4).json()
        if data.get("status") == "success":
            return {"ip":data.get("query",ip_address),"country":data.get("country"),"region":data.get("regionName"),"city":data.get("city"),"lat":data.get("lat"),"lon":data.get("lon"),"isp":data.get("isp"),"timezone":data.get("timezone")}
    except Exception:
        pass
    return None

def _is_private_ip(ip):
    if not ip: return True
    if ip in ("::1","localhost"): return True
    for prefix in ("127.","10.","192.168.","::ffff:10.","::ffff:192.168."):
        if ip.startswith(prefix): return True
    try:
        parts = ip.split(".")
        if len(parts) == 4 and parts[0] == "172" and 16 <= int(parts[1]) <= 31:
            return True
    except Exception:
        pass
    return False

def haversine_distance_km(lat1, lon1, lat2, lon2):
    R = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = math.sin(dlat/2)**2 + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))