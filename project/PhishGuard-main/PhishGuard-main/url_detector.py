import re
import joblib
import pandas as pd
import urllib.parse

# Load ML model
model = joblib.load("phishing_model.pkl")


# ---------------- ML Prediction ----------------
def ml_predict(url):

    features = {}

    features["NumDots"] = url.count(".")
    features["NumHyphens"] = url.count("-")
    features["LengthURL"] = len(url)
    features["HasHTTPS"] = 1 if url.startswith("https") else 0

    # IP detection
    features["HasIP"] = 1 if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url) else 0

    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]

    return "Phishing" if prediction == 1 else "Legitimate"


# ---------------- URL Detection ----------------
def check_url(url):

    score = 0
    reasons = []

    url_lower = url.lower()

    parsed = urllib.parse.urlparse(url_lower if "://" in url_lower else "http://" + url_lower)
    domain = parsed.netloc

    # ---------------- Suspicious TLD ----------------
    suspicious_exts = [
        ".xyz", ".top", ".tk", ".ga", ".cf", ".ml", ".gq",
        ".cn", ".ru", ".biz", ".info", ".pw", ".click", ".link"
    ]

    if any(domain.endswith(ext) for ext in suspicious_exts):
        reasons.append("⚠️ Suspicious domain extension")
        score += 20

    # ---------------- Too many dots ----------------
    if url.count(".") > 4:
        reasons.append("⚠️ Too many subdomains (possible spoofing)")
        score += 10

    # ---------------- IP address ----------------
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url):
        reasons.append("⚠️ URL uses IP address")
        score += 25

    # ---------------- @ symbol ----------------
    if "@" in url:
        reasons.append("⚠️ '@' symbol used (hides real domain)")
        score += 20

    # ---------------- URL length ----------------
    if len(url) > 75:
        reasons.append("⚠️ Very long URL")
        score += 10

    # ---------------- Hyphen abuse ----------------
    if url.count("-") > 3:
        reasons.append("⚠️ Too many hyphens in URL")
        score += 10

    # ---------------- HTTPS check ----------------
    if not url.startswith("https"):
        reasons.append("⚠️ Not using HTTPS")
        score += 10

    # ---------------- Shortener ----------------
    if re.search(r"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|rebrand\.ly)", url):
        reasons.append("⚠️ Shortened URL detected")
        score += 20

    # ---------------- Suspicious keywords ----------------
    suspicious_words = [
        "login", "verify", "secure", "account", "update",
        "bank", "confirm", "password", "paypal", "invoice"
    ]

    found_words = [w for w in suspicious_words if w in url_lower]

    if found_words:
        reasons.append(f"⚠️ Suspicious keywords in URL: {', '.join(found_words)}")
        score += len(found_words) * 5

    # ---------------- Brand spoofing ----------------
    legit_brands = ["paypal.com", "amazon.com", "google.com", "facebook.com"]

    for brand in legit_brands:
        if brand.split(".")[0] in url_lower and brand not in domain:
            reasons.append(f"⚠️ Possible brand spoofing: {brand}")
            score += 25
            break

    # ---------------- ML Prediction ----------------
    ml_result = ml_predict(url)
    reasons.append(f"🤖 ML Model Prediction: {ml_result}")

    if ml_result == "Phishing":
        score += 30

    score = min(score, 100)

    return score, reasons, ml_result