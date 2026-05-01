import re
import urllib.parse
import joblib
import pandas as pd

# Load trained ML model
model = joblib.load("phishing_model.pkl")


# ---------------- ML Prediction ----------------
def ml_predict(url):

    features = {}

    # Basic URL features
    features["NumDots"] = url.count(".")
    features["NumHyphens"] = url.count("-")
    features["LengthURL"] = len(url)
    features["HasHTTPS"] = 1 if url.startswith("https") else 0

    # Detect IP address
    if re.search(r"\d{1,3}(?:\.\d{1,3}){3}", url):
        features["HasIP"] = 1
    else:
        features["HasIP"] = 0

    df = pd.DataFrame([features])

    prediction = model.predict(df)[0]

    if prediction == 1:
        return "Phishing"
    else:
        return "Legitimate"


# ---------------- Rule Based Detection ----------------
def check_phishing(subject, body, sender=""):

    text = (subject + " " + body).lower()
    score = 0
    reasons = []

    whitelist_domains = [
        "gmail.com", "google.com", "microsoft.com", "outlook.com",
        "paypal.com", "amazon.com", "facebook.com", "netflix.com",
        "linkedin.com"
    ]

    suspicious_exts = [
        ".xyz", ".top", ".tk", ".ga", ".cf", ".ml", ".gq",
        ".cn", ".ru", ".biz", ".info", ".pw"
    ]

    low_weight_keywords = [
        "login", "signin", "account", "update",
        "password", "support", "service", "billing"
    ]

    high_weight_phrases = [
        r"verify (your )?account",
        r"confirm (your )?account",
        r"reset (your )?password",
        r"click (here|the link) to",
        r"urgent (action )?",
        r"suspend(ed|ing)? account",
        r"reactivate (your )?account"
    ]

    # Find URLs
    urls = re.findall(r"(https?://[^\s]+|[A-Za-z0-9.-]+\.[A-Za-z]{2,})", text)

    # High risk phrases
    for pat in high_weight_phrases:
        if re.search(r"\b" + pat + r"\b", text):
            reasons.append(f"⚠️ Suspicious phrase detected: {pat}")
            score += 25

    # Low weight keywords
    found_low = [w for w in low_weight_keywords if re.search(r"\b" + re.escape(w) + r"\b", text)]

    if found_low:
        reasons.append(f"ℹ️ Suspicious words found: {', '.join(found_low)}")
        score += len(found_low) * 5

    # URL inspection
    for u in urls:

        u_lower = u.lower()

        parsed = urllib.parse.urlparse(u_lower if "://" in u_lower else "http://" + u_lower)

        domain = parsed.netloc or parsed.path
        domain = domain.strip("/")

        if any(w in domain for w in whitelist_domains):
            continue

        if any(domain.endswith(ext) for ext in suspicious_exts):
            reasons.append(f"⚠️ Suspicious domain extension: {u}")
            score += 12

        if re.search(r"https?://\d{1,3}(?:\.\d{1,3}){3}", u_lower):
            reasons.append(f"⚠️ URL contains IP address: {u}")
            score += 18

        if re.search(r"(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly)", u_lower):
            reasons.append(f"⚠️ URL shortener detected: {u}")
            score += 15

    if urls:
        reasons.append(f"🔗 Links found: {', '.join(urls[:3])}")
        score += 8

    # Sender mismatch
    if sender:

        sender_lower = sender.lower()

        brands = ["paypal", "amazon", "google", "microsoft", "netflix", "bank"]

        for b in brands:
            if re.search(r"\b" + re.escape(b) + r"\b", text) and b not in sender_lower:
                reasons.append(f"⚠️ Brand '{b}' mentioned but sender domain different")
                score += 18
                break

    # ML prediction if URL exists
    ml_result = None

    if urls:
        ml_result = ml_predict(urls[0])

        reasons.append(f"🤖 ML Model Prediction: {ml_result}")

        if ml_result == "Phishing":
            score += 20

    score = min(score, 100)

    return score, reasons, ml_result


# ---------------- Custom User Input ----------------
if __name__ == "__main__":

    print("====== PHISHGUARD EMAIL SCANNER ======\n")

    subject = input("Enter Email Subject: ")
    body = input("Enter Email Body: ")
    sender = input("Enter Sender Email: ")

    score, reasons, ml_result = check_phishing(subject, body, sender)

    print("\n========== RESULT ==========")

    print("Risk Score:", score)

    if score > 60:
        print("⚠️ This email is likely PHISHING")
    elif score > 30:
        print("⚠️ Suspicious Email")
    else:
        print("✅ Email looks Legitimate")

    if ml_result:
        print("ML Model Prediction:", ml_result)

    print("\nReasons:")

    for r in reasons:
        print("-", r)