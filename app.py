from flask import Flask, request, jsonify
from flask_cors import CORS
import re

app = Flask(__name__)
CORS(app)  # Allow frontend to talk to backend

# ── Simple rule-based spam detector ──────────────────────────────────────────
SPAM_KEYWORDS = [
    "win", "winner", "free", "prize", "claim", "urgent", "act now",
    "limited time", "click here", "buy now", "100%", "guaranteed",
    "no risk", "congratulations", "you have been selected",
    "nigerian prince", "lottery", "bitcoin", "crypto offer",
    "verify your account", "suspended", "password", "bank account",
    "wire transfer", "make money", "work from home", "earn cash",
    "double your", "million dollars", "inheritance", "unclaimed",
    "dear friend", "beloved", "undisclosed", "cheap", "discount",
    "enlargement", "pharmacy", "pills", "medication", "weight loss",
    "casino", "poker", "gambling", "unsubscribe", "opt-out",
]

SPAM_PATTERNS = [
    r'\b\d+\s*%\s*(off|discount|free)\b',   # "50% off"
    r'\$\d+[\d,]*',                           # dollar amounts
    r'https?://\S+',                          # URLs (suspicious in plain email)
    r'[A-Z]{5,}',                             # EXCESSIVE CAPS
    r'!{2,}',                                 # Multiple !!!
    r'\b(click|tap)\s+here\b',
    r'(earn|make)\s+\$',
    r'no\s+credit\s+card',
    r'risk[\s-]*free',
]

def analyze_email(subject: str, body: str) -> dict:
    text = (subject + " " + body).lower()
    full_text = subject + " " + body  # for case-sensitive patterns

    hits = []
    score = 0

    # Keyword check
    for kw in SPAM_KEYWORDS:
        if kw in text:
            hits.append(f'Spam keyword: "{kw}"')
            score += 10

    # Pattern check
    for pat in SPAM_PATTERNS:
        matches = re.findall(pat, full_text, re.IGNORECASE)
        if matches:
            hits.append(f'Pattern matched: {pat}  →  {matches[:2]}')
            score += 8

    # Extra signals
    if subject.isupper() and len(subject) > 5:
        hits.append("Subject is ALL CAPS")
        score += 15

    exclamation_count = full_text.count("!")
    if exclamation_count >= 3:
        hits.append(f"Excessive exclamation marks: {exclamation_count}")
        score += exclamation_count * 3

    if len(body) > 0 and len(re.findall(r'[A-Z]', body)) / len(body) > 0.4:
        hits.append("High proportion of capital letters in body")
        score += 10

    # Verdict
    score = min(score, 100)
    if score >= 60:
        verdict = "SPAM"
        confidence = "High" if score >= 80 else "Medium"
    elif score >= 30:
        verdict = "SUSPICIOUS"
        confidence = "Medium"
    else:
        verdict = "LEGITIMATE"
        confidence = "High" if score < 15 else "Medium"

    return {
        "verdict": verdict,
        "score": score,
        "confidence": confidence,
        "reasons": hits[:8],   # top 8 reasons
        "keyword_hits": sum(1 for h in hits if "keyword" in h.lower()),
        "pattern_hits": sum(1 for h in hits if "pattern" in h.lower()),
    }


@app.route("/api/check", methods=["POST"])
def check_email():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON body sent"}), 400

    subject = data.get("subject", "").strip()
    body    = data.get("body", "").strip()

    if not subject and not body:
        return jsonify({"error": "Please provide a subject or body"}), 400

    result = analyze_email(subject, body)
    return jsonify(result)


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "message": "Spam Detector API is running"})


if __name__ == "__main__":
    print("🚀  Spam Detector API running on http://localhost:5000")
    app.run(debug=True, port=5000)