
import re

# Basic lists of suspicious indicators
RISKY_KEYWORDS = ["urgent", "verify", "password", "account", "login", "reset", "suspend", "gift card", "payment", "invoice"]
URGENCY_PHRASES = ["act now", "immediately", "within 24 hours", "final notice", "last warning", "respond immediately"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl"]
EXECUTABLE_EXTS = [".exe", ".bat", ".cmd", ".scr", ".js"]

def extract_urls(text):
    return re.findall(r'https?://\S+', text)

def find_attachments(text):
    return re.findall(r'attachment:\s*([^\s]+)', text.lower())

def risk_label(score):
    if score >= 50:
        return "HIGH"
    elif score >= 20:
        return "MEDIUM"
    return "LOW"

def color(text, level):
    colors = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m", "RESET": "\033[0m"}
    return f"{colors[level]}{text}{colors['RESET']}"

def score_email(subject, body):
    text = (subject + " " + body).lower()
    score = 0
    reasons = []

    # Check keywords
    for word in RISKY_KEYWORDS:
        if word in text:
            score += 8
            reasons.append(f"Keyword: {word}")

    # Check urgency
    for phrase in URGENCY_PHRASES:
        if phrase in text:
            score += 12
            reasons.append(f"Urgency: {phrase}")

    # Check URLs
    urls = extract_urls(text)
    if urls:
        reasons.append(f"Found {len(urls)} link(s)")
        for url in urls:
            if any(s in url for s in URL_SHORTENERS):
                score += 18
                reasons.append(f"Shortened URL: {url}")

    # Check attachments
    attachments = find_attachments(text)
    if attachments:
        reasons.append(f"Attachment(s): {', '.join(attachments)}")
        for att in attachments:
            if any(att.endswith(ext) for ext in EXECUTABLE_EXTS):
                score += 20
                reasons.append(f"Executable attachment: {att}")

    score = min(score, 100)
    return score, risk_label(score), reasons, urls, attachments

def main():
    print("=== Phishing Email Detector ===")
    subject = input("Subject: ").strip()
    body = input("Body: ").strip()

    score, label, reasons, urls, attachments = score_email(subject, body)
    print("\n--- Analysis ---")
    print(f"Risk Score: {score} ({color(label, label)})")

    print("Reasons:")
    if reasons:
        for r in reasons:
            print(f"- {r}")
    else:
        print("- No obvious phishing signals found.")

    if urls:
        print("Links:")
        for u in urls:
            print(f"- {u}")

    if attachments:
        print("Attachments:")
        for a in attachments:
            print(f"- {a}")

if __name__ == "__main__":
    main()