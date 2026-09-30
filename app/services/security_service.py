"""Password strength scoring, registration rules and the vault health report."""
import math
import re
from datetime import timedelta

from flask import current_app

from app.models import utcnow
from app.services.encryption import DecryptionError, decrypt

# A short list of the passwords everyone tries first. Not exhaustive - it just stops
# "Password123!" from scoring as strong purely because it has four character classes.
COMMON = {
    "password", "passw0rd", "qwerty", "qwertyuiop", "letmein", "welcome", "admin", "login",
    "iloveyou", "monkey", "dragon", "football", "baseball", "master", "sunshine", "princess",
    "abc123", "trustno1", "shadow", "superman", "michael", "hello", "freedom", "whatever",
}
_LEET = str.maketrans("0134$@5!", "oleastsi")
SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm")


def _has_sequence(pw, run=4):
    low = pw.lower()
    for seq in SEQUENCES:
        for s in (seq, seq[::-1]):
            for i in range(len(s) - run + 1):
                if s[i:i + run] in low:
                    return True
    return False


def label_for(entropy_bits):
    if entropy_bits < 40:
        return "weak"
    if entropy_bits < 60:
        return "medium"
    return "strong"


def evaluate_strength(password):
    """Rough entropy-based estimate. Heuristic, not a guarantee - the JS meter uses the same idea."""
    if not password:
        return {"score": 0, "label": "weak", "entropy": 0.0}
    pool = 0
    pool += 26 if re.search(r"[a-z]", password) else 0
    pool += 26 if re.search(r"[A-Z]", password) else 0
    pool += 10 if re.search(r"\d", password) else 0
    pool += 33 if re.search(r"[^A-Za-z0-9]", password) else 0
    entropy = len(password) * math.log2(pool) if pool else 0.0

    entropy *= 0.4 + 0.6 * (len(set(password)) / len(password))   # repeated characters
    if re.search(r"(.)\1{2,}", password):
        entropy -= 8
    if _has_sequence(password):
        entropy -= 10
    core = re.sub(r"[^a-z]", "", password.lower().translate(_LEET))
    if core in COMMON or any(w in core for w in COMMON if len(w) >= 6):
        entropy = min(entropy, 28)
    entropy = max(entropy, 0.0)
    return {"score": min(100, round(entropy / 80 * 100)), "label": label_for(entropy), "entropy": round(entropy, 1)}


def password_policy_errors(password):
    errors = []
    if len(password) < 12:
        errors.append("at least 12 characters")
    if not re.search(r"[A-Z]", password):
        errors.append("an uppercase letter")
    if not re.search(r"[a-z]", password):
        errors.append("a lowercase letter")
    if not re.search(r"\d", password):
        errors.append("a number")
    if not re.search(r"[^A-Za-z0-9]", password):
        errors.append("a special character")
    return errors


def vault_report(user):
    """Health summary for one user. Decrypts server-side to find reuse; plaintext never leaves this function."""
    items = user.vault_items.all()
    total = len(items)
    counts = {"strong": 0, "medium": 0, "weak": 0}
    for it in items:
        counts[it.strength] = counts.get(it.strength, 0) + 1

    seen = {}
    unreadable = 0
    for it in items:
        try:
            seen.setdefault(decrypt(user, it.encrypted_password), []).append(it)
        except DecryptionError:
            unreadable += 1
    reused = [group for group in seen.values() if len(group) > 1]
    reused_items = [it for group in reused for it in group]

    cutoff = utcnow() - timedelta(days=current_app.config["OLD_PASSWORD_DAYS"])
    old_items = [it for it in items if it.password_changed_at < cutoff]
    weak_items = [it for it in items if it.strength == "weak"]

    if total:
        health = (counts["strong"] + 0.5 * counts["medium"]) / total * 100
        health -= 25 * len(reused_items) / total + 15 * len(old_items) / total
        health = max(0, min(100, round(health)))
    else:
        health = 0

    tips = []
    if counts["weak"]:
        tips.append(f"{counts['weak']} password{'s are' if counts['weak'] != 1 else ' is'} weak. Replace {'them' if counts['weak'] != 1 else 'it'} with generated ones.")
    if reused_items:
        tips.append(f"{len(reused_items)} credentials share a password with another entry. Give each account its own.")
    if old_items:
        tips.append(f"{len(old_items)} password{'s have' if len(old_items) != 1 else ' has'} not been changed in {current_app.config['OLD_PASSWORD_DAYS']}+ days.")
    if unreadable:
        tips.append(f"{unreadable} item(s) could not be decrypted. Check that VAULT_ENCRYPTION_KEY is the one you started with.")
    if total and not tips:
        tips.append("Nothing needs attention right now.")
    if not total:
        tips.append("Your vault is empty. Add a credential to start tracking its health.")

    brief = lambda its: [{"id": i.id, "title": i.title, "username": i.username} for i in its]  # noqa: E731
    return {
        "total": total,
        "strong": counts["strong"],
        "medium": counts["medium"],
        "weak": counts["weak"],
        "reused": len(reused_items),
        "old": len(old_items),
        "health": health,
        "recommendations": tips,
        "weak_items": brief(weak_items),
        "reused_items": brief(reused_items),
        "old_items": brief(old_items),
    }
