# strength.py
import math
import re
from pathlib import Path

COMMON_PATH = Path(__file__).with_name("common_passwords.txt")

# Preload a small common-password list
def load_common_passwords():
    if COMMON_PATH.exists():
        with COMMON_PATH.open("r", encoding="utf-8") as f:
            return set(p.strip().lower() for p in f if p.strip())
    return set()

COMMON = load_common_passwords()

SEQUENCES = [
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiopasdfghjklzxcvbnm",  # keyboard-ish
    "0123456789"
]

def contains_user_info(pw: str, user_inputs):
    if not user_inputs:
        return False
    pw_lower = pw.lower()
    for raw in user_inputs:
        if not raw:
            continue
        for token in re.split(r"[^\w]+", str(raw).lower()):
            if token and len(token) >= 3 and token in pw_lower:
                return True
    return False

def has_seq(pw: str, min_len=3):
    p = pw.lower()
    for seq in SEQUENCES:
        # forward
        for i in range(len(seq) - min_len + 1):
            chunk = seq[i:i+min_len]
            if chunk in p:
                return True
        # reverse
        rev = seq[::-1]
        for i in range(len(rev) - min_len + 1):
            chunk = rev[i:i+min_len]
            if chunk in p:
                return True
    return False

def has_repeated_runs(pw: str, run_len=3):
    return re.search(r"(.)\1{" + str(run_len - 1) + r",}", pw) is not None

def char_variety(pw: str):
    lowers = bool(re.search(r"[a-z]", pw))
    uppers = bool(re.search(r"[A-Z]", pw))
    digits = bool(re.search(r"\d", pw))
    symbols = bool(re.search(r"[^\w\s]", pw))
    classes = sum([lowers, uppers, digits, symbols])
    return classes, {"lower": lowers, "upper": uppers, "digit": digits, "symbol": symbols}

def approx_entropy_bits(pw: str):
    # Very rough estimate: choose character space based on classes
    classes, _ = char_variety(pw)
    if classes == 0:
        space = 1
    elif classes == 1:
        # Pick a typical space size; refine if you like
        if re.fullmatch(r"[a-z]+", pw.lower()): space = 26
        elif re.fullmatch(r"\d+", pw): space = 10
        else: space = 32
    elif classes == 2:
        space = 52  # e.g., lower+upper OR letters+digits
    elif classes == 3:
        space = 62  # letters+digits+one more
    else:
        space = 90  # letters+digits+symbols (rough)
    return len(pw) * math.log2(space)

def evaluate_password(pw: str, user_inputs=None):
    """
    Returns:
      {
        "score": int 0..100,
        "label": str,
        "entropy_bits": float,
        "warnings": [str],
        "suggestions": [str],
        "details": {...}   # breakdown for debugging/learning
      }
    """
    user_inputs = user_inputs or []
    warnings = []
    suggestions = []

    length = len(pw)
    score = 0

    # Length points
    if length < 8:
        length_points = 0
        warnings.append("Password is shorter than 8 characters.")
        suggestions.append("Use at least 12–16 characters.")
    elif 8 <= length <= 11:
        length_points = 10
        suggestions.append("Longer is stronger; aim for 12–16+ characters.")
    elif 12 <= length <= 15:
        length_points = 20
    else:
        length_points = 30
    score += length_points

    # Variety points
    classes, flags = char_variety(pw)
    variety_points = classes * 5  # up to 20
    if classes <= 2:
        suggestions.append("Mix uppercase, lowercase, digits, and symbols.")
    score += variety_points

    # Bonus for good length + variety
    if length >= 10 and classes >= 3:
        score += 5

    # Penalties: common passwords/dictionary-ish
    pw_lower = pw.lower()
    if pw_lower in COMMON:
        score -= 30
        warnings.append("Appears in a common password list.")
        suggestions.append("Avoid common passwords and their simple variations.")

    # Penalize if user info is present
    if contains_user_info(pw, user_inputs):
        score -= 20
        warnings.append("Contains your personal info (name/email/username).")
        suggestions.append("Avoid including names, emails, or birthdays.")

    # Penalize sequences and repeated runs
    if has_seq(pw):
        score -= 20
        warnings.append("Contains sequential patterns (e.g., abc, 123, qwerty).")
        suggestions.append("Avoid sequences or keyboard patterns.")

    if has_repeated_runs(pw, run_len=3):
        score -= 10
        warnings.append("Contains repeated characters.")
        suggestions.append("Avoid repeating the same character many times.")

    # Slight penalty for only alphabetic or only digits
    if re.fullmatch(r"[A-Za-z]+", pw):
        score -= 10
        warnings.append("Only letters detected.")
        suggestions.append("Add digits and symbols.")
    if re.fullmatch(r"\d+", pw):
        score -= 15
        warnings.append("Only digits detected.")
        suggestions.append("Add letters and symbols.")

    # Cap score between 0 and 100
    score = max(0, min(100, score))

    # Map to labels
    if score <= 20:
        label = "Very Weak"
    elif score <= 40:
        label = "Weak"
    elif score <= 60:
        label = "Fair"
    elif score <= 80:
        label = "Strong"
    else:
        label = "Very Strong"

    # Entropy (rough)
    entropy_bits = round(approx_entropy_bits(pw), 1)

    # Improve suggestion quality (dedupe + sort)
    def uniq(xs): 
        seen = set(); out = []
        for x in xs:
            if x not in seen:
                out.append(x); seen.add(x)
        return out

    return {
        "score": score,
        "label": label,
        "entropy_bits": entropy_bits,
        "warnings": uniq(warnings),
        "suggestions": uniq(suggestions),
        "details": {
            "length_points": length_points,
            "variety_points": variety_points,
            "length": length,
            "classes": flags
        }
    }
