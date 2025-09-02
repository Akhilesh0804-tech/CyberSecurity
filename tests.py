# tests.py
from strength import evaluate_password

cases = [
    ("123456", []),
    ("password", []),
    ("iloveyou", []),
    ("Qwerty123", []),
    ("Qwerty123!", []),
    ("Tr0ub4dor&3", []),
    ("LongerPassPhraseWithMix123!", []),
    ("AKHILESH_2025", ["akhilesh"]),
    ("v3ry$tr0ng_P@ssw0rd!!", []),
]

for pw, user_inputs in cases:
    r = evaluate_password(pw, user_inputs=user_inputs)
    print(f"{pw:30} -> {r['label']:12} {r['score']:3}/100  ({r['entropy_bits']} bits)")
