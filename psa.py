# psa.py
import argparse
import json
from strength import evaluate_password

def main():
    parser = argparse.ArgumentParser(description="Password Strength Analyzer")
    parser.add_argument("password", help="Password to evaluate (wrap in quotes).")
    parser.add_argument("--user", help="Username or your name (optional).")
    parser.add_argument("--email", help="Email (optional).")
    parser.add_argument("--json", action="store_true", help="Output JSON.")
    args = parser.parse_args()

    user_inputs = [args.user, args.email]
    result = evaluate_password(args.password, user_inputs=user_inputs)

    if args.json:
        print(json.dumps(result, indent=2))
        return

    print("\n=== Password Strength Report ===")
    print(f"Label : {result['label']}")
    print(f"Score : {result['score']} / 100")
    print(f"Entropy (approx): {result['entropy_bits']} bits")

    if result['warnings']:
        print("\nWarnings:")
        for w in result['warnings']:
            print(f" - {w}")

    if result['suggestions']:
        print("\nSuggestions:")
        for s in result['suggestions']:
            print(f" - {s}")

    print("\nDetails:")
    d = result["details"]
    print(f" - Length: {d['length']}")
    print(f" - Variety flags: {d['classes']}")
    print(f" - Length points: {d['length_points']}")
    print(f" - Variety points: {d['variety_points']}")
    print("================================\n")

if __name__ == "__main__":
    main()
