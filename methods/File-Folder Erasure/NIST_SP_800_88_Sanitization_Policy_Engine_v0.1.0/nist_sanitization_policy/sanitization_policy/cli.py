from __future__ import annotations
import argparse
import json
import sys
from .models import SanitizationRequest
from .policy import evaluate


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Non-destructive NIST SP 800-88 Rev. 2 sanitization policy evaluator")
    parser.add_argument("request", help="JSON request file")
    parser.add_argument("--pretty", action="store_true", help="Pretty-print JSON")
    args = parser.parse_args(argv)

    try:
        with open(args.request, "r", encoding="utf-8") as f:
            data = json.load(f)
        decision = evaluate(SanitizationRequest.from_dict(data))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(decision.to_dict(), indent=2 if args.pretty else None, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
