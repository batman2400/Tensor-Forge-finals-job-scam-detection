"""Train the detector(s), evaluate on held-out test and shifted sets, and save the chosen model.

Usage: python scripts/train.py [--kind embed|tfidf] [--compare]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scamshield import config  # noqa: E402
from scamshield.training import evaluate_all, save_report, train  # noqa: E402


def fmt(m: dict | None) -> str:
    if not m:
        return "n/a"
    return (f"n={m['n']} acc={m['accuracy']:.3f} P={m['precision']:.3f} R={m['recall']:.3f} "
            f"F1={m['f1']:.3f} conf={m['mean_confidence']:.2f} unfamiliar={m['unfamiliar_rate']:.0%}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kind", default=config.MODEL_KIND, choices=["embed", "tfidf"])
    parser.add_argument("--compare", action="store_true", help="also train and report the other model kind")
    args = parser.parse_args()

    kinds = ["tfidf", "embed"] if args.compare else [args.kind]
    reports = {}
    for kind in kinds:
        print(f"== training {kind}")
        detector = train(kind=kind)
        report = evaluate_all(detector)
        reports[kind] = report
        print(f"   test:    {fmt(report['test'])}")
        print(f"   shifted: {fmt(report['shifted'])}")
        if kind == args.kind:
            detector.save()
            print(f"   saved -> {config.MODEL_PATH} ({detector.version})")

    save_report(reports, "metrics")
    print(json.dumps({k: v["reference"] for k, v in reports.items()}, indent=2))


if __name__ == "__main__":
    main()
