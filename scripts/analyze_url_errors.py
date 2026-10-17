"""Error analysis of the URL model on the VALIDATION partition only.

Never reads test.jsonl. Prints aggregated category counts (no raw URLs).
Categories are deterministic heuristics on the model text (host[:port]) and a
row can fall in several categories.
"""
from __future__ import annotations

import argparse
import collections
import json
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from scamshield.url_ml_preprocessing import registrable_domain  # noqa: E402

PLATFORM_DOMAINS = frozenset("""
blogspot.com wordpress.com github.io herokuapp.com netlify.app vercel.app web.app
firebaseapp.com weebly.com wixsite.com 000webhostapp.com glitch.me pages.dev workers.dev
azurewebsites.net google.com duckdns.org ngrok.io ngrok-free.app repl.co replit.app square.site
godaddysites.com webflow.io framer.app myshopify.com appspot.com cloudfront.net
amazonaws.com r2.dev ipfs.io sharepoint.com wix.com jimdo.com yolasite.com
mystrikingly.com carrd.co gitbook.io notion.site typeform.com forms.gle bit.ly
""".split())
COMMON_TLDS = frozenset("""
com org net edu gov mil int io co uk de fr jp au ca in br ru it nl es ch se pl lk us
info biz be at dk no fi ie nz za mx ar cn kr tw hk sg my
""".split())
BRAND_TOKENS = ("paypal", "apple", "microsoft", "office", "outlook", "netflix", "amazon",
                "facebook", "instagram", "whatsapp", "google", "bank", "dhl", "usps", "wells",
                "chase", "coinbase", "metamask", "binance", "login", "secure", "verify",
                "account", "update", "signin", "wallet", "support", "auth")
IPV4 = re.compile(r"^[0-9]+(\.[0-9]+){3}$")
CATEGORIES = ("ip_host", "punycode_idn", "platform_or_shared_hosting", "uncommon_tld",
              "long_or_digit_heavy_host", "many_subdomains", "hyphen_heavy", "brand_or_lure_token",
              "plain_dictionary_like_host")


def categorise(text: str) -> list[str]:
    host = text.rsplit(":", 1)[0] if text.count(":") == 1 else text
    if IPV4.match(host):
        return ["ip_host"]
    cats = []
    labels = host.split(".")
    reg = registrable_domain(host)
    if "xn--" in host:
        cats.append("punycode_idn")
    if reg in PLATFORM_DOMAINS and host != reg:
        cats.append("platform_or_shared_hosting")
    if labels[-1] not in COMMON_TLDS:
        cats.append("uncommon_tld")
    digits = sum(c.isdigit() for c in host)
    if len(host) > 30 or digits >= 4 or digits / max(len(host), 1) > 0.2:
        cats.append("long_or_digit_heavy_host")
    if len(labels) >= 4:
        cats.append("many_subdomains")
    if host.count("-") >= 2:
        cats.append("hyphen_heavy")
    if any(t in host for t in BRAND_TOKENS):
        cats.append("brand_or_lure_token")
    if not cats and reg.split(".")[0].isalpha():
        cats.append("plain_dictionary_like_host")
    return cats


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="/workspace/url_ml_data/prepared")
    ap.add_argument("--model-dir", default=str(REPO / "artifacts" / "url_ml"))
    a = ap.parse_args(argv)
    from scamshield import url_ml
    b = url_ml.load_model(a.model_dir)
    thr = float(b["meta"]["threshold"])
    rows = [json.loads(l) for l in open(Path(a.data) / "val.jsonl", encoding="utf-8")]
    X = [r["text"] for r in rows]
    s = b["model"].predict_proba(X)[:, b["col"]]
    groups = {"false_positive": [], "false_negative": [], "true_negative": [], "true_positive": []}
    for r, sc in zip(rows, s):
        pred = sc >= thr
        key = ("true_positive" if r["label"] else "false_positive") if pred else \
              ("false_negative" if r["label"] else "true_negative")
        groups[key].append(r["text"])
    out = {"model_version": b["meta"]["model_version"], "threshold": thr,
           "partition": "validation", "n": len(rows),
           "counts": {k: len(v) for k, v in groups.items()}, "categories": {}}
    for k, texts in groups.items():
        c = collections.Counter(cat for t in texts for cat in categorise(t))
        out["categories"][k] = {cat: c[cat] for cat in CATEGORIES}
    print(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
