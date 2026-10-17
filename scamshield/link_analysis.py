"""Adapter: rule-based link checks plus optional URL ML observations.

``analyze_links`` calls the public ``check_urls`` exactly once and returns its
list unchanged under "links". The ML layer is a separate, observation-only
field "url_ml" (no score fusion, never changes rule risk). When disabled (the
default) no ML dependency or artifact is touched and "url_ml" is [].
"""
from __future__ import annotations

from scamshield.links import check_urls

__all__ = ["analyze_links"]


def analyze_links(text, claimed_company=None, *, enable_url_ml: bool = False,
                  model_dir=None) -> dict:
    links = check_urls(text, claimed_company)
    if not enable_url_ml or not links:
        return {"links": links, "url_ml": []}
    urls = [r["url"] for r in links]
    try:
        from scamshield.url_ml import predict_urls
        ml = predict_urls(urls, model_dir=model_dir)
        if len(ml) != len(urls):
            raise ValueError("length mismatch")
    except Exception as exc:
        ml = [{"url": u, "status": "unavailable", "phishing_score": None,
               "above_threshold": None, "model_version": None,
               "reason": f"URL model unavailable ({type(exc).__name__})"} for u in urls]
    for r, m in zip(links, ml):
        m["host"] = r["host"]
    return {"links": links, "url_ml": ml}
