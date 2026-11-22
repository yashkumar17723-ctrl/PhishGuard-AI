"""Stable backend API for PhishGuard AI email analysis.

The saved classifier receives cleaned subject/body text only. URL indicators
are extracted separately and passed to the existing triage engine.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any

import joblib
import pandas as pd

from .preprocessing import clean_text
from .url_extractor import (
    aggregate_email_url_features,
    extract_url_features,
    extract_urls,
)
from .triage_engine import evaluate_risk

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "phishing_text_model.joblib"
MODEL_NAME = "TF-IDF + Logistic Regression"


@lru_cache(maxsize=1)
def _load_model() -> Any:
    """Load the bundled model once per Python process."""
    if not MODEL_PATH.is_file():
        raise FileNotFoundError(f"Saved phishing model not found: {MODEL_PATH}")
    return joblib.load(MODEL_PATH)


def _phishing_probability(model: Any, subject: str, body: str) -> float:
    # Keep this exact training-time field format. Do not add URL features.
    email_text = f"subject: {subject} body: {body}"
    probabilities = model.predict_proba(pd.Series([email_text]))

    classifier = getattr(model, "named_steps", {}).get("classifier")
    if classifier is None or not hasattr(classifier, "classes_"):
        raise ValueError("Saved model pipeline must expose named_steps['classifier'].classes_")
    classes = list(classifier.classes_)
    if 1 not in classes:
        raise ValueError("Saved model does not contain phishing class label 1")
    probability = float(probabilities[0, classes.index(1)])
    if not 0.0 <= probability <= 1.0:
        raise ValueError("Model returned a probability outside [0, 1]")
    return probability


def analyze_email(subject: str, body: str) -> dict[str, Any]:
    """Analyze an email and return the stable PhishGuard response schema.

    Args:
        subject: Raw email subject (may be empty).
        body: Raw email body (may be empty).

    Raises:
        ValueError: If both fields are empty after cleaning.
    """
    if subject is not None and not isinstance(subject, str):
        raise TypeError("subject must be a string or None")
    if body is not None and not isinstance(body, str):
        raise TypeError("body must be a string or None")

    raw_subject = subject or ""
    raw_body = body or ""
    cleaned_subject = clean_text(raw_subject)
    cleaned_body = clean_text(raw_body)
    if not cleaned_subject and not cleaned_body:
        raise ValueError("Email subject and body cannot both be empty")

    # Extract from raw content so HTML href targets are not lost by cleaning.
    raw_email = f"{raw_subject}\n{raw_body}"
    urls = extract_urls(raw_email)
    extracted_features = aggregate_email_url_features(urls)
    per_url_features = [extract_url_features(url) for url in urls]
    unique_domains = {
        feature["hostname"] for feature in per_url_features if feature["hostname"]
    }

    # These three fields are the only URL indicators consumed by triage.
    triage_url_features = {
        "has_ip_url": extracted_features["has_ip_url"],
        "has_shortened_url": extracted_features["has_shortened_url"],
        "has_suspicious_url_tokens": extracted_features["has_suspicious_url_tokens"],
    }

    model = _load_model()
    probability = _phishing_probability(model, cleaned_subject, cleaned_body)
    triage = evaluate_risk(
        p_phishing=probability,
        url_features=triage_url_features,
        matched_text_signals=None,  # No validated text-explanation extractor supplied.
    )

    return {
        "model": MODEL_NAME,
        "raw_phishing_probability": round(probability, 6),
        "probability_calibrated": False,
        **triage,
        "url_analysis": {
            "url_count": extracted_features["url_count"],
            "unique_domain_count": len(unique_domains),
            "has_ip_url": triage_url_features["has_ip_url"],
            "has_shortened_url": triage_url_features["has_shortened_url"],
            "has_suspicious_url_tokens": triage_url_features["has_suspicious_url_tokens"],
        },
    }
