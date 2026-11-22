"""
Inference risk triage and explainability engine.

Maps raw, uncalibrated model probabilities and static lexical URL features
to a three-tier decision verdict (Safe, Suspicious, Phishing) with
actionable recommendations and transparent explainability reasons.
"""

from typing import Any


def evaluate_risk(
    p_phishing: float,
    url_features: dict[str, Any] | None = None,
    matched_text_signals: list[str] | None = None
) -> dict[str, Any]:
    """
    Evaluates raw, uncalibrated phishing probability and URL indicators to produce
    the final 3-tier user verdict: Safe, Suspicious, or Phishing.

    Parameters:
    -----------
    p_phishing : float
        Raw, uncalibrated model probability of phishing in [0.0, 1.0].
    url_features : dict, optional
        Aggregated lexical features for URLs in the email (e.g., has_ip_url,
        has_shortened_url, has_suspicious_url_tokens).
    matched_text_signals : list[str], optional
        List of suspicious textual triggers or phrases identified in the body/subject.

    Returns:
    --------
    dict
        Structured triage output containing:
        - 'verdict': "Safe" | "Suspicious" | "Phishing"
        - 'risk_score': float Raw model probability scaled to [0, 100]
        - 'reasons': dict with 'text_signals' and 'url_signals'
        - 'action_recommendation': actionable user-facing guidance
    """
    feats = url_features or {}
    has_ip = feats.get("has_ip_url", 0) == 1
    has_shortener = feats.get("has_shortened_url", 0) == 1
    has_tokens = feats.get("has_suspicious_url_tokens", 0) == 1

    url_anomaly = has_ip or has_shortener or has_tokens

    url_signals: list[str] = []
    if has_ip:
        url_signals.append("Contains raw IP address in destination link")
    if has_shortener:
        url_signals.append("Uses obfuscated URL shortening service")
    if has_tokens:
        url_signals.append("Link path contains sensitive verification keywords")

    text_signals: list[str] = list(matched_text_signals) if matched_text_signals else []

    prob = float(p_phishing)

    # Triage Matrix Rules
    if prob >= 0.75 or (prob >= 0.50 and has_ip):
        verdict = "Phishing"
        recommendation = "High risk detected. Do not click links or disclose credentials."
    elif (0.35 <= prob < 0.75) or (prob < 0.35 and url_anomaly):
        verdict = "Suspicious"
        recommendation = "Potential threat detected. Exercise caution and verify via official channels."
    else:
        verdict = "Safe"
        recommendation = "No prominent phishing or deceptive indicators identified."

    return {
        "verdict": verdict,
        "risk_score": round(prob * 100, 2),
        "reasons": {
            "text_signals": text_signals,
            "url_signals": url_signals
        },
        "action_recommendation": recommendation
    }
