import pytest
import numpy as np

from ml import ml_service
from ml.triage_engine import evaluate_risk
from ml.url_extractor import extract_urls, aggregate_email_url_features


class FakeClassifier:
    classes_ = [0, 1]


class FakeModel:
    named_steps = {"classifier": FakeClassifier()}

    def predict_proba(self, values):
        assert len(values) == 1
        assert values.iloc[0].startswith("subject: ")
        return np.array([[0.2, 0.8]])


def test_analyze_email_schema_and_text_only(monkeypatch):
    monkeypatch.setattr(ml_service, "_load_model", lambda: FakeModel())
    result = ml_service.analyze_email("Hello", "Please read this message")
    assert result["verdict"] == "Phishing"
    assert result["raw_phishing_probability"] == 0.8
    assert result["probability_calibrated"] is False
    assert result["url_analysis"]["url_count"] == 0
    assert result["reasons"]["text_signals"] == []


def test_html_anchor_url_is_extracted(monkeypatch):
    monkeypatch.setattr(ml_service, "_load_model", lambda: FakeModel())
    result = ml_service.analyze_email("Hi", '<a href="http://bit.ly/verify">open</a>')
    assert result["url_analysis"]["url_count"] == 1
    assert result["url_analysis"]["has_shortened_url"] == 1
    assert result["url_analysis"]["has_suspicious_url_tokens"] == 1


def test_empty_email_rejected():
    with pytest.raises(ValueError):
        ml_service.analyze_email("  ", "")


def test_url_extraction_and_aggregation():
    urls = extract_urls("See https://1.2.3.4/login and https://example.com/path")
    features = aggregate_email_url_features(urls)
    assert features["url_count"] == 2
    assert features["has_ip_url"] == 1
    assert features["has_suspicious_url_tokens"] == 1

def test_triage_boundaries():
    # Safe boundary
    assert evaluate_risk(0.3499)["verdict"] == "Safe"

    # Suspicious boundaries
    assert evaluate_risk(0.35)["verdict"] == "Suspicious"
    assert evaluate_risk(0.4999)["verdict"] == "Suspicious"
    assert evaluate_risk(0.50, {})["verdict"] == "Suspicious"
    assert evaluate_risk(0.7499)["verdict"] == "Suspicious"

    # Phishing boundaries
    assert evaluate_risk(0.50, {"has_ip_url": 1})["verdict"] == "Phishing"
    assert evaluate_risk(0.75)["verdict"] == "Phishing"

    # URL anomaly below the Safe threshold
    assert evaluate_risk(
        0.3499,
        {"has_shortened_url": 1}
    )["verdict"] == "Suspicious"