# PhishGuard AI — Backend integration

## API

```python
from ml.ml_service import analyze_email

result = analyze_email(
    subject="Urgent account verification",
    body="Please review the message at https://example.com/verify",
)
```

`analyze_email(subject, body)` returns model probability, triage verdict, reasons,
action recommendation, and aggregated URL analysis.

## Architecture rules preserved

- `clean_text()` from the supplied Member 1 module is applied to subject and body.
- The saved TF-IDF + Logistic Regression model receives only
  `subject: <cleaned subject> body: <cleaned body>`.
- URL extraction runs separately on raw content, preserving HTML anchor hrefs.
- Only `has_ip_url`, `has_shortened_url`, and
  `has_suspicious_url_tokens` are passed to the supplied triage engine.
- The model is loaded once per process via an LRU cache.
- `probability_calibrated` is always `false`; `risk_score` is the raw model
  probability multiplied by 100, not a verified real-world likelihood.
- Text explanation signals remain empty because no validated text-signal
  extractor was supplied.

## Layout

- `ml/ml_service.py`: stable API imported by Streamlit
- `ml/preprocessing.py`: supplied text cleaner
- `ml/url_extractor.py`: supplied URL extractor
- `ml/triage_engine.py`: supplied triage engine
- `models/`: saved model and metadata
- `tests/`: backend unit tests

## Install and test

Use the Python/dependency versions recorded in `models/model_metadata.json`.
Then run:

```bash
pip install -r requirements.txt
python -m pytest -q
```

Streamlit integration:

```python
from ml.ml_service import analyze_email
result = analyze_email(subject, body)
```

## Known limitations

- URL indicators are lexical heuristics; suspicious token substring matching
  can flag legitimate URLs. A URL count is not evidence of phishing by itself.
- The classifier's probability is uncalibrated.
- Reported validation metrics in model metadata should not be described as
  independent real-world performance without the dataset/source caveats in
  the team handover.
