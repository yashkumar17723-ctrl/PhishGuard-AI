# AI-Based Phishing and Scam Message Detection System
## Data Engineering and Dataset Handover Guide (Member 1 -> Member 2)

This document outlines the data preparation, curated datasets, and feature contracts for downstream model development and evaluation.

---

## 1. Handover Package Files (For Google Drive / Project Repo)

| File Name | Size / Records | Purpose |
|---|---|---|
| `phishing_curated.parquet` | ~37.0 MB / 5,555 records | **Primary Training Dataset**: Cleaned, deduplicated, and pre-split. |
| `held_out_spam.parquet` | ~94.1 MB / 37,536 records | **Robustness Test Dataset**: Excluded commercial marketing spam for false-positive validation. |
| `data_dictionary.md` | Markdown documentation | Complete column schema, data types, and value descriptions. |
| `data_audit_report.md` | Markdown documentation | Summary of missingness, source distribution, and URL indicators. |
| `scripts/triage_engine.py` | Python module | Inference risk engine translating model probabilities into Safe, Suspicious, or Phishing. |

---

## 2. Quickstart Code for Member 2 (Model Training)

Use the following snippet to load and use the pre-split dataset in Python:

```python
import pandas as pd

# 1. Load curated dataset
df = pd.read_parquet("phishing_curated.parquet")

# 2. Extract stratified splits (70% Train, 15% Validation, 15% Test)
train_df = df[df["split"] == "train"]
val_df   = df[df["split"] == "val"]
test_df  = df[df["split"] == "test"]

# 3. Target Label (Binary Ground Truth)
# 1 = Phishing (verified attacks from Nazario corpus)
# 0 = Safe / Benign (clean correspondence from Enron and SpamAssassin ham)
y_train = train_df["project_label"]
y_val   = val_df["project_label"]
y_test  = test_df["project_label"]

# 4. Text Features
X_train_text = train_df["body_clean"]   # Sanitised message body (HTML stripped, entities decoded)
X_train_subj = train_df["subject_clean"]

# 5. Tabular URL Features (Zero network calls required)
url_cols = [
    "url_count",                  # Total unique links extracted
    "has_ip_url",                 # 1 if URL uses raw IP address, else 0
    "has_shortened_url",          # 1 if URL uses shortening domain (bit.ly, tinyurl), else 0
    "max_subdomain_count",        # Maximum subdomain depth
    "has_suspicious_url_tokens"   # 1 if path contains 'login', 'verify', 'banking', etc.
]
X_train_url_feats = train_df[url_cols]
```

---

## 3. Dataset Composition and Split Distribution

The training set applies a balanced sampling ratio (~72% safe, ~28% phishing) to mirror realistic baseline detection while providing strong statistical representation:

| Split | Phishing (1) | Safe (0) | Total Records | Percentage |
|---|---|---|---|---|
| **train** | 1,088 | 2,800 | 3,888 | 70.0% |
| **val** | 233 | 600 | 833 | 15.0% |
| **test** | 234 | 600 | 834 | 15.0% |
| **Total** | **1,555** | **4,000** | **5,555** | **100.0%** |

- **Deduplication**: Content hashes (SHA-256 over cleaned text) ensure **zero duplicate messages** across train, validation, or test sets.
- **Completeness**: 0 null values across all text and URL feature columns.

---

## 4. How to Use the Inference Triage Engine (`triage_engine.py`)

Academic datasets do not have ground truth for an arbitrary "Suspicious" label. Real-world systems use a **calibrated binary classifier** combined with an **expert heuristic risk matrix**:

```python
from scripts.triage_engine import evaluate_risk

# Example: Model outputs calibrated probability P(Phishing) = 0.25
# but URL extractor found a raw IP address
model_prob = 0.25
url_features = {"has_ip_url": 1, "has_shortened_url": 0, "has_suspicious_url_tokens": 0}
text_signals = ["urgent account verification"]

result = evaluate_risk(
    p_phishing=model_prob,
    url_features=url_features,
    matched_text_signals=text_signals
)

print(result)
# Output:
# {
#   "verdict": "Suspicious",
#   "risk_score": 25.0,
#   "reasons": {
#     "text_signals": ["urgent account verification"],
#     "url_signals": ["Contains raw IP address in destination link"]
#   },
#   "action_recommendation": "Potential threat detected. Exercise caution and verify via official channels."
# }
```

### Risk Matrix Thresholds
- **Phishing (High Risk)**:
  - $P(\text{Phishing}) \ge 0.75$, OR ($P(\text{Phishing}) \ge 0.50$ with an IP-based URL).
- **Suspicious (Medium Risk)**:
  - Probability in ambiguous zone ($0.35 \le P < 0.75$), OR $P < 0.35$ with URL anomalies (raw IP, shortener, or security keywords in path).
- **Safe (Low Risk)**:
  - $P(\text{Phishing}) < 0.35$ and zero anomalous URL features.

---

## 5. Robustness Testing with `held_out_spam.parquet`

The raw data contained ~37,536 commercial marketing emails (newsletters, mortgage offers, retail promotions from CEAS and SpamAssassin). These were deliberately isolated into `held_out_spam.parquet`.

**Academic Defense**:
After training your model on `phishing_curated.parquet`, run predictions on `held_out_spam.parquet`. Demonstrate in your college project report that the model does not trigger false phishing alarms on generic promotional marketing spam.

---

## 6. Environment Dependencies

Install required libraries:
```bash
pip install -r requirements.txt
```
*(Packages: `pandas`, `pyarrow`, `beautifulsoup4`, `scikit-learn`, `pytest`)*

