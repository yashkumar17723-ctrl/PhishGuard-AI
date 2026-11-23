# Phishing Data Engineering: Audit and Quality Report

## 1. Executive Summary
- Total Raw Records Ingested: 79,154
- Curated Training Records (Deduplicated): 5,555
- Phishing Records (Nazario): 1,555
- Safe / Benign Records: 4,000
- Excluded Held-Out Commercial Spam: 37,536

## 2. Split Distribution

| Split | Phishing (1) | Safe (0) | Total |
|---|---|---|---|
| train | 1,088 | 2,800 | 3,888 |
| val | 233 | 600 | 833 |
| test | 234 | 600 | 834 |

## 3. URL Indicator Prevalence in Curated Dataset

- Emails containing URLs: 870
- Emails containing IP-based URLs: 4
- Emails containing shortened URLs: 7
- Emails with suspicious URL path tokens: 42
