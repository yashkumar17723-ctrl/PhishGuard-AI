# Processed Dataset Data Dictionary

| Column | Data Type | Description |
|---|---|---|
| email_id | string | Deterministic unique message identifier ({source}_{index}_{hash}) |
| source | string | Provenance corpus name (Nazario, Enron, SpamAssassin, Ling) |
| subject_raw | string | Original uncleaned subject header |
| body_raw | string | Original uncleaned email body text |
| subject_clean | string | Sanitised subject (HTML stripped, whitespace normalized) |
| body_clean | string | Sanitised body text (HTML stripped, entities decoded) |
| project_label | int | Project ground truth (1 = Phishing, 0 = Safe, -1 = Excluded Spam) |
| content_hash | string | SHA-256 hash of combined clean text used for deduplication |
| split | string | Assigned split (train, val, test) |
| url_count | int | Total number of unique URLs extracted from message |
| has_ip_url | int | 1 if any extracted URL uses an IPv4/IPv6 hostname, else 0 |
| has_shortened_url | int | 1 if any URL uses a known shortening domain, else 0 |
| max_subdomain_count | int | Maximum subdomain depth across all extracted URLs |
| has_suspicious_url_tokens | int | 1 if any URL contains verification/banking tokens in path/query |
