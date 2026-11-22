import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly"
}

SUSPICIOUS_TOKENS = {
    "login", "verify", "verification", "secure", "account",
    "update", "banking", "confirm", "password", "credential", "auth"
}

IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}(:\d+)?$")
URL_REGEX = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)


def extract_urls(raw_text: str | None) -> list[str]:
    """Extracts unique URLs from plain text and HTML anchor tags."""
    if not raw_text:
        return []

    text = str(raw_text)
    urls = set()

    # 1. Plain text regex extraction
    for match in URL_REGEX.findall(text):
        cleaned_url = match.rstrip(".,;)>]\"'")
        if cleaned_url:
            urls.add(cleaned_url)

    # 2. HTML href extraction if tags present
    if "<a " in text.lower():
        try:
            soup = BeautifulSoup(text, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                if href.startswith("http://") or href.startswith("https://") or href.startswith("www."):
                    urls.add(href.rstrip(".,;)>]\"'"))
        except Exception:
            pass

    return sorted(list(urls))


def extract_url_features(url: str) -> dict:
    """Computes static lexical features for a single URL without network requests."""
    parsed = urlparse(url if "://" in url else "http://" + url)
    hostname = (parsed.hostname or "").lower()
    path_and_query = (parsed.path + "?" + parsed.query).lower()

    has_ip = 1 if IPV4_REGEX.match(hostname) else 0
    is_shortener = 1 if hostname in SHORTENER_DOMAINS else 0
    subdomains = max(0, len(hostname.split(".")) - 2) if not has_ip and hostname else 0
    has_at = 1 if "@" in url else 0

    suspicious_token_count = sum(1 for token in SUSPICIOUS_TOKENS if token in path_and_query)

    return {
        "url": url,
        "hostname": hostname,
        "has_ip_hostname": has_ip,
        "url_length": len(url),
        "subdomain_count": subdomains,
        "is_shortener": is_shortener,
        "has_at_symbol": has_at,
        "suspicious_path_tokens": suspicious_token_count
    }


def aggregate_email_url_features(urls: list[str]) -> dict:
    """Aggregates URL metrics into tabular email-level summary features."""
    if not urls:
        return {
            "url_count": 0,
            "has_ip_url": 0,
            "has_shortened_url": 0,
            "max_subdomain_count": 0,
            "has_suspicious_url_tokens": 0
        }

    feats_list = [extract_url_features(u) for u in urls]

    return {
        "url_count": len(urls),
        "has_ip_url": int(any(f["has_ip_hostname"] == 1 for f in feats_list)),
        "has_shortened_url": int(any(f["is_shortener"] == 1 for f in feats_list)),
        "max_subdomain_count": max(f["subdomain_count"] for f in feats_list),
        "has_suspicious_url_tokens": int(any(f["suspicious_path_tokens"] > 0 for f in feats_list))
    }
