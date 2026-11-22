"""Text sanitisation and cleaning module for email subject and body content.

Cleans email text while preserving threat indicators:
- Decodes HTML entities
- Strips markup tags while keeping inner text
- Normalizes excessive whitespace and line breaks
- Preserves capitalization, punctuation clusters, and currency tokens
"""

import html
import math
import re
from typing import Any
from bs4 import BeautifulSoup


def clean_text(raw_text: Any) -> str:
    """Cleans email text while preserving cyber-threat indicators.

    Args:
        raw_text: Raw email subject or body string, or None/NaN.

    Returns:
        Sanitised text string.
    """
    if raw_text is None:
        return ""

    if isinstance(raw_text, float) and math.isnan(raw_text):
        return ""

    text = str(raw_text)
    if not text.strip():
        return ""

    # Decode HTML entities (&amp; -> &, &lt; -> <)
    text = html.unescape(text)

    # Strip HTML tags if HTML tags detected
    if bool(re.search(r"<[^>]+>", text)):
        try:
            soup = BeautifulSoup(text, "html.parser")
            for tag in soup(["script", "style"]):
                tag.decompose()
            text = soup.get_text(separator=" ")
        except Exception:
            text = re.sub(r"<[^>]+>", " ", text)

    # Normalize multiple whitespaces and newlines
    text = re.sub(r"\r\n|\r", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n\s*\n+", "\n\n", text)

    return text.strip()


if __name__ == "__main__":
    sample = "<p>Dear Customer &amp; User,<br>Click <a href='http://evil.com'>Here</a> NOW!!!</p>"
    print("Original:", sample)
    print("Cleaned: ", clean_text(sample))
