"""Text normalization applied before any rule runs.

Attackers split keywords with invisible characters or fullwidth lookalikes.
NFKC folds compatibility forms, and format/control characters are removed
so the regex table sees the same word a human sees. This is not a homoglyph
defense: many confusable letters survive NFKC.
"""

from dataclasses import dataclass
import re
import unicodedata


@dataclass(frozen=True)
class NormalizedText:
    text: str
    base64_blobs: tuple[str, ...]
    removed_invisible_count: int


_BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")


def strip_invisible(text: str) -> tuple[str, int]:
    """Drop format characters and control characters.

    Newlines, carriage returns, and tabs are kept so a later whitespace
    collapse still sees word breaks. Zero-width and bidi marks are category
    Cf; they are removed because they are not visible to a reviewer.
    """
    kept: list[str] = []
    removed = 0
    for char in text:
        category = unicodedata.category(char)
        if category == "Cf":
            removed += 1
            continue
        if category == "Cc" and char not in "\n\r\t":
            removed += 1
            continue
        kept.append(char)
    return "".join(kept), removed


def collapse_whitespace(text: str) -> str:
    """Make regex spacing stable without changing the words."""
    return re.sub(r"\s+", " ", text).strip()


def find_base64_blobs(text: str, min_length: int) -> tuple[str, ...]:
    """Return long base64-shaped tokens.

    The pattern is intentionally blunt: a long hex digest also matches.
    Callers flag these; they do not try to decode them.
    """
    found: list[str] = []
    for match in _BASE64_BLOB.finditer(text):
        token = match.group(0)
        if len(token) >= min_length:
            found.append(token)
    return tuple(found)


def normalize(text: str, base64_min_length: int = 40) -> NormalizedText:
    folded = unicodedata.normalize("NFKC", text)
    stripped, removed = strip_invisible(folded)
    collapsed = collapse_whitespace(stripped)
    blobs = find_base64_blobs(collapsed, base64_min_length)
    return NormalizedText(
        text=collapsed,
        base64_blobs=blobs,
        removed_invisible_count=removed,
    )
