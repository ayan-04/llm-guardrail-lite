"""Detect and redact PII and secret-shaped strings, and catch a canary.

PII and secret hits are redacted and flagged. They do not use the numeric
block threshold: the useful response is the redacted text, not a refusal.
A canary hit is different. The token exists only inside the system prompt,
so seeing it in the output means the prompt was echoed. That path blocks.

Patterns are intentionally incomplete. See the known limitations.
"""

import re

from guardrail.config import GuardrailConfig
from guardrail.models import Finding, OutputScanResult, Severity, Verdict

_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
# Separators are required so a long digit run is left for the card check.
_PHONE = re.compile(r"(?<!\d)(?:\+1[\s.-]?)?\(?\d{3}\)?[\s.-]\d{3}[\s.-]\d{4}(?!\d)")
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_PAT = re.compile(r"\bghp_[A-Za-z0-9]{20,}\b")
_SLACK = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")
_SK_TOKEN = re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")
_BEARER = re.compile(r"\bBearer\s+[A-Za-z0-9\-._~+/]{20,}\b")


def luhn_ok(number: str) -> bool:
    """True when digits pass the Luhn checksum used by payment card numbers."""
    if not number.isdigit() or not 13 <= len(number) <= 19:
        return False
    total = 0
    for index, char in enumerate(reversed(number)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _card_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for match in _CARD.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if luhn_ok(digits):
            spans.append((match.start(), match.end()))
    return spans


_SIMPLE_PATTERNS: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    ("output.email", "pii", _EMAIL, "Email address."),
    ("output.phone", "pii", _PHONE, "Phone number."),
    ("output.aws_access_key", "secret", _AWS_KEY, "AWS-style access key id."),
    ("output.github_pat", "secret", _GITHUB_PAT, "GitHub-style personal access token."),
    ("output.slack_token", "secret", _SLACK, "Slack-style token."),
    ("output.sk_token", "secret", _SK_TOKEN, "sk-style token."),
    ("output.bearer", "secret", _BEARER, "Bearer token."),
)


def _overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    return any(not (end <= left or start >= right) for left, right in spans)


def redact_text(text: str, replacement: str = "[REDACTED]", extra_secrets: list[str] | None = None) -> str:
    """Replace PII, secret-shaped tokens, and any extra secret strings."""
    spans: list[tuple[int, int]] = []
    for _, _, pattern, _ in _SIMPLE_PATTERNS:
        for match in pattern.finditer(text):
            if not _overlaps(spans, match.start(), match.end()):
                spans.append((match.start(), match.end()))
    for start, end in _card_spans(text):
        if not _overlaps(spans, start, end):
            spans.append((start, end))

    redacted = text
    for start, end in sorted(spans, reverse=True):
        redacted = redacted[:start] + replacement + redacted[end:]

    for secret in extra_secrets or []:
        if secret:
            redacted = redacted.replace(secret, replacement)
    return redacted


def scan_output(
    text: str,
    config: GuardrailConfig | None = None,
    canary: str = "",
) -> OutputScanResult:
    """Redact the output. Block only when the canary is echoed verbatim."""
    cfg = config or GuardrailConfig()
    findings: list[Finding] = []
    working = text

    # An empty canary would match every string. Only a real token counts.
    canary_leaked = bool(canary) and canary in working
    if canary_leaked:
        findings.append(
            Finding(
                rule_id="output.canary",
                category="system_prompt_leakage",
                severity=Severity.CRITICAL,
                weight=cfg.block_threshold,
                description="The canary token from the system prompt appeared in the output.",
                excerpt=cfg.redaction_token,
            )
        )

    for rule_id, category, pattern, description in _SIMPLE_PATTERNS:
        if pattern.search(working):
            findings.append(
                Finding(
                    rule_id=rule_id,
                    category=category,
                    severity=Severity.HIGH if category == "secret" else Severity.MEDIUM,
                    weight=1.0,
                    description=description,
                    excerpt=cfg.redaction_token,
                )
            )

    if _card_spans(working):
        findings.append(
            Finding(
                rule_id="output.card",
                category="pii",
                severity=Severity.HIGH,
                weight=1.0,
                description="Payment card number that passed the Luhn check.",
                excerpt=cfg.redaction_token,
            )
        )

    redacted = redact_text(working, replacement=cfg.redaction_token, extra_secrets=[canary] if canary else None)
    if len(redacted) > cfg.max_output_chars:
        findings.append(
            Finding(
                rule_id="output.too_long",
                category="limit",
                severity=Severity.MEDIUM,
                weight=1.0,
                description="Output was longer than max_output_chars and was truncated after redaction.",
                excerpt=f"length={len(redacted)}",
            )
        )
        redacted = redacted[: cfg.max_output_chars]

    score = sum(item.weight for item in findings)
    if canary_leaked:
        verdict = Verdict.BLOCK
    elif findings:
        verdict = Verdict.FLAG
    else:
        verdict = Verdict.ALLOW

    return OutputScanResult(
        verdict=verdict,
        score=score,
        findings=findings,
        redacted_text=redacted,
        canary_leaked=canary_leaked,
    )
