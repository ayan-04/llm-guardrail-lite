"""Score user text against the rule table."""

from guardrail.config import GuardrailConfig
from guardrail.models import Finding, ScanResult, Severity, verdict_for_score
from guardrail.normalize import normalize
from guardrail.output_scanner import redact_text
from guardrail.rules import compiled_rules


def scan_input(text: str, config: GuardrailConfig | None = None) -> ScanResult:
    """Return a verdict for untrusted user text.

    Each rule contributes its weight at most once. Repeating a phrase does
    not multiply the score, which keeps the threshold meaning stable.
    Over-long text is truncated after a flag-weight finding so a huge
    string cannot hide a match past the limit or skip the limit quietly.
    """
    cfg = config or GuardrailConfig()
    findings: list[Finding] = []
    working = text
    if len(working) > cfg.max_input_chars:
        findings.append(
            Finding(
                rule_id="input.too_long",
                category="limit",
                severity=Severity.MEDIUM,
                weight=cfg.flag_threshold,
                description="Input was longer than max_input_chars and was truncated before scoring.",
                excerpt=f"length={len(text)}",
            )
        )
        working = working[: cfg.max_input_chars]

    normalized = normalize(working, base64_min_length=cfg.base64_min_length)
    active = set(cfg.enabled_rules)
    for rule, pattern in compiled_rules():
        if active and rule.id not in active:
            continue
        match = pattern.search(normalized.text)
        if match is None:
            continue
        # Excerpts are redacted so a match that contains an email or key
        # is not copied into logs by accident.
        excerpt = redact_text(match.group(0)[:80], replacement=cfg.redaction_token)
        findings.append(
            Finding(
                rule_id=rule.id,
                category=rule.category,
                severity=rule.severity,
                weight=rule.weight,
                description=rule.description,
                excerpt=excerpt,
            )
        )

    if normalized.base64_blobs:
        # One finding no matter how many blobs, matching the once-per-rule
        # rule. The blob text is omitted because it may be an encoded secret.
        findings.append(
            Finding(
                rule_id="input.suspicious_base64",
                category="encoded_payload",
                severity=Severity.MEDIUM,
                weight=cfg.base64_weight,
                description="A long base64-shaped token was present. It was not decoded.",
                excerpt=f"count={len(normalized.base64_blobs)}",
            )
        )

    score = sum(item.weight for item in findings)
    verdict = verdict_for_score(score, cfg.flag_threshold, cfg.block_threshold)
    return ScanResult(
        verdict=verdict,
        score=score,
        findings=findings,
        normalized_text=normalized.text,
    )
