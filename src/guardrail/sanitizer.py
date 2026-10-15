"""Treat retrieved or web text as data, not as instructions.

The scan runs on the cleaned text before delimiters are neutralized, so a
fake system marker is still a finding. Neutralizing after the scan is what
keeps that marker from being copied into the prompt as a role token.
"""

import re

from guardrail.config import GuardrailConfig
from guardrail.input_scanner import scan_input
from guardrail.models import Finding, SanitizedContext, ScanResult, Severity, verdict_for_score
from guardrail.normalize import strip_invisible

_BEGIN = "----- BEGIN UNTRUSTED DATA -----"
_END = "----- END UNTRUSTED DATA -----"

# Chat-template markers and line-leading role labels. Replacing them does
# not make the text safe; it stops a naive concatenation from looking like
# a new system turn. The scanner still has to score the wording.
_NEUTRALIZERS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"<\s*\|\s*im_start\s*\|\s*>", re.IGNORECASE), "[removed-delim]"),
    (re.compile(r"<\s*\|\s*im_end\s*\|\s*>", re.IGNORECASE), "[removed-delim]"),
    (re.compile(r"\[/?\s*system\s*\]", re.IGNORECASE), "[removed-delim]"),
    (re.compile(r"</?\s*system\s*>", re.IGNORECASE), "[removed-delim]"),
    (re.compile(r"```\s*system", re.IGNORECASE), "[removed-delim]"),
    (re.compile(r"###\s*system\b", re.IGNORECASE), "[removed-delim]"),
    (re.compile(r"(?m)^(?:system|assistant|user)\s*:\s*", re.IGNORECASE), "[removed-role] "),
)


def neutralize_markup(text: str) -> str:
    neutralized = text
    for pattern, replacement in _NEUTRALIZERS:
        neutralized = pattern.sub(replacement, neutralized)
    return neutralized


def wrap_untrusted(text: str) -> str:
    return f"{_BEGIN}\n{text}\n{_END}"


def _append_finding(scan: ScanResult, finding: Finding, config: GuardrailConfig) -> ScanResult:
    findings = [*scan.findings, finding]
    score = scan.score + finding.weight
    verdict = verdict_for_score(score, config.flag_threshold, config.block_threshold)
    return ScanResult(
        verdict=verdict,
        score=score,
        findings=findings,
        normalized_text=scan.normalized_text,
    )


def sanitize_context(text: str, config: GuardrailConfig | None = None) -> SanitizedContext:
    """Strip hidden characters, score instruction-like wording, wrap the result."""
    cfg = config or GuardrailConfig()
    visible, removed = strip_invisible(text)
    working = visible
    scan_text = working
    extra: Finding | None = None
    if len(working) > cfg.max_context_chars:
        extra = Finding(
            rule_id="context.too_long",
            category="limit",
            severity=Severity.MEDIUM,
            weight=cfg.flag_threshold,
            description="Context was longer than max_context_chars and was truncated.",
            excerpt=f"length={len(working)}",
        )
        scan_text = working[: cfg.max_context_chars]

    # Context has its own length cap. Raising the input cap for this call
    # stops the input scanner from applying max_input_chars to retrieved text.
    scan_cfg = cfg.model_copy(
        update={"max_input_chars": max(cfg.max_input_chars, cfg.max_context_chars)}
    )
    scan = scan_input(scan_text, scan_cfg)
    if extra is not None:
        scan = _append_finding(scan, extra, cfg)

    neutralized = neutralize_markup(scan_text)
    return SanitizedContext(
        wrapped=wrap_untrusted(neutralized),
        scan=scan,
        invisible_removed=removed,
    )
