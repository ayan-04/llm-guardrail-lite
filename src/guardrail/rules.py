"""Explainable rule table.

Each rule is a documented phrasing, not a model. Weights are points added
into one score. A weight of 6 meets the default block threshold by itself.
A weight of 4 stays between flag and block so one softer signal is reviewed
instead of dropped. Patterns are case-insensitive and expect normalize()
to have collapsed whitespace already.

The phrases are the short, widely documented ones used to test detectors
(instruction override, a fake system delimiter, "send this to", and so on).
"""

from dataclasses import dataclass
from functools import lru_cache
import re

from guardrail.models import Severity


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    pattern: str
    weight: float
    description: str
    severity: Severity


RULES: tuple[Rule, ...] = (
    Rule(
        id="inj.override.ignore_previous",
        category="instruction_override",
        pattern=(
            r"\bignore\s+(?:all\s+|any\s+|the\s+)?"
            r"(?:previous|prior|above|earlier)\s+"
            r"(?:instructions|prompts|rules|directions)\b"
        ),
        weight=6.0,
        description="Tells the model to ignore earlier instructions.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.override.disregard",
        category="instruction_override",
        pattern=(
            r"\bdisregard\s+(?:your|the|all|any)\s+"
            r"(?:previous|prior|system|safety|above)\s+"
            r"(?:prompt|instructions|rules|policy|policies)\b"
        ),
        weight=6.0,
        description="Tells the model to disregard system or safety instructions.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.override.forget",
        category="instruction_override",
        pattern=(
            r"\bforget\s+(?:everything|all|any)\s+"
            r"(?:you\s+were\s+told|previous\s+instructions|prior\s+instructions|above)\b"
        ),
        weight=6.0,
        description="Tells the model to forget prior instructions.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.override.override_prompt",
        category="instruction_override",
        pattern=(
            r"\boverride\s+(?:your|the)\s+(?:system|safety)\s+"
            r"(?:prompt|instructions|rules|policy)\b"
        ),
        weight=6.0,
        description="Asks to override the system prompt or safety policy.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.jailbreak.persona",
        category="roleplay_jailbreak",
        pattern=(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are))\s+"
            r"(?:dan|an?\s+ai\s+with\s+no\s+(?:rules|restrictions|filters)"
            r"|a\s+persona\s+that\s+ignores\s+safety)\b"
        ),
        weight=4.0,
        description="Role-play jailbreak that asks for an unrestricted persona.",
        severity=Severity.HIGH,
    ),
    Rule(
        id="inj.jailbreak.no_restrictions",
        category="roleplay_jailbreak",
        pattern=(
            r"\bact\s+as\s+if\s+you\s+have\s+no\s+restrictions\b"
            r"|\bdo\s+anything\s+now\b"
            r"|\benter\s+jailbreak\s+mode\b"
        ),
        weight=4.0,
        description="Asks the model to drop restrictions or enter a jailbreak mode.",
        severity=Severity.HIGH,
    ),
    Rule(
        id="inj.extract.reveal",
        category="system_prompt_extraction",
        pattern=(
            r"\b(?:reveal|print|show|display|leak|output)\s+(?:me\s+)?"
            r"(?:your|the)\s+(?:system\s+prompt|hidden\s+instructions|"
            r"initial\s+instructions|original\s+instructions)\b"
        ),
        weight=6.0,
        description="Asks the model to reveal hidden or system instructions.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.extract.what_is",
        category="system_prompt_extraction",
        pattern=(
            r"\bwhat\s+(?:is|are)\s+your\s+"
            r"(?:system\s+prompt|hidden\s+instructions|original\s+instructions)\b"
        ),
        weight=6.0,
        description="Asks what the system prompt or hidden instructions are.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.extract.repeat_above",
        category="system_prompt_extraction",
        pattern=r"\brepeat\s+(?:the\s+)?(?:text|words|message)\s+above\b",
        weight=6.0,
        description="Asks the model to repeat the text above, a common extraction phrasing.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.delimiter.fake_system",
        category="delimiter_injection",
        pattern=(
            r"<\|im_start\|>|<\|im_end\|>"
            r"|\[/?\s*system\s*\]"
            r"|</?\s*system\s*>"
            r"|###\s*system\b"
            r"|```system"
        ),
        weight=6.0,
        description="Delimiter or fake system-message marker.",
        severity=Severity.CRITICAL,
    ),
    Rule(
        id="inj.encoded.follow",
        category="encoded_payload",
        pattern=(
            r"\b(?:base64|rot13|hex)\s+decode\b"
            r"|\bdecode\s+(?:this\s+)?(?:base64|rot13|hex)\b"
            r"|\bfrom\s*char\s*code\b"
            r"|\bunicode\s+escape\b"
        ),
        weight=4.0,
        description="Asks the model to decode an obfuscated instruction and follow it.",
        severity=Severity.HIGH,
    ),
    Rule(
        id="inj.exfil.phrasing",
        category="data_exfiltration",
        pattern=(
            r"\bsend\s+this\s+to\b"
            r"|\b(?:email|exfiltrate)\s+the\s+"
            r"(?:secrets|passwords|keys|data|conversation)\b"
            r"|\bpost\s+(?:this|the)\s+data\b"
        ),
        weight=4.0,
        description="Phrasing that asks to send secrets or the conversation out.",
        severity=Severity.HIGH,
    ),
    Rule(
        id="inj.exfil.markdown_image",
        category="data_exfiltration",
        pattern=r"!\[[^\]]*\]\([^)\s]*\?[^)\s]*data=",
        weight=4.0,
        description="Markdown image whose query string carries a data parameter.",
        severity=Severity.HIGH,
    ),
    Rule(
        id="inj.tool.abuse",
        category="tool_abuse",
        pattern=(
            r"\bignore\s+the\s+tool\s+allowlist\b"
            r"|\bbypass\s+the\s+tool\s+policy\b"
            r"|\brun\s+a\s+shell\s+command\b"
            r"|\bexecute\s+arbitrary(?:\s+code)?\b"
            r"|\bcall\s+the\s+tool\s+with\b"
        ),
        weight=4.0,
        description="Phrasing that asks to bypass tool policy or run a shell command.",
        severity=Severity.HIGH,
    ),
)


@lru_cache(maxsize=1)
def compiled_rules() -> tuple[tuple[Rule, re.Pattern[str]], ...]:
    compiled: list[tuple[Rule, re.Pattern[str]]] = []
    for rule in RULES:
        compiled.append((rule, re.compile(rule.pattern, re.IGNORECASE)))
    return tuple(compiled)
