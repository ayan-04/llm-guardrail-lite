"""Result types shared by every scanner.

Verdicts are ordered so a pipeline can keep the stricter decision when
several stages run. Scores stay numeric so a reviewer can see why.
"""

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Verdict(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


_RANK = {Verdict.ALLOW: 0, Verdict.FLAG: 1, Verdict.BLOCK: 2}


def stricter(left: Verdict, right: Verdict) -> Verdict:
    """Return the verdict that imposes the tighter restriction."""
    return left if _RANK[left] >= _RANK[right] else right


def verdict_for_score(score: float, flag_threshold: float, block_threshold: float) -> Verdict:
    """Map a weight sum onto ALLOW, FLAG, or BLOCK.

    The two thresholds are inclusive: a score equal to a threshold takes
    that verdict. FLAG is only possible when the flag threshold is lower
    than the block threshold.
    """
    if score >= block_threshold:
        return Verdict.BLOCK
    if score >= flag_threshold:
        return Verdict.FLAG
    return Verdict.ALLOW


class Finding(BaseModel):
    rule_id: str
    category: str
    severity: Severity
    weight: float
    description: str
    excerpt: str = ""


class ScanResult(BaseModel):
    verdict: Verdict
    score: float
    findings: list[Finding] = Field(default_factory=list)
    normalized_text: str = ""


class OutputScanResult(BaseModel):
    verdict: Verdict
    score: float
    findings: list[Finding] = Field(default_factory=list)
    redacted_text: str
    canary_leaked: bool = False


class ToolDecision(BaseModel):
    name: str
    allowed: bool
    reason: str
    # Denied calls keep arguments empty so a credential-bearing value is
    # not handed back to the application as if it were approved.
    arguments: dict[str, Any] = Field(default_factory=dict)


class SanitizedContext(BaseModel):
    wrapped: str
    scan: ScanResult
    invisible_removed: int = 0


class GuardedResponse(BaseModel):
    text: str
    verdict: Verdict
    llm_called: bool
    findings: list[Finding] = Field(default_factory=list)
    tool_decisions: list[ToolDecision] = Field(default_factory=list)
    blocked_at: str | None = None
