from pydantic import ValidationError
import pytest

from guardrail.models import Finding, Severity, Verdict, stricter, verdict_for_score


def test_stricter_prefers_block_over_flag_and_allow() -> None:
    assert stricter(Verdict.ALLOW, Verdict.FLAG) is Verdict.FLAG
    assert stricter(Verdict.FLAG, Verdict.BLOCK) is Verdict.BLOCK
    assert stricter(Verdict.BLOCK, Verdict.ALLOW) is Verdict.BLOCK


def test_verdict_thresholds_are_inclusive() -> None:
    assert verdict_for_score(2.9, 3.0, 6.0) is Verdict.ALLOW
    assert verdict_for_score(3.0, 3.0, 6.0) is Verdict.FLAG
    assert verdict_for_score(6.0, 3.0, 6.0) is Verdict.BLOCK


def test_finding_requires_its_fields() -> None:
    with pytest.raises(ValidationError):
        Finding(rule_id="x", category="y", severity=Severity.LOW, weight=1.0)
