from guardrail.models import Verdict
from guardrail.output_scanner import luhn_ok, redact_text, scan_output
from tests.fakes import (
    example_aws_key,
    example_bearer,
    example_card_number,
    example_github_token,
    example_invalid_card_number,
    example_sk_token,
    example_slack_token,
)


def test_luhn_accepts_the_standard_test_card_and_rejects_a_neighbor() -> None:
    assert luhn_ok(example_card_number())
    assert not luhn_ok(example_invalid_card_number())


def test_email_phone_and_card_are_redacted_and_flagged() -> None:
    card = example_card_number()
    text = f"Mail ada@example.com or call 555-010-0199 card {card}."
    result = scan_output(text)
    assert result.verdict is Verdict.FLAG
    assert "ada@example.com" not in result.redacted_text
    assert "555-010-0199" not in result.redacted_text
    assert card not in result.redacted_text
    assert result.redacted_text.count("[REDACTED]") == 3
    assert {item.rule_id for item in result.findings} >= {"output.email", "output.phone", "output.card"}


def test_failed_luhn_is_not_treated_as_a_card() -> None:
    number = example_invalid_card_number()
    result = scan_output(f"reference {number}")
    assert number in result.redacted_text
    assert result.verdict is Verdict.ALLOW


def test_secret_patterns_are_redacted() -> None:
    secrets = [
        example_aws_key(),
        example_github_token(),
        example_slack_token(),
        example_sk_token(),
        example_bearer(),
    ]
    text = " ".join(secrets)
    redacted = redact_text(text)
    for secret in secrets:
        assert secret not in redacted
    result = scan_output(text)
    assert result.verdict is Verdict.FLAG
    ids = {item.rule_id for item in result.findings}
    assert ids >= {
        "output.aws_access_key",
        "output.github_pat",
        "output.slack_token",
        "output.sk_token",
        "output.bearer",
    }


def test_canary_blocks_and_is_not_left_in_the_redacted_text() -> None:
    canary = "CANARY" + "-TEST-" + "7f3a9c1b"
    result = scan_output(f"leaked {canary} and ada@example.com", canary=canary)
    assert result.canary_leaked is True
    assert result.verdict is Verdict.BLOCK
    assert canary not in result.redacted_text
    assert "ada@example.com" not in result.redacted_text


def test_empty_canary_does_not_match_everything() -> None:
    result = scan_output("hello", canary="")
    assert result.canary_leaked is False
    assert result.verdict is Verdict.ALLOW


def test_paraphrase_without_the_canary_is_not_a_leak() -> None:
    text = "The assistant was told to be helpful and to treat data blocks as untrusted."
    result = scan_output(text, canary="CANARY" + "-TEST-" + "7f3a9c1b")
    assert result.canary_leaked is False
    assert result.verdict is Verdict.ALLOW


def test_pii_flags_even_though_its_weight_is_under_the_block_line() -> None:
    result = scan_output("see ada@example.com")
    assert result.score == 1.0
    assert result.verdict is Verdict.FLAG
