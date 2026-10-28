from guardrail.walkthrough import walkthrough_text


def test_walkthrough_traces() -> None:
    text = walkthrough_text()
    print("WALKTHROUGH_BEGIN")
    print(text)
    print("WALKTHROUGH_END")
    assert "trace: allow" in text
    assert "llm_called: true" in text
    assert "text: Paris is the capital." in text
    assert "trace: blocked_input" in text
    assert "llm_called: false" in text
    assert "input_rules: inj.override.ignore_previous" in text
    assert "trace: pii_redaction" in text
    assert "ada@example.com" not in text.split("trace: pii_redaction", 1)[1]
    assert "output_rules: output.email" in text
    assert "[REDACTED]" in text
