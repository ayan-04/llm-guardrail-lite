from pydantic import ValidationError
import pytest

from guardrail.config import GuardrailConfig


def test_defaults() -> None:
    config = GuardrailConfig()
    assert config.flag_threshold == 3.0
    assert config.block_threshold == 6.0
    assert config.tool_allowlist == ["search", "calculator", "get_time"]
    assert "http_get" not in config.tool_allowlist
    assert config.url_scheme_allowlist == ["https"]
    assert config.url_host_allowlist == []
    assert config.tool_call_budget == 8
    assert config.canary_token == ""


def test_flag_above_block_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GuardrailConfig(flag_threshold=8.0, block_threshold=6.0)


def test_unknown_field_is_rejected() -> None:
    with pytest.raises(ValidationError):
        GuardrailConfig(not_a_setting=True)  # type: ignore[call-arg]
