"""Operator-facing defaults.

Thresholds live here so a deployment can tighten them without editing
the rule table. See DECISIONS.md for why these numbers were chosen.
"""

from pydantic import BaseModel, ConfigDict, Field, model_validator


class GuardrailConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # A single critical rule weighs 6, so the default block line is one
    # clear instruction-override match. The flag line sits lower so a
    # softer signal (jailbreak phrasing, a long base64 blob) is visible
    # without dropping the request.
    flag_threshold: float = Field(default=3.0, gt=0)
    block_threshold: float = Field(default=6.0, gt=0)

    max_input_chars: int = Field(default=8000, gt=0)
    max_context_chars: int = Field(default=16000, gt=0)
    max_output_chars: int = Field(default=8000, gt=0)

    base64_min_length: int = Field(default=40, ge=16)
    # Equal to the default flag threshold: a blob is recorded and flagged,
    # and it does not block on its own. The characters themselves are not
    # copied into the finding, because the blob may be an encoded secret.
    base64_weight: float = Field(default=3.0, gt=0)

    tool_allowlist: list[str] = Field(
        default_factory=lambda: ["search", "calculator", "get_time"]
    )
    tool_call_budget: int = Field(default=8, ge=0)

    # https only. http_get is implemented but absent from tool_allowlist
    # until an operator opts in. An empty host list means "any hostname",
    # with IP literals still checked. A non-empty list is a real allowlist.
    url_scheme_allowlist: list[str] = Field(default_factory=lambda: ["https"])
    url_host_allowlist: list[str] = Field(default_factory=list)

    # Empty means the pipeline generates a fresh token per instance.
    # Callers set this in tests so the value is deterministic.
    canary_token: str = ""
    redaction_token: str = "[REDACTED]"

    @model_validator(mode="after")
    def _thresholds_in_order(self) -> "GuardrailConfig":
        if self.flag_threshold > self.block_threshold:
            raise ValueError("flag_threshold must be less than or equal to block_threshold")
        return self
