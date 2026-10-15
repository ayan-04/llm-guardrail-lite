"""Allowlist, argument schemas, URL checks, and a per-run call budget.

URL checks parse the string and, when the host is an IP literal, ask the
ipaddress module what kind of address it is. Hostnames are not resolved.
A name that would resolve to a private address is therefore not detected.
"""

from typing import Any
import ipaddress
import json
import re
from urllib.parse import urlparse

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from guardrail.config import GuardrailConfig
from guardrail.models import ToolDecision

_TOOL_LINE = re.compile(r"^TOOL_CALL:\s*(\{.*\})\s*$", re.MULTILINE)
_LOCAL_HOSTS = {"localhost", "localhost.localdomain"}


class SearchArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=200)
    max_results: int = Field(default=5, ge=1, le=10)


class CalculatorArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Digits and arithmetic only, so the string is not a shell command.
    expression: str = Field(min_length=1, max_length=100, pattern=r"^[0-9+\-*/().\s]+$")


class GetTimeArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timezone: str = Field(default="UTC", min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_/+-]+$")


class HttpGetArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(min_length=1, max_length=2000)


TOOL_SCHEMAS: dict[str, type[BaseModel]] = {
    "search": SearchArgs,
    "calculator": CalculatorArgs,
    "get_time": GetTimeArgs,
    "http_get": HttpGetArgs,
}


class ToolBudget:
    """Counts proposed tool calls inside a single invoke."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def try_consume(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def _ip_block_reason(host: str) -> str | None:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    # Order picks a stable reason when several flags are true, for example
    # a loopback address that some Python versions also mark private.
    if address.is_multicast:
        return "multicast_ip"
    if address.is_unspecified:
        return "unspecified_ip"
    if address.is_loopback:
        return "loopback_ip"
    if address.is_link_local:
        return "link_local_ip"
    if address.is_private:
        return "private_ip"
    if not address.is_global:
        return "non_global_ip"
    return None


def check_url(url: str, config: GuardrailConfig | None = None) -> tuple[bool, str]:
    """Return (allowed, reason). Never resolves DNS."""
    cfg = config or GuardrailConfig()
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    allowed_schemes = {item.lower() for item in cfg.url_scheme_allowlist}
    if scheme not in allowed_schemes:
        return False, "scheme_not_allowed"
    if parsed.username is not None or parsed.password is not None:
        return False, "credentials_in_url"
    host = parsed.hostname
    if not host:
        return False, "missing_host"
    lowered = host.lower().rstrip(".")
    if lowered in _LOCAL_HOSTS or lowered.endswith(".localhost"):
        return False, "localhost_host"
    ip_reason = _ip_block_reason(lowered)
    if ip_reason is not None:
        return False, ip_reason
    if cfg.url_host_allowlist:
        allowed_hosts = {item.lower().rstrip(".") for item in cfg.url_host_allowlist}
        if lowered not in allowed_hosts:
            return False, "host_not_allowlisted"
    return True, "ok"


def parse_tool_calls(text: str) -> tuple[list[dict[str, Any]], list[str]]:
    """Pull one-line TOOL_CALL JSON objects out of model text.

    Invalid JSON is reported and does not raise. The caller still counts
    the line against the budget so garbage cannot be used to skip the cap.
    """
    calls: list[dict[str, Any]] = []
    errors: list[str] = []
    for match in _TOOL_LINE.finditer(text):
        raw = match.group(1)
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            errors.append("invalid_json")
            calls.append({"name": "", "arguments": {}, "_error": "invalid_json"})
            continue
        if not isinstance(payload, dict) or "name" not in payload:
            errors.append("invalid_shape")
            calls.append({"name": "", "arguments": {}, "_error": "invalid_shape"})
            continue
        arguments = payload.get("arguments", {})
        if arguments is None:
            arguments = {}
        if not isinstance(arguments, dict):
            errors.append("invalid_shape")
            calls.append({"name": str(payload.get("name", "")), "arguments": {}, "_error": "invalid_shape"})
            continue
        calls.append({"name": str(payload["name"]), "arguments": arguments})
    return calls, errors


def strip_tool_lines(text: str) -> str:
    """Remove TOOL_CALL lines so the host does not scrape them out of prose."""
    stripped = _TOOL_LINE.sub("", text)
    return re.sub(r"\n{3,}", "\n\n", stripped).strip()


def evaluate_tool_call(name: str, arguments: dict[str, Any], config: GuardrailConfig | None = None) -> ToolDecision:
    """Validate one call. Denied decisions do not echo the arguments."""
    cfg = config or GuardrailConfig()
    if name not in cfg.tool_allowlist:
        return ToolDecision(name=name, allowed=False, reason="tool_not_allowlisted")
    schema = TOOL_SCHEMAS.get(name)
    if schema is None:
        return ToolDecision(name=name, allowed=False, reason="no_schema")
    try:
        validated = schema.model_validate(arguments)
    except ValidationError:
        return ToolDecision(name=name, allowed=False, reason="invalid_arguments")
    dumped = validated.model_dump()
    if name == "http_get":
        allowed, reason = check_url(str(dumped["url"]), cfg)
        if not allowed:
            return ToolDecision(name=name, allowed=False, reason=reason)
    return ToolDecision(name=name, allowed=True, reason="ok", arguments=dumped)
