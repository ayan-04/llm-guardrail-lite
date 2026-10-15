import json

from guardrail.config import GuardrailConfig
from guardrail.tool_policy import (
    ToolBudget,
    check_url,
    evaluate_tool_call,
    parse_tool_calls,
    strip_tool_lines,
)
from tests.fakes import make_url


def test_budget_rejects_after_the_limit() -> None:
    budget = ToolBudget(1)
    assert budget.try_consume() is True
    assert budget.try_consume() is False


def test_private_loopback_link_local_and_localhost_are_blocked() -> None:
    cases = {
        "10.1.2.3": "private_ip",
        "172.16.5.5": "private_ip",
        "192.168.0.5": "private_ip",
        "127.0.0.1": "loopback_ip",
        "::1": "loopback_ip",
        "169.254.1.1": "link_local_ip",
        "fe80::1": "link_local_ip",
        "0.0.0.0": "unspecified_ip",
        "224.0.0.1": "multicast_ip",
        "localhost": "localhost_host",
        "localhost.localdomain": "localhost_host",
        "app.localhost": "localhost_host",
    }
    for host, reason in cases.items():
        if ":" in host and host.count(":") > 1:
            target = make_url("[" + host + "]")
        else:
            target = make_url(host)
        allowed, got = check_url(target)
        assert allowed is False, host
        assert got == reason, host


def test_credentials_and_bad_scheme_are_blocked() -> None:
    with_password = make_url("docs.example", userinfo="user:pass")
    allowed, reason = check_url(with_password)
    assert allowed is False
    assert reason == "credentials_in_url"
    allowed, reason = check_url(make_url("docs.example", scheme="http"))
    assert allowed is False
    assert reason == "scheme_not_allowed"
    allowed, reason = check_url(make_url("docs.example", scheme="file"))
    assert allowed is False
    assert reason == "scheme_not_allowed"


def test_public_hostname_is_allowed_without_dns() -> None:
    allowed, reason = check_url(make_url("docs.example"))
    assert allowed is True
    assert reason == "ok"
    # A documentation-looking public literal. Parsing does not connect.
    allowed, reason = check_url(make_url("1.2.3.4"))
    assert allowed is True
    assert reason == "ok"


def test_host_allowlist_restricts_names() -> None:
    config = GuardrailConfig(url_host_allowlist=["docs.example"])
    assert check_url(make_url("docs.example"), config)[0] is True
    assert check_url(make_url("Docs.Example"), config)[0] is True
    allowed, reason = check_url(make_url("other.example"), config)
    assert allowed is False
    assert reason == "host_not_allowlisted"


def test_default_tools_and_http_get_opt_in() -> None:
    search = evaluate_tool_call("search", {"query": "weather"})
    assert search.allowed is True
    assert search.arguments["query"] == "weather"
    denied = evaluate_tool_call("http_get", {"url": make_url("docs.example")})
    assert denied.allowed is False
    assert denied.reason == "tool_not_allowlisted"
    assert denied.arguments == {}
    config = GuardrailConfig(tool_allowlist=["http_get"])
    private = evaluate_tool_call("http_get", {"url": make_url("10.1.2.3")}, config)
    assert private.allowed is False
    assert private.reason == "private_ip"
    assert private.arguments == {}
    public = evaluate_tool_call("http_get", {"url": make_url("docs.example")}, config)
    assert public.allowed is True


def test_argument_schema_rejects_shell_metacharacters_and_extra_fields() -> None:
    bad = evaluate_tool_call("calculator", {"expression": "2+2;noop"})
    assert bad.allowed is False
    assert bad.reason == "invalid_arguments"
    extra = evaluate_tool_call("search", {"query": "weather", "cmd": "noop"})
    assert extra.allowed is False
    assert extra.reason == "invalid_arguments"


def test_parse_and_strip_tool_lines() -> None:
    raw = 'Answer.\nTOOL_CALL: {"name": "calculator", "arguments": {"expression": "2+2"}}\nTOOL_CALL: {nope}'
    calls, errors = parse_tool_calls(raw)
    assert errors == ["invalid_json"]
    assert calls[0]["name"] == "calculator"
    assert calls[1]["_error"] == "invalid_json"
    visible = strip_tool_lines(raw)
    assert "TOOL_CALL" not in visible
    assert visible == "Answer."


def test_policy_module_does_not_reference_dns() -> None:
    import inspect
    import guardrail.tool_policy as tool_policy

    source = inspect.getsource(tool_policy)
    assert "getaddrinfo" not in source
    assert "socket" not in source
    assert "urllib.request" not in source
