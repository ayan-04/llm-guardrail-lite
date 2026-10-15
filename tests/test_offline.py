"""The library must stay offline. This reads source text; it does not connect."""

from pathlib import Path


def test_library_source_has_no_network_clients() -> None:
    root = Path(__file__).parent.parent / "src" / "guardrail"
    banned = ("getaddrinfo", "urllib.request", "http.client", "httpx", "socket", "requests")
    for path in root.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text, f"{path.name} contains {token}"
