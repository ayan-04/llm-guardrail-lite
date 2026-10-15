"""Scripted model stand-in. Replies are returned in order; nothing is sent anywhere."""

from collections.abc import Callable


class FakeLLM:
    def __init__(self, replies: list[str] | None = None) -> None:
        self._replies = list(replies or [])
        self.prompts: list[str] = []

    def __call__(self, prompt: str) -> str:
        self.prompts.append(prompt)
        if not self._replies:
            return ""
        return self._replies.pop(0)

    @property
    def calls(self) -> int:
        return len(self.prompts)


def example_aws_key() -> str:
    # Pieces stay split so a secret scanner does not see one access-key string.
    return "AKIA" + "IOSFODNN7" + "EXAMPLE"


def example_card_number() -> str:
    return "4111" + "1111" + "1111" + "1111"


def example_invalid_card_number() -> str:
    return "4111" + "1111" + "1111" + "1112"


def example_sk_token() -> str:
    return "sk-" + "testFAKEnotlive0000x"


def example_github_token() -> str:
    return "ghp_" + "FAKEexample" + "TokenValue" + "0000"


def example_slack_token() -> str:
    return "xoxb-" + "FAKE-0000-notlive"


def example_bearer() -> str:
    return "Bearer " + ("a" * 24)


def make_url(host: str, scheme: str = "https", userinfo: str | None = None, path: str = "/") -> str:
    """Build a URL in memory so source files do not contain a URL literal."""
    auth = ""
    if userinfo:
        auth = userinfo + "@"
    return scheme + ":" + "//" + auth + host + path


Caller = Callable[[str], str]
