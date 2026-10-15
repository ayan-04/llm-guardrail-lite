import json

from guardrail.audit import AuditLog
from tests.fakes import example_aws_key


def test_events_redact_and_hash(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    secret = example_aws_key()
    canary = "CANARY" + "-TEST-" + "7f3a9c1b"
    content = f"key {secret} mail ada@example.com token {canary}"
    record = log.write(
        "output_scan",
        verdict="flag",
        score=1.0,
        rule_ids=["output.aws_access_key"],
        reason="",
        content=content,
        extra_secrets=[canary],
    )
    assert secret not in str(record["content_preview"])
    assert "ada@example.com" not in str(record["content_preview"])
    assert canary not in str(record["content_preview"])
    assert record["content_sha256"]
    on_disk = path.read_text(encoding="utf-8")
    assert secret not in on_disk
    assert canary not in on_disk
    assert "ada@example.com" not in on_disk
    loaded = json.loads(on_disk)
    assert loaded["event"] == "output_scan"
    assert loaded["rule_ids"] == ["output.aws_access_key"]
