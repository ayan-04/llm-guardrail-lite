"""JSONL audit events.

The log stores a hash and a short redacted preview. It does not store raw
secrets, the canary, or approved tool arguments. A hash of a short secret
can still be guessed offline, so previews are redacted before they are written
and callers should keep the canary long.
"""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from guardrail.output_scanner import redact_text


class AuditLog:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path
        self.events: list[dict[str, object]] = []

    def write(
        self,
        event: str,
        *,
        verdict: str = "",
        score: float = 0.0,
        rule_ids: list[str] | None = None,
        reason: str = "",
        content: str = "",
        extra_secrets: list[str] | None = None,
    ) -> dict[str, object]:
        preview_source = redact_text(content, extra_secrets=extra_secrets)
        for secret in extra_secrets or []:
            if secret:
                preview_source = preview_source.replace(secret, "[REDACTED]")
        preview = preview_source.replace("\n", " ")[:80]
        record: dict[str, object] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "verdict": verdict,
            "score": score,
            "rule_ids": list(rule_ids or []),
            "reason": reason,
            "content_sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
            "content_preview": preview,
        }
        self.events.append(record)
        if self.path is not None:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8", newline="\n") as handle:
                handle.write(json.dumps(record, sort_keys=True, ensure_ascii=True) + "\n")
        return record
