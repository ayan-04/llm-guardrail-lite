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


def read_audit(path: Path) -> list[dict[str, object]]:
    """Load JSONL events. Missing files raise FileNotFoundError."""
    text = path.read_text(encoding="utf-8")
    records: list[dict[str, object]] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        payload = json.loads(line)
        if not isinstance(payload, dict):
            raise ValueError("audit line is not an object")
        records.append(payload)
    return records


def format_audit_file(path: Path) -> str:
    """One plain line per event: time, name, verdict, rule ids, preview.

    The preview is whatever the writer stored. This reader does not put
    the original content back.
    """
    records = read_audit(path)
    if not records:
        return "(no events)"
    lines: list[str] = []
    for record in records:
        rule_ids = record.get("rule_ids") or []
        if isinstance(rule_ids, list) and rule_ids:
            rules = ",".join(str(item) for item in rule_ids)
        else:
            rules = "(none)"
        lines.append(
            f"{record.get('ts', '')} event={record.get('event', '')} "
            f"verdict={record.get('verdict', '')} rules={rules} "
            f"preview={record.get('content_preview', '')}"
        )
    return "\n".join(lines)
