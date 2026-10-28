"""Per-category counts for the local corpus.

A row is flagged when the input verdict is flag or block. Benign rows
that flag are false positives. Malicious rows that do not flag are misses.
"""

from guardrail.config import GuardrailConfig
from guardrail.input_scanner import scan_input
from guardrail.models import Verdict


def summarize_categories(
    samples: list[dict[str, str]],
    config: GuardrailConfig | None = None,
) -> list[dict[str, object]]:
    """Count flagged samples for each category and label."""
    cfg = config or GuardrailConfig()
    buckets: dict[tuple[str, str], dict[str, object]] = {}
    for sample in samples:
        key = (sample["category"], sample["label"])
        row = buckets.get(key)
        if row is None:
            row = {
                "category": sample["category"],
                "label": sample["label"],
                "total": 0,
                "flagged": 0,
            }
            buckets[key] = row
        row["total"] = int(row["total"]) + 1
        if scan_input(sample["text"], cfg).verdict is not Verdict.ALLOW:
            row["flagged"] = int(row["flagged"]) + 1
    return [buckets[key] for key in sorted(buckets)]


def format_category_report(rows: list[dict[str, object]]) -> str:
    """One MEASURED_CATEGORY line per row, safe to quote after a real run."""
    lines: list[str] = []
    for row in rows:
        lines.append(
            "MEASURED_CATEGORY "
            f"category={row['category']} label={row['label']} "
            f"total={row['total']} flagged={row['flagged']}"
        )
    return "\n".join(lines)
