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


def detection_metrics(samples: list[dict[str, str]], config: GuardrailConfig | None = None) -> dict[str, float]:
    """Precision, recall, and false-positive rate.

    A detection is a flag or block verdict. Malicious rows are the positive
    class. The caller prints the returned figures; this function does not
    round them for a document.
    """
    cfg = config or GuardrailConfig()
    tp = fp = tn = fn = 0
    malicious = benign = 0
    for sample in samples:
        detected = scan_input(sample["text"], cfg).verdict is not Verdict.ALLOW
        if sample["label"] == "malicious":
            malicious += 1
            if detected:
                tp += 1
            else:
                fn += 1
        elif sample["label"] == "benign":
            benign += 1
            if detected:
                fp += 1
            else:
                tn += 1
        else:
            raise ValueError(sample["label"])
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "corpus_size": float(len(samples)),
        "malicious": float(malicious),
        "benign": float(benign),
        "tp": float(tp),
        "fp": float(fp),
        "tn": float(tn),
        "fn": float(fn),
        "precision": precision,
        "recall": recall,
        "fpr": fpr,
    }


def format_detection_metrics(metrics: dict[str, float], prefix: str) -> str:
    """One line a test can print and a doc can quote after that run."""
    return (
        f"{prefix} corpus_size={metrics['corpus_size']:.0f} "
        f"malicious={metrics['malicious']:.0f} benign={metrics['benign']:.0f} "
        f"tp={metrics['tp']:.0f} fp={metrics['fp']:.0f} "
        f"tn={metrics['tn']:.0f} fn={metrics['fn']:.0f} "
        f"precision={metrics['precision']:.4f} recall={metrics['recall']:.4f} "
        f"fpr={metrics['fpr']:.4f}"
    )


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
