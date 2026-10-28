"""Score a held-out set with the frozen rule table.

These sentences are not in tests/data/corpus.json. The rules are not
edited to raise this score. A detection is still flag or block. The
printed MEASURED_HELDOUT line is what the docs may quote.
"""

import json
from pathlib import Path

from guardrail.report import detection_metrics, format_category_report, format_detection_metrics, summarize_categories

CORPUS = Path(__file__).parent / "data" / "corpus.json"
HELDOUT = Path(__file__).parent / "data" / "heldout.json"


def _load(path: Path) -> list[dict[str, str]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    samples = payload["samples"]
    for sample in samples:
        for field in ("id", "text", "label", "category"):
            assert field in sample
        assert sample["label"] in {"malicious", "benign"}
    return samples


def test_heldout_is_disjoint_and_large_enough() -> None:
    design = _load(CORPUS)
    heldout = _load(HELDOUT)
    assert {item["text"] for item in design}.isdisjoint({item["text"] for item in heldout})
    assert sum(item["label"] == "malicious" for item in heldout) >= 20
    assert sum(item["label"] == "benign" for item in heldout) >= 20
    assert len({item["id"] for item in heldout}) == len(heldout)


def test_heldout_metrics() -> None:
    heldout = _load(HELDOUT)
    metrics = detection_metrics(heldout)
    print(format_detection_metrics(metrics, "MEASURED_HELDOUT"))
    print(format_category_report(summarize_categories(heldout)))
    # The design corpus asserts 0.9. This set must not. Editing rules to
    # lift this printout would defeat the hold-out.
    assert metrics["malicious"] >= 20
    assert metrics["benign"] >= 20
