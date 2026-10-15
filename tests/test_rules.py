import json
from pathlib import Path

from guardrail.normalize import normalize
from guardrail.rules import RULES, compiled_rules

CORPUS = Path(__file__).parent / "data" / "corpus.json"


def test_rule_ids_are_unique_and_patterns_compile() -> None:
    ids = [rule.id for rule in RULES]
    assert len(ids) == len(set(ids))
    compiled = compiled_rules()
    assert len(compiled) == len(RULES)
    categories = {rule.category for rule in RULES}
    assert categories == {
        "instruction_override",
        "roleplay_jailbreak",
        "system_prompt_extraction",
        "delimiter_injection",
        "encoded_payload",
        "data_exfiltration",
        "tool_abuse",
    }


def test_each_rule_hits_a_malicious_sample_and_no_benign_sample() -> None:
    samples = json.loads(CORPUS.read_text(encoding="utf-8"))["samples"]
    malicious = [normalize(item["text"]).text for item in samples if item["label"] == "malicious"]
    benign = [normalize(item["text"]).text for item in samples if item["label"] == "benign"]
    for rule, pattern in compiled_rules():
        assert any(pattern.search(text) for text in malicious), rule.id
        assert not any(pattern.search(text) for text in benign), rule.id
