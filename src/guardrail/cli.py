"""Tiny CLI. Call main() or build_parser(); do not spawn a shell to test it."""

import argparse
import json
from pathlib import Path

from guardrail.audit import format_audit_file
from guardrail.config import GuardrailConfig
from guardrail.input_scanner import scan_input
from guardrail.models import ScanResult, Verdict
from guardrail.report import format_category_report, summarize_categories


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="Score text with the llm-guardrail-lite input scanner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Score text and print a JSON verdict")
    _add_scan_options(scan)

    explain = sub.add_parser("explain", help="Print the score as a running total")
    _add_scan_options(explain)

    report = sub.add_parser("report", help="Print per-category counts for a corpus file")
    report.add_argument("--corpus", required=True, help="Path to a corpus JSON file")
    report.add_argument("--config", default=None, help="Path to a JSON config file")

    audit = sub.add_parser("audit", help="Print redacted JSONL audit events")
    audit.add_argument("--path", required=True, help="Path to an audit JSONL file")
    return parser


def _add_scan_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--text", required=True, help="Text to scan")
    parser.add_argument("--config", default=None, help="Path to a JSON config file")
    parser.add_argument("--flag-threshold", type=float, default=None)
    parser.add_argument("--block-threshold", type=float, default=None)


def load_config(
    path: str | Path | None = None,
    *,
    flag_threshold: float | None = None,
    block_threshold: float | None = None,
) -> GuardrailConfig:
    """Load defaults, optionally replace them from JSON, then apply CLI overrides.

    JSON is validated by the same model as code, so a flag threshold above
    the block threshold still fails.
    """
    if path is None:
        values = GuardrailConfig().model_dump()
    else:
        loaded = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(loaded, dict):
            raise ValueError("config file must be a JSON object")
        values = loaded
    if flag_threshold is not None:
        values["flag_threshold"] = flag_threshold
    if block_threshold is not None:
        values["block_threshold"] = block_threshold
    return GuardrailConfig.model_validate(values)


def exit_code_for(verdict: Verdict) -> int:
    """Exit codes: 0 allow, 1 flag, 2 block."""
    if verdict == Verdict.BLOCK:
        return 2
    if verdict == Verdict.FLAG:
        return 1
    return 0


def format_explanation(result: ScanResult, config: GuardrailConfig) -> str:
    """Show normalized text, each finding, the running total, and the verdict."""
    lines = [
        f"normalized: {result.normalized_text}",
        f"flag_threshold: {config.flag_threshold:.1f}",
        f"block_threshold: {config.block_threshold:.1f}",
    ]
    running = 0.0
    for finding in result.findings:
        running += finding.weight
        lines.append(
            f"rule {finding.rule_id} weight {finding.weight:.1f} running_total {running:.1f}"
        )
    lines.append(f"total: {result.score:.1f}")
    lines.append(f"verdict: {result.verdict.value}")
    return "\n".join(lines)


def run_scan(text: str, config: GuardrailConfig | None = None) -> tuple[int, str]:
    """Scan text and return an exit code plus JSON."""
    result = scan_input(text, config or GuardrailConfig())
    payload = result.model_dump(mode="json")
    return exit_code_for(result.verdict), json.dumps(payload, sort_keys=True)


def run_explain(text: str, config: GuardrailConfig | None = None) -> tuple[int, str]:
    cfg = config or GuardrailConfig()
    result = scan_input(text, cfg)
    return exit_code_for(result.verdict), format_explanation(result, cfg)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "audit":
        print(format_audit_file(Path(args.path)))
        return 0
    if args.command == "report":
        config = load_config(args.config)
        payload = json.loads(Path(args.corpus).read_text(encoding="utf-8"))
        samples = payload["samples"]
        print(format_category_report(summarize_categories(samples, config)))
        return 0
    config = load_config(
        args.config,
        flag_threshold=args.flag_threshold,
        block_threshold=args.block_threshold,
    )
    if args.command == "explain":
        code, text = run_explain(args.text, config)
    else:
        code, text = run_scan(args.text, config)
    print(text)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
