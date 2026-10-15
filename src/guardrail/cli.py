"""Tiny CLI. Call main() or build_parser(); do not spawn a shell to test it."""

import argparse
import json

from guardrail.config import GuardrailConfig
from guardrail.input_scanner import scan_input
from guardrail.models import Verdict


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="guardrail",
        description="Score text with the llm-guardrail-lite input scanner.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan", help="Score text and print a JSON verdict")
    scan.add_argument("--text", required=True, help="Text to scan")
    scan.add_argument("--flag-threshold", type=float, default=None)
    scan.add_argument("--block-threshold", type=float, default=None)
    return parser


def run_scan(text: str, config: GuardrailConfig | None = None) -> tuple[int, str]:
    """Scan text and return an exit code plus JSON.

    Exit codes: 0 allow, 1 flag, 2 block.
    """
    result = scan_input(text, config or GuardrailConfig())
    payload = result.model_dump(mode="json")
    if result.verdict == Verdict.BLOCK:
        code = 2
    elif result.verdict == Verdict.FLAG:
        code = 1
    else:
        code = 0
    return code, json.dumps(payload, sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    # Build a new model so the threshold validator runs. model_copy does not
    # re-check flag_threshold <= block_threshold in this Pydantic version.
    values = GuardrailConfig().model_dump()
    if args.flag_threshold is not None:
        values["flag_threshold"] = args.flag_threshold
    if args.block_threshold is not None:
        values["block_threshold"] = args.block_threshold
    config = GuardrailConfig.model_validate(values)
    code, payload = run_scan(args.text, config)
    print(payload)
    return code


if __name__ == "__main__":
    raise SystemExit(main())
