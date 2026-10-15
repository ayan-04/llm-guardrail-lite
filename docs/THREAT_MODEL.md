# Threat model

This document describes what llm-guardrail-lite is trying to protect and where it stops. It is a learning project. It is not a certified or production security product.

## Assets

- The system prompt, including any policy text the operator put there, and the canary token that proves a verbatim leak.
- User prompts, which may contain personal data the operator did not mean to store.
- Retrieved or web text that the application wants to show the model (documents, search hits, page text).
- Model output, which may echo personal data, secret-shaped strings, or the canary.
- Tool side effects the application might take if it trusted the model: search, arithmetic, time, and an optional HTTP GET.
- The audit log. It is useful only if it does not become a second copy of the secrets.

## Trust boundaries

| Boundary | Trusted | Untrusted |
| --- | --- | --- |
| Operator config and the rule table | Yes, the operator | A model or a user must not be able to edit these at runtime. This library does not enforce that outside the process. |
| User text | No | Scanned by the input scanner before the model is called. |
| Retrieved or web context | No | Sanitized, scanned, and wrapped. A block verdict skips the model. |
| Model output | No | Redacted, checked for the canary, and not executed as a tool call until `tool_policy` accepts it. |
| Tool arguments | No | Validated against a Pydantic schema and, for `http_get`, against the URL checks. |
| Audit storage | The operator's disk | The bytes written are redacted and hashed so the file is safer to retain. |

The library and the callable the operator passes in run in the same process. A hostile callable can ignore the guardrail. The guardrail only wraps a callable that the operator actually invokes through `GuardedLLM`.

## Attacker goals

- Change the model's instructions (override, jailbreak persona, fake system delimiter).
- Recover the system prompt, either by asking or by getting the model to echo the canary.
- Move data out through phrasing ("send this to") or through a tool call.
- Hide instructions inside retrieved text.
- Cause a tool call the operator did not allow, or a URL that points at localhost, a private address, a link-local address, or a URL with credentials.
- Get personal data or a secret-shaped string back to a person who should not see it.
- Fill the audit log with raw secrets.

## Protections and the OWASP Top 10 for LLM Applications

Names only, from the OWASP Top 10 for LLM Applications. This table says what the code actually does.

| Protection in this repo | OWASP category | What the code does |
| --- | --- | --- |
| Input scanner (`rules.py`, `input_scanner.py`) | Prompt Injection | Scores instruction override, role-play jailbreak phrasing, system-prompt extraction phrasing, delimiter markers, "decode and follow" phrasing, exfiltration phrasing, and tool-abuse phrasing. Block skips the model. |
| Context sanitizer (`sanitizer.py`) | Prompt Injection; Vector and Embedding Weaknesses | Retrieved text is untrusted. Hidden characters are stripped, instruction-like wording is scored, delimiter-like markup is neutralized, and the text is wrapped in a marked data block. A block verdict does not enter the prompt. |
| Output redaction (`output_scanner.py`) | Sensitive Information Disclosure | Emails, phone numbers, Luhn-valid card numbers, and a few secret-shaped patterns are replaced before the text is returned. |
| Canary token (`pipeline.py`) | System Prompt Leakage | The token sits in the system section. A verbatim copy in the output is blocked and not returned. |
| Tool allowlist, Pydantic schemas, URL checks (`tool_policy.py`) | Excessive Agency; Improper Output Handling | The model cannot directly cause a call. The host is given a decision. Unknown tools, bad arguments, disallowed schemes, credentials in the URL, localhost, and private, loopback, link-local, unspecified, multicast, or non-global IP literals are rejected. |
| Per-invoke tool budget | Unbounded Consumption | One reply cannot schedule more tool calls than the budget. This is not a limit across users or across time. |
| JSONL audit (`audit.py`) | Supports the categories above | Records verdicts and rule ids with redacted previews. It is not a monitoring product. |

Categories this repo does not meaningfully address:

- Supply Chain. Dependencies are pinned in `requirements.txt`. There is no dependency review service and no model-artifact supply chain, because there is no model artifact.
- Data and Model Poisoning. There is no training step.
- Misinformation. The library does not check whether an answer is true.
- Unbounded Consumption beyond the single tool budget and the character caps. There is no token accounting, no cross-user rate limit, and no spend limit.

## Residual risks

- The rules are phrases. Wording that does not match, including other languages and encodings that are not in the table, is allowed. NFKC does not fold every lookalike letter.
- There is no semantic classifier and no second model judging the first.
- Hostnames are not resolved, so a public-looking name can still point at a private address.
- PII patterns miss many real identifiers (national ids, many phone formats, names, street addresses).
- The canary catches a verbatim copy only.
- A flag verdict still calls the model. The caller has to read the verdict.
- The host can ignore `tool_decisions` and run text from the model anyway.
- The in-memory response for an allowed tool includes the validated arguments. The audit record for that decision does not.
- The corpus used to print precision, recall, and false-positive rate was written by the same author as the rules. Those numbers are optimistic. See the README.
- This is a learning project, not a certified or production security product.
