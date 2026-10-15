# Decisions

Defaults chosen while building llm-guardrail-lite. Each entry is one choice.

## Rules instead of a machine-learning classifier

- Options considered: a trained classifier, an LLM asked to judge the prompt, a regex rule table.
- Choice: a regex rule table with weights.
- Reason: the result has to be explainable and testable with no model file, no GPU, and no network. A classifier would hide why a line was blocked and would need data this repo does not have.

## Canary token for system-prompt leakage

- Options considered: compare the output to the system prompt with fuzzy matching, a secret canary token, do nothing.
- Choice: a per-instance canary placed in the system section. If that exact string appears in the output, the output is blocked.
- Reason: verbatim echo is the leak this can actually prove. Fuzzy matching would flag honest summaries of the instructions. The canary does not catch a paraphrase.

## No DNS resolution

- Options considered: resolve the host and then block private answers, or judge only the URL string.
- Choice: parse the URL and classify IP literals with the standard library. Hostnames are not resolved.
- Reason: a lookup can leak the lookup itself to a resolver, can be slow, and can be pointed at a different address later (rebinding). The gap is documented: a name that resolves to a private address is not caught.

## Pydantic for configuration and tool arguments

- Options considered: hand-written checks, JSON Schema files, Pydantic models.
- Choice: Pydantic v2 models for `GuardrailConfig` and for each tool's arguments.
- Reason: one place rejects unknown fields, bad types, and a flag threshold above the block threshold. Tool calls from the model are untrusted dicts, so they go through `model_validate` before anything is marked allowed.

## Flag and block thresholds

- Options considered: block on any match, a single threshold, two thresholds.
- Choice: flag at 3.0 and block at 6.0. Critical instruction-override, extraction, and delimiter rules weigh 6. Jailbreak, exfiltration, encoded-instruction, and tool-abuse phrasing weigh 4. Each rule counts once.
- Reason: one clear override should stop the call. A softer signal should be visible and still reach the model, so the caller can review it. Repeating the same sentence does not inflate the score.

## Redact versus block

- Options considered: block whenever PII or a secret pattern matches, always redact and return, redact-and-flag for PII and block only the canary.
- Choice: emails, phone numbers, Luhn-valid card numbers, and secret-shaped tokens are replaced with `[REDACTED]` and the verdict is flag. A canary leak, a blocked user prompt, or blocked untrusted context returns a fixed refusal. The model is not called in the last two cases, and a canary leak is not returned.
- Reason: throwing away a whole answer because it contained an email hides a useful reply. Returning a system prompt that echoed the canary does not.

## Empty host allowlist

- Options considered: deny every host until listed, or allow any hostname that is not a blocked IP literal and not localhost.
- Choice: an empty `url_host_allowlist` allows those hostnames. A non-empty list is a real allowlist. `https` is the only default scheme.
- Reason: the library does not know the operator's hosts. IP literals and credentials in the URL are still rejected either way.

## http_get is opt-in

- Options considered: put an HTTP tool on the default allowlist, or leave it implemented but off.
- Choice: default tools are `search`, `calculator`, and `get_time`. `http_get` exists and is checked, and it is not allowlisted until configured.
- Reason: a default that can fetch URLs is a larger side effect than a calculator. The URL checks still run once it is enabled.

## Context that scores block is not sent to the model

- Options considered: wrap hostile retrieved text and send it anyway, or skip the model call.
- Choice: the sanitizer still neutralizes delimiters and wraps data, but a block verdict on that scan skips the model and returns a refusal.
- Reason: wrapping is a seatbelt, not a guarantee. A retrieved page that is itself an instruction override should not be concatenated into the prompt.

## Tool budget is per invoke

- Options considered: a process-wide counter, a per-user counter, a counter that resets on each `invoke`.
- Choice: each `invoke` gets `tool_call_budget` (default 8). Every proposed `TOOL_CALL` line consumes one, including invalid JSON.
- Reason: this object does not know who the user is, so a cross-user limit would be fiction. Per call stops one reply from listing an unbounded number of tools.

## Denied tool calls flag the reply and leave the arguments off the decision

- Options considered: block the whole reply, return the raw model text, or strip the tool line and record a reason.
- Choice: the tool line is removed from the text the caller sees. An allowed call includes validated arguments. A denied call includes a reason code and empty arguments. The reply verdict becomes flag.
- Reason: the host must execute only structured decisions. Echoing a rejected URL, especially one with a password, would undo the check. A bad tool proposal should not delete an otherwise usable answer.

## Audit stores a hash and a redacted preview

- Options considered: log the raw prompt, log nothing, log a hash plus a redacted preview.
- Choice: JSONL with the event name, verdict, score, rule ids, reason code, SHA-256 of the original text, and a preview that has already been through the redactor. The canary is stripped from the preview. Tool decisions log the tool name and the reason, not the arguments.
- Reason: an audit log that contains the secret it just found is another copy of the secret. A hash still lets an operator correlate events.

## Over-long text is truncated and flagged

- Options considered: block on length, ignore length, truncate and add a finding whose weight equals the flag threshold.
- Choice: input and context over the configured cap are truncated, scored, and flagged. Output is redacted first, then truncated, and any truncation adds a finding so the output verdict is at least flag.
- Reason: length is a cost and a hiding place, and it is not by itself an injection. The model still sees only the truncated input when the verdict is flag rather than block.

## Suspicious base64 is flagged once and not copied

- Options considered: decode the blob and scan the result, ignore it, or record one finding.
- Choice: a token of at least 40 base64-alphabet characters adds one finding at `base64_weight` (default 3.0). The finding stores the count, not the characters.
- Reason: the blob might be the secret. Decoding it would mean running attacker-controlled bytes. Long hex strings match this pattern too, which is a known source of flags.

## Standard library besides Pydantic

- Options considered: an HTTP client, an LLM SDK, or the standard library plus Pydantic.
- Choice: Pydantic v2 for models, pytest for tests, and the standard library for everything else. The LLM is a function the caller passes in.
- Reason: the guardrail should run offline and should not pretend to be a chat product.
