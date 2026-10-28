# Interview questions

Answers refer to this repository. Personal-experience answers are marked `[FILL IN]`. Likely follow-ups are the next question an interviewer would ask after the answer, not a second full question set.

## 30-second pitch

llm-guardrail-lite wraps any LLM function with checks you can read. It scores user text with weighted rules, treats retrieved context as untrusted data, puts a canary in the system prompt, redacts obvious PII and secret-shaped strings, and refuses tool calls that fail an allowlist, a Pydantic schema, or URL checks that never resolve DNS. It is explainable and tested offline with a fake model. It is a learning project, and the corpus numbers are optimistic because the same author wrote the rules and the samples.

## 2-minute walkthrough

Start at `GuardedLLM.invoke` in `src/guardrail/pipeline.py`. The user string goes through `scan_input`. Normalization folds NFKC, strips zero-width and control characters, and collapses whitespace, then `rules.py` adds weights. At the default thresholds, 6 blocks and 3 flags. A block returns a fixed refusal and does not call the model.

If the caller passed context, `sanitize_context` strips hidden characters, scores the same rules, neutralizes delimiter-like markup, and wraps the text in a marked data block. A block on that scan also skips the model. Otherwise the prompt is the system text, a canary, the wrapped data, and the user text.

The callable returns a string. `scan_output` redacts emails, phones, Luhn-valid card numbers, and a few token shapes. If the canary appears verbatim, the reply is replaced with a refusal. Lines that start with `TOOL_CALL:` are parsed as JSON, checked against the allowlist and the argument model, and counted against a per-invoke budget. URL checks allow `https` by default, reject credentials and localhost, and reject private, loopback, and link-local IP literals without DNS. Every stage appends a JSONL audit event with a hash and a redacted preview.

The tests in `tests/` use `FakeLLM`. Nothing in the suite opens a socket. The README status line is the honest one: unit tests pass offline; never tested against a real LLM.

## Basic

### 1. What problem does this library solve?

It puts a predictable set of checks around an LLM call so a bad user string, a hostile document, a leaked canary, or a disallowed tool call is visible and, in the block cases, stopped.

Follow-up: Which of those checks actually skip the model call? Input block, context block, and a canary leak. A flag still calls the model.

### 2. Why is the LLM a callable instead of an SDK?

`GuardedLLM` types the model as a function from string to string. Tests pass `FakeLLM`. The library stays offline and does not depend on a vendor client.

Follow-up: How would you attach a real client? Write a function that builds the vendor request and returns the text, then pass that function in. That wiring is not in this repo, and it was not tested.

### 3. What are the three verdicts?

`allow`, `flag`, and `block`, defined on `Verdict` in `models.py`. `stricter` keeps the tighter one when several stages run.

Follow-up: What is the default numeric line for each? Flag at 3.0 and block at 6.0 on the input score. Output PII does not use that line.

### 4. What is a finding?

A `Finding` is a rule id, category, severity, weight, description, and a short excerpt. Input excerpts are redacted. Output excerpts are the redaction token, not the secret.

Follow-up: Why not put the matched secret in the finding? The finding is what gets logged. Copying the secret would store it again.

### 5. What happens on an input block?

`invoke` writes an `input_scan` event and an `llm_skipped` event, sets `llm_called` false, and returns `INPUT_REFUSAL`. `FakeLLM.calls` stays 0 in `test_blocked_input_does_not_call_the_model`.

Follow-up: Does the refusal echo the user text? No. It is a fixed sentence.

### 6. Why normalize with NFKC?

Fullwidth Latin letters are compatibility characters. NFKC folds them so the regex sees the same word. The test `test_fullwidth_letters_still_block` covers that.

Follow-up: Does NFKC stop lookalike letters from another script? No. `test_cyrillic_lookalike_is_not_folded_by_nfkc` uses U+0456 and expects the Latin word not to appear.

### 7. Why strip zero-width characters?

They are category Cf. A reader does not see them, and they can split a keyword. `strip_invisible` removes them before the rules run. Newlines and tabs are kept until whitespace collapse.

Follow-up: Where is that tested? `test_zero_width_split_still_blocks` and the corpus sample `m43`.

### 8. What is the canary?

A token stored on `GuardedLLM`. If `canary_token` is empty, the object generates one with `secrets.token_hex(16)`. `build_prompt` places it in the system section. `scan_output` blocks if that exact string is in the output.

Follow-up: Why is an empty canary ignored? The empty string is a substring of every string, so it would block every reply.

### 9. What does the sanitizer wrap context with?

`----- BEGIN UNTRUSTED DATA -----` and `----- END UNTRUSTED DATA -----`. The markers are plain text on purpose, so the wrapper is not itself a fake system tag.

Follow-up: Does the wrapper make the text safe? No. It is a label. A block score still drops the call.

### 10. Why hash the audit content?

Operators need to correlate events without keeping a second copy of a key or a canary. `AuditLog.write` stores SHA-256 of the original and a preview that has been through `redact_text`.

Follow-up: Can a short secret be guessed from the hash? Yes, if the secret is short and the attacker can try candidates. The preview is still redacted, and the canary is generated long when the caller does not set one.

### 11. Why a Luhn check on card numbers?

Many 13 to 19 digit runs are not cards. `luhn_ok` keeps the redaction on numbers that pass the checksum used by payment cards. The tests build the standard 4111 test number by concatenation, and a neighbor that fails the checksum is left in place.

Follow-up: Is every Luhn-valid number a real card? No. The check reduces false redactions. It does not prove the number is in use.

### 12. Which tools are allowlisted by default?

`search`, `calculator`, and `get_time`. `http_get` has a schema and URL checks and is not on the default list.

Follow-up: Why is the calculator expression restricted? The pattern is digits and `+ - * / ( ) .` and spaces, so the string is not a shell command.

### 13. What does the CLI do?

`scan` scores one string with the input scanner and prints JSON. Exit 0 is allow, 1 is flag, 2 is block. Tests call `build_parser`, `run_scan`, and `main` directly.

Follow-up: What happens if the flag threshold is set above the block threshold? `GuardrailConfig` validation fails. `main` rebuilds the model so that check runs.

### 14. How do you run the tests?

Install `requirements.txt`, then `python -m pytest` from the repository root. `pytest.ini` puts `src` on the path. No network and no subprocess.

Follow-up: What does the corpus test print? A `MEASURED` line with precision, recall, and false-positive rate. The README quotes that line.

### 15. What is FakeLLM?

A callable in `tests/fakes.py` that records prompts and returns scripted replies in order. It is how every pipeline test avoids a real model.

Follow-up: What does a clean-path test assert about the prompt? The canary and the untrusted-data wrapper are present, and the canary is absent from the audit JSON.

### 16. What is in the corpus?

`tests/data/corpus.json` holds labeled samples with id, text, label, and category. The measured run had 43 malicious and 45 benign. Labels are `malicious` or `benign`. Benign rows include hard negatives and two documented misses.

Follow-up: What is a hard negative here? Benign text that shares words with an attack, such as "Ignore the noise in this dataset" or "The previous instructions in the manual say to restart."

### 17. How does a sample count as detected?

When `scan_input` returns flag or block. Allow is a negative. That definition is what precision, recall, and false-positive rate use.

Follow-up: Why count flag as a detection? The scanner raised a finding. The pipeline may still call the model, and the metric is about the scanner, not about whether the call was skipped.

### 18. Which Python version does the project target?

3.11 and newer, as stated in the README. The local test run used the interpreter in `.venv`. CI is written for 3.11 and was not executed from this environment.

Follow-up: Why pin every requirement? So a later install resolves the same Pydantic and pytest versions this workspace installed.

## Intermediate

### 19. How is the input score computed?

Sum of the weights of matched rules, plus at most one base64 finding, plus a length finding when the text is over the cap. Each rule id is added once even if the phrase repeats.

Follow-up: What is the score of "Ignore all previous instructions" repeated twice? 6, from `test_each_rule_counts_once`.

### 20. Why do override rules weigh 6 and jailbreak rules weigh 4?

6 meets the default block threshold, so one clear override skips the model. 4 sits between flag and block, so "Enter jailbreak mode." flags and, in the pipeline, still calls the model. `test_flagged_input_still_calls_the_model` locks that in.

Follow-up: What if an operator wants a single jailbreak phrase to block? Raise that rule's weight or lower `block_threshold`. Both are data, not a code change in the scanner.

### 21. Why does output PII ignore the block threshold?

One email weighs 1 in the output score and the verdict is still flag. Two emails must not become a block, or the caller would lose the redacted answer. Only the canary forces block on the output path.

Follow-up: Where is that tested? `test_pii_flags_even_though_its_weight_is_under_the_block_line` and `test_pii_is_redacted_before_return`.

### 22. Walk through indirect injection.

The user string is benign ("Summarize the page."). The context contains an instruction override. `sanitize_context` scores it as block. `invoke` does not call the model, `blocked_at` is `context`, and the text is `CONTEXT_REFUSAL`. The audit reason is `context_block`.

Follow-up: What if the context only flags? The sanitized, wrapped text is included and the model is called. The final verdict is at least flag.

### 23. Why scan context before neutralizing delimiters?

Neutralizing removes the marker the rule is looking for. Scanning first records the finding. Neutralizing then keeps the marker out of the prompt if the verdict is not block. If it is block, the prompt is not built.

Follow-up: Which markers are replaced? `<|im_start|>`, `<|im_end|>`, `[SYSTEM]` and closing variants, `<system>` tags, triple-backtick system, `### system`, and line-leading `system:`, `assistant:`, and `user:`.

### 24. What URL checks exist?

Scheme allowlist, no username or password, a host must be present, localhost and `*.localhost` are rejected, and IP literals are classified with `ipaddress`. An optional host allowlist applies after that. `check_url` does not call `getaddrinfo`.

Follow-up: Why check loopback before private? Some Python versions mark loopback as private as well. The order yields a stable reason string.

### 25. Why no DNS?

A lookup can contact a resolver, and the address can change between the check and the fetch. The code only parses. `test_policy_module_does_not_reference_dns` reads the module source for `getaddrinfo` and `socket`.

Follow-up: What does that miss? A hostname that is not an IP literal and not localhost. Documented in the README limitations and in `DECISIONS.md`.

### 26. Which IP literals are blocked?

Loopback, unspecified, link-local, private, multicast, and any address that is not global. The tests cover 10/8, 172.16/12, 192.168/16, 127.0.0.1, ::1, 169.254.1.1, fe80::1, 0.0.0.0, and 224.0.0.1, plus localhost names.

Follow-up: Is a public IP literal allowed? `1.2.3.4` is allowed by `test_public_hostname_is_allowed_without_dns`. The test parses the string and does not connect.

### 27. How does the tool budget work?

`ToolBudget` starts at `tool_call_budget` on each `invoke`. Every parsed `TOOL_CALL` line consumes one, including invalid JSON. Past the limit the reason is `budget_exhausted` and the arguments are empty.

Follow-up: Why count invalid JSON? Otherwise a reply could emit junk lines without moving the counter.

### 28. Why is the budget per invoke and not per user?

The object does not see a user id. A cross-user limiter would need storage and identity this library does not have. Saying it had one would be false.

Follow-up: What would you add for a real multi-tenant limit? A store keyed by user, outside this class, with a policy for windows and failure mode. That is not built.

### 29. What is in an audit event?

`ts`, `event`, `verdict`, `score`, `rule_ids`, `reason`, `content_sha256`, and `content_preview`. Tool events put the tool name in the content field and the reason code in `reason`. Arguments are not a field.

Follow-up: Which test proves a fake key and the canary stay out of the file? `test_events_redact_and_hash` and `test_canary_leak_blocks_and_hides_the_output`.

### 30. Why Pydantic for tool arguments?

The model returns a dict. `model_validate` rejects the wrong types, extra fields, and strings that fail the pattern. `ValidationError` becomes the reason `invalid_arguments` without copying the exception text into the audit, because that text can echo the bad value.

Follow-up: What does the search schema allow? `query` from 1 to 200 characters and `max_results` from 1 to 10, default 5. Unknown fields are forbidden.

### 31. What if the tool JSON is invalid?

`parse_tool_calls` appends a placeholder with `_error` set to `invalid_json` or `invalid_shape`. The pipeline records a denied decision with that reason and still consumes budget.

Follow-up: What does the user-facing text contain? `strip_tool_lines` removes those lines so the host cannot scrape a call out of the prose.

### 32. How is the final verdict combined?

`stricter` across the input verdict, the context verdict, the output verdict, and a flag if any tool decision is denied. A block returns earlier, so the combination path is for calls that were not blocked up front.

Follow-up: A denied tool and a clean answer: what verdict? Flag. The answer text remains, without the tool line. `test_tool_call_denied`.

### 33. What if the callable raises?

The pipeline catches the exception, logs the type name only, writes `llm_error`, and returns `OUTPUT_REFUSAL`. The exception text is dropped because it may contain the prompt and the canary. `llm_called` is true because the call was attempted.

Follow-up: Why not retry? A retry policy is not built. Retrying could also replay a prompt the operator meant to send once.

### 34. Why is https the only default scheme?

Cleartext and non-HTTP schemes are rejected until the operator adds them. `file` is rejected by the same check. Tests build these strings at runtime so the repository files do not contain URL literals.

Follow-up: Can an operator allow another scheme? Yes, by setting `url_scheme_allowlist`. That is their choice, and the IP checks still apply.

### 35. What does an empty host allowlist mean?

Any hostname that is not localhost and not a blocked IP literal. A non-empty list restricts hosts, compared case-insensitively. `test_host_allowlist_restricts_names`.

Follow-up: Why not deny by default? The library does not know the deployment's hosts. IP checks still run. The choice is recorded in `DECISIONS.md`.

### 36. What is the TOOL_CALL protocol?

One JSON object on a line that starts with `TOOL_CALL:`. `name` is required. `arguments` must be an object if present. The tests use calculator, an unknown tool named shell with a noop argument, and `http_get`.

Follow-up: Does the library run the calculator? No. An allowed decision returns the validated arguments for the host.

### 37. How are secrets kept out of the log when the model echoes a key?

`redact_text` replaces AWS-style ids, `ghp_` tokens, Slack-style tokens, `sk-` tokens, and bearer tokens before the preview is sliced to 80 characters. The tests assemble those strings from pieces so the source does not hold one continuous secret.

Follow-up: Are those patterns complete? No. They are examples of shapes. The limitation is stated in the README.

### 38. What happens to an over-long user string?

A finding `input.too_long` is added with weight equal to the flag threshold, the text is sliced to `max_input_chars`, and the slice is scored. Length alone flags. It does not block unless the sliced text also scores at the block line.

Follow-up: Why flag instead of block? Length is a limit, not an injection. The choice is in `DECISIONS.md`.

## Advanced

### 39. How can the rule table miss an attack?

Anything that does not match the patterns: a paraphrase, another language, or an encoding the table does not name. NFKC will not fold every confusable character. The README states this as a limitation. This answer does not list bypass strings.

Follow-up: What would you add first? More labeled text that you did not write yourself, then measure false positives before adding patterns. That evaluation set is not in this repo.

### 40. Why not an ML classifier?

A classifier needs training data, a model artifact, and a story for why it fired. This project wanted a score you can trace to a rule id in a unit test, with no network and no model file. `DECISIONS.md` records that.

Follow-up: Where would a classifier sit if you added one later? As another finding source with its own weight, still behind the same verdict function. It is not built.

### 41. What is not built?

A machine-learning classifier, semantic checks, rate limiting across users, and monitoring. Also not built: DNS resolution, tool execution, a real LLM client, token or spend accounting, and a dashboard. The CI workflow file is present and was not run from this workspace.

Follow-up: Which of those would you refuse to fake in an interview? All of them. The status line says the tests never ran against a real LLM.

### 42. How does this map to prompt injection in the OWASP Top 10 for LLM Applications?

The input scanner and the context sanitizer are the controls aimed at Prompt Injection. The threat-model table also maps the sanitizer to Vector and Embedding Weaknesses because retrieved text is the indirect path. The mapping is by category name in `docs/THREAT_MODEL.md`.

Follow-up: Does a passing corpus test mean the category is solved? No. The corpus is small and same-author. Residual risk is paraphrase and context that only flags.

### 43. How does excessive agency show up here?

The model can propose a tool, and the host might perform it. `tool_policy` is the check: allowlist, schema, URL policy, budget. The category in the threat model is Excessive Agency, together with Improper Output Handling because the raw model text is not the thing the host should execute.

Follow-up: What is the residual risk? The host ignores `tool_decisions` and parses the model text itself. Stripping `TOOL_CALL` lines reduces that. It does not forbid a careless host.

### 44. What does the canary fail to catch?

A description of the system prompt that does not contain the token. `test_paraphrase_without_the_canary_is_not_a_leak` feeds a sentence about being helpful and expects allow. System Prompt Leakage in the threat model is therefore only partly addressed.

Follow-up: Why not block if the output is similar to the system prompt? Similarity would flag ordinary answers that mention the same words. That comparator is not built, on purpose.

### 45. Why are the corpus numbers optimistic?

The measured line was precision 1.0000, recall 1.0000, and false-positive rate 0.0000 on 43 malicious and 45 benign samples, with tp 43, fp 0, tn 45, and fn 0. The same author wrote the rules and the samples, including the hard negatives. Two `documented_miss` rows are benign paraphrases the rules allow, and that category measured flagged=0. A stranger's wording would score worse. The README says these are not a real-world benchmark.

Follow-up: What floors does the test enforce? It requires at least 40 malicious and 40 benign, precision and recall at least 0.9, and false-positive rate at most 0.1. Those floors are the test's bar. The measured line is the result.

### 46. How do you add a rule without silently breaking benign text?

Add a `Rule` with a unique id, a category, a weight, and a description. Add at least one malicious corpus row the pattern matches and confirm no benign row matches. `test_each_rule_hits_a_malicious_sample_and_no_benign_sample` fails if either side is wrong. Then re-read the `MEASURED` line and update the README only from that run.

Follow-up: Why is weight part of the review? A weight of 6 changes a miss into a skipped model call. A weight of 4 flags and still calls. That is a product decision, not just a regex.

### 47. Is the tool budget safe under concurrency?

No extra claim is made. One `ToolBudget` is created inside one `invoke` on one object. Two threads calling `invoke` on the same object do not share that counter, and they would also share `self.llm` with no lock. Cross-call limiting is not built.

Follow-up: What is safe to say? Each call enforces its own cap on the tool lines in that reply. It does not coordinate processes.

### 48. What would cross-user rate limiting require that is absent?

A user identity, a shared counter, a time window, and a failure mode when the store is down. None of those types exist in `guardrail`. The character caps and the tool budget are the only consumption controls, and both are per call.

Follow-up: Which OWASP category is that a gap for? Unbounded Consumption, as written in the threat model.

### 49. How is supply chain handled?

`requirements.txt` pins the versions that were installed in this workspace, including Pydantic 2.14.1 and pytest 9.1.1. There is no model file to poison. Data and Model Poisoning does not apply because there is no training. A pin is not a full dependency review.

Follow-up: Why is pytest in the same file as the library? The project is small and the CI file installs that one list. An application that imports the library would not need pytest. Splitting the files is not done.

### 50. Was this built with an AI agent?

Yes. The first draft of this repository was written by an AI coding agent in Cursor, in an autonomous build that was told not to ask questions. The agent selected the defaults in `DECISIONS.md`, wrote the corpus, and ran pytest offline. It did not call a live LLM. Whether you reviewed the diff, rewrote pieces, or would decline to ship it is `[FILL IN]`.

Follow-up: What should a reviewer look at first? The block paths in `pipeline.py`, the URL function for any resolve call, the audit preview for raw secrets, and whether the README numbers match a `MEASURED` line you can reproduce.

### 51. What personal experience should you add before you tell this story?

`[FILL IN]`. The repo cannot answer why you chose it, what you changed after reading it, or a bug you found yourself.

Follow-up: If you have not reviewed it yet, say that, then review the block paths before the interview.

### 52. Tell me about a time you reviewed AI-generated security code.

`[FILL IN]`. Use a real review. Do not invent a production incident from this exercise.

Follow-up: What did you change, and what test locked the change in?

### 53. How would you explain a false negative to a stakeholder?

The scanner missed because the text did not match a rule. Flag and block are the only detections. I would show the rule table, the missed string, and the corpus caveat, and I would not quote the 1.0000 recall figure as production performance.

Follow-up: What number are you willing to quote? Only the measured line, labeled as the small local test corpus, plus the statement that it is optimistic.

### 54. What is the trust boundary around the audit log?

The operator trusts the disk more than they trust the model output, but the writer still has to redact. `AuditLog` is the boundary. Callers pass `extra_secrets` so the canary is removed from the preview. The hash is of the original bytes.

Follow-up: What if the operator sets a short canary? The hash is easier to guess, and a short token is also easier to leak by accident. The generator uses 16 bytes of hex when the config value is empty. Operators who set their own token are responsible for its length.

### 55. What would you refuse to claim in a design review?

LangGraph, a monitoring dashboard, a semantic classifier, cross-user rate limits, DNS rebinding protection, exhaustive PII coverage, and "tested against a real LLM." None of those exist here. The status line is the claim: unit tests pass offline; never tested against a real LLM.

Follow-up: What would you build next if the review asked for one item? An evaluation set written by someone else, before any new rules. That set is not in this repo.

## [FILL IN] checklist

- Your name, role, and the setting in which you are presenting the project.
- Why you chose a guardrail project.
- What you personally changed after the initial draft, or a statement that you have not changed it yet.
- A defect you found while reading the code, with the file you found it in.
- Whether you re-ran pytest yourself and saw the `MEASURED` line.
- The second half of question 50: what you reviewed and what you would not ship.
