# Tasks: command-policy permissionRules-style redesign

Tracked under GitHub Milestone #1 (`command-policy: permissionRules-style rule format`). Each numbered group corresponds to one Stage (one parent Issue / one PR to `main`; sub-issues may land via sub-PRs targeting the stage branch, as in Stage 1).

## 1. Stage 1 — Close deny bypass in command parsing (Issue #3 — CLOSED, PR #16)

- [x] 1.1 Strip shell keywords (`if`, `then`, `elif`, `else`, `fi`, `for`, `while`, `until`, `do`, `done`, `{`, `}`, `!`), skip `for` headers, and propagate malformed quote/escape parse errors to `tool_call` (Issue #10, PR #13; verified by `extension_test.go` & `mise run check`)
- [x] 1.2 Parse the 11 recognized command wrappers with bounded option tables, implicit `xargs` -> `echo`, informational flags, dual stripped/unstripped deny matching, and fail-closed unknown options (Issue #11, PR #14; verified by `extension_test.go` & `mise run check`)
- [x] 1.3 Recursively inspect `bash`/`sh`/`zsh -c` and space-joined `eval` up to depth 8 (depth 9 error), rejecting missing operands and ambiguous shell options (Issue #12, PR #15; verified by `extension_test.go` & `mise run check`)

## 2. Stage 2 — Do not read project config in untrusted projects (Issue #4)

- [x] 2.1 (Issue #19) Gate project config loading in both `OnSessionStart` and `EventToolCall` on non-empty `cwd` and `ctx.IsProjectTrusted()` returning `(true, nil)` (treating `false` and errors as untrusted, without caching trust state across events), keeping trust checking/loading injectable and unit-testable outside `sdk.Context` (since `sdk.Context` is a concrete struct with no test fake), and verify unit tests cover trusted, untrusted, error, and empty-`cwd` branches (verified by `TestPolicyForTrustGate` & `mise run check`; unconditional blocking of unmatched commands in untrusted projects completes in §2.2 / Issue #20)
- [ ] 2.2 (Issue #20) When untrusted, ignore `<cwd>/.pig/command-policy.json`, allow/block built-in (`defaultPolicy`) matches by their own decision, block all unmatched commands regardless of `onUnlisted` with an explanatory block `reason`, and emit a single `ctx.Notify` notice at `session_start` (confirming `"warn"` vs SDK-documented `"warning"` level); verify `TestEvaluate`, `TestEvaluateOnUnlisted`, new trust unit tests, and `mise run check` pass

## 3. Stage 3 — Judge commands by rule format (Issue #5)

- [ ] 3.1 Split `extensions/command-policy` into SDK-free `shell.go` (lexical layer) and `policy.go` (judgment layer) plus PiG-glue `extension.go`, and verify neither `shell.go` nor `policy.go` imports the PiG SDK
- [ ] 3.2 Extend `shell.go` to detect redirects (`>`, `>>`, `<`, `2>`, etc.), command substitutions, and wrapper presence per segment, and verify unit tests cover `cat a > b` and substitution cases
- [ ] 3.3 Implement rule-format loading and evaluation (`{version, onUnlisted, rules}`, `id`, `decision`, `reason`, `match.prefix` with string/array alternatives, `allow < ask < block`, dual wrapper matching for `ask`/`block`, basename for `ask`/`block` vs original token for `allow`, allow-condition restrictions, non-interactive `ask` -> `block`, and dropping legacy `allow`/`deny` format); verify Droid-measured table tests pass with intentional divergences commented
- [ ] 3.4 Update `README.md` (Configuration, How it works, Limitations) to match the new rule format and verify `mise run check` passes

## 4. Stage 4 — Self-test rules and warn on config errors (Issue #6)

- [ ] 4.1 Add strict JSON decoding (`DisallowUnknownFields`) and source-level structural validation (missing required fields, invalid `decision`, duplicate `id` within one source) that drops the entire source on error; verify unit tests cover each failure mode
- [ ] 4.2 Add non-executing `tests` (`match` / `noMatch`) self-verification that skips only the failing rule and records diagnostics; verify unit tests confirm other valid rules still load
- [ ] 4.3 Surface problem diagnostics via `ctx.Notify(..., "warn")` at `session_start` and display active rule and problem counts in the status bar; verify tests and `mise run check` pass

## 5. Stage 5 — Layer user config with protected built-in deny rules (Issue #7)

- [ ] 5.1 Load user config from `<ConfigHome>/command-policy.json` via `ctx.ConfigHome()` and implement three-tier layering (`project` > `user` > `builtin`), same-`id` override, `enabled: false`, and cross-`id` `block > ask > allow`; verify unit tests cover each layering rule
- [ ] 5.2 Protect built-in `block` rules so user/project configs cannot override them by the same `id` or disable them with `enabled: false`, and preserve untrusted-project behavior (user + built-in apply, unmatched blocked); verify `echo hi` stays blocked under override/`enabled: false` and `mise run check` pass

## 6. Stage 6 — Add `/command-policy check` and status commands (Issue #8)

- [ ] 6.1 Expose structured evaluation results (decision, deciding rule `id`, source, all matched rules) and loaded/disabled/failing source status from SDK-free `policy.go`, and register `/command-policy check <command>` and bare `/command-policy` in `extension.go` without executing commands; verify formatting tests cover `check echo hi`, `check ls`, and status output
- [ ] 6.2 Document `/command-policy check <command>` and `/command-policy` in `README.md` and verify `mise run check` passes

## Workflow follow-up

- After Stage 6 merges to `main`, run `openspec archive command-policy-permission-rules` to promote the five capability specs into `openspec/specs/` and archive the change.
- Verify `openspec validate --all --strict` passes on the archived state.
