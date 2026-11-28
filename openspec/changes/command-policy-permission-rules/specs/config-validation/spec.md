# Spec Delta: config-validation

## Purpose

Validates rule configuration files strictly, self-tests individual rules without executing commands, and reports configuration problems through session-start warnings and status-bar diagnostics.

## ADDED Requirements

### Requirement: Strict JSON decoding rejects unknown fields
The judgment layer SHALL decode configuration JSON with unknown fields disallowed (equivalent to `DisallowUnknownFields`), treating any unknown field as a source-level structural error.

#### Scenario: Unknown field drops the config source
- **WHEN** a rule file contains an unrecognized top-level or rule-level JSON field
- **THEN** the judgment layer rejects the entire config source and records a problem diagnostic

### Requirement: Structural errors drop the entire config source
The judgment layer SHALL reject an entire config source when any rule is missing a required field (`id`, `decision`, `reason`, `match.prefix`), has an invalid `decision` value, or duplicates another rule's `id` within the same config source.

#### Scenario: Missing required field, invalid decision, or duplicate id
- **WHEN** a config source contains a rule with a missing required field, a `decision` other than `allow`/`ask`/`block`, or a duplicate `id` within that source
- **THEN** the entire config source is not loaded (fail closed) and a problem diagnostic is recorded

### Requirement: Non-executing rule self-tests skip only failing rules
The judgment layer SHALL verify each rule's `tests.match` and `tests.noMatch` entries strictly by running the matcher without executing any shell command; if a rule fails its self-tests, only that rule SHALL be skipped while remaining valid rules still load (Decision 3).

#### Scenario: Rule failing tests is skipped individually
- **WHEN** a config source contains one rule whose `tests.match` does not match its own `match.prefix` (or whose `tests.noMatch` unexpectedly matches) alongside other valid rules
- **THEN** only the failing rule is skipped, a problem diagnostic is recorded, no command is executed, and the other valid rules remain active

### Requirement: Session-start warnings and status-bar problem counts
The connection layer SHALL list all detected configuration problems and emit a warning via `ctx.Notify(..., "warning")` at `session_start`, and SHALL display both the active rule count and the problem count in the status bar.

#### Scenario: Config problems reported at session_start and in status
- **WHEN** a session starts with a config source containing structural errors or rules failing self-tests
- **THEN** `session_start` notifies the user with level `"warning"` listing the problems, and the status bar reports accurate active-rule and problem counts

### Requirement: Per-call config re-reading
The extension SHALL re-read and validate configuration files on every `bash` `tool_call` so rule edits take effect immediately without restarting PiG.

#### Scenario: Edited config takes effect on next bash call
- **WHEN** a user modifies `.pig/command-policy.json` during an active session and invokes a `bash` tool call
- **THEN** the extension re-reads, validates, self-tests, and applies the updated configuration on that call
