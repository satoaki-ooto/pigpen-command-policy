# Spec Delta: rule-evaluation

## Purpose

Evaluates parsed bash command segments against Droid-compatible permission rules (`version`, `onUnlisted`, `rules`) using positional prefix matching, decision strength precedence, strict allow conditions, and non-interactive fallback rules.

## ADDED Requirements

### Requirement: Droid-compatible rule file format
The judgment layer SHALL read rule configurations in the JSON shape `{"version": 1, "onUnlisted": "<decision>", "rules": [...]}` where each rule defines `id`, `decision` (`allow`, `ask`, or `block`), `reason`, `match.prefix`, and optional `enabled` and `tests` (`match`, `noMatch`).

#### Scenario: Valid rule file loads and evaluates
- **WHEN** a config file defines `version: 1`, `onUnlisted: "ask"`, and a rule with `id: "project/git-push"`, `decision: "ask"`, `reason`, and `match.prefix: ["git", "push"]`
- **THEN** `git push origin main` matches that rule and yields decision `ask` with its `id` and `reason`

#### Scenario: Legacy allow/deny list format is not read
- **WHEN** a config file uses the legacy `{"allow": [...], "deny": [...], "onUnlisted": "..."}` format
- **THEN** the judgment layer does not load it as a valid rule configuration and its legacy entries have no effect

### Requirement: Positional prefix matching with alternatives
The judgment layer SHALL match `match.prefix` position by position against a segment's tokens, where a string entry matches an exact token and an array entry matches any string in the array.

#### Scenario: Alternative subcommand matching
- **WHEN** a rule has `match.prefix: ["git", ["push", "pull"]]`
- **THEN** both `git push origin main` and `git pull` match the rule, while `git status` does not match

### Requirement: Decision strength precedence and onUnlisted fallback
The judgment layer SHALL order decisions as `allow < ask < block`, select the strongest matching rule per segment, include `onUnlisted` if any segment matches no rule, and return the strongest decision across all segments along with the deciding rule's `id`, `reason`, and source.

#### Scenario: Strongest decision wins across segments
- **WHEN** a command line has one segment matching an `allow` rule and another segment matching a `block` rule
- **THEN** the final decision is `block` with the blocking rule's `id` and `reason`

#### Scenario: Unmatched segment includes onUnlisted
- **WHEN** one segment matches `allow` and another segment matches no rule while `onUnlisted` is `ask`
- **THEN** the final decision is `ask`

### Requirement: Dual wrapper matching for ask and block
For `ask` and `block` rules, the judgment layer SHALL match against both the unstripped segment and the wrapper-stripped segment (Decision 1), so bare wrappers such as `env` and wrapped commands such as `env ls` or `sudo echo hi` are both caught.

#### Scenario: Bare env and wrapped env both match env block rule
- **WHEN** a built-in `block` rule has `match.prefix: ["env"]` and the command is `env` or `env ls`
- **THEN** the judgment layer matches the `env` block rule and returns `block` (intentional stricter divergence from Droid 1.12.1)

#### Scenario: Wrapped denied command matches inner block rule
- **WHEN** a `block` rule has `match.prefix: ["echo"]` and the command is `env echo hi`, `nice -n 5 echo hi`, `time -p echo hi`, or `sudo echo hi`
- **THEN** the judgment layer matches the `echo` block rule and returns `block`

### Requirement: Absolute-path matching asymmetry
For `ask` and `block` rules, the judgment layer SHALL match the first token by its basename, whereas for `allow` rules it SHALL match the original token without basename reduction (Decision 2).

#### Scenario: Absolute-path denied binary is blocked
- **WHEN** a `block` rule has `match.prefix: ["env"]` and the command is `/usr/bin/env`
- **THEN** the judgment layer matches on basename `env` and returns `block` (intentional stricter divergence from Droid 1.12.1)

#### Scenario: Absolute-path binary does not match bare allow rule
- **WHEN** an `allow` rule has `match.prefix: ["ls"]` and the command is `/tmp/x/ls` or `/usr/bin/ls`
- **THEN** the `allow` rule does not match and the segment falls back to `onUnlisted`

### Requirement: Allow-condition restrictions
The judgment layer SHALL NOT apply an `allow` rule to a segment when the segment contains a redirect, when the command line contains a command substitution, or when a wrapper is present on the segment.

#### Scenario: Redirect suppresses allow rule
- **WHEN** an `allow` rule has `match.prefix: ["cat"]` and the command is `cat a > b`
- **THEN** the `allow` rule does not apply and the command falls back to `onUnlisted`

#### Scenario: Wrapper suppresses allow rule
- **WHEN** an `allow` rule has `match.prefix: ["ls"]` and the command is `sudo ls` or `xargs ls`
- **THEN** the `allow` rule does not apply

### Requirement: Interactive confirmation and non-interactive blocking
The connection layer SHALL pass `allow` commands through, stop `block` commands with the rule's `reason`, prompt via `ctx.Confirm` for `ask` when UI is available (proceeding only on bool `true`), and block `ask` commands without waiting when running non-interactively.

#### Scenario: Non-interactive ask blocks immediately
- **WHEN** evaluation returns `ask` and no UI is available
- **THEN** the connection layer blocks the command with the reason without waiting for input

#### Scenario: Interactive ask proceeds only on explicit true
- **WHEN** evaluation returns `ask` with UI available and `ctx.Confirm` returns `false` or an error
- **THEN** the connection layer blocks the command
