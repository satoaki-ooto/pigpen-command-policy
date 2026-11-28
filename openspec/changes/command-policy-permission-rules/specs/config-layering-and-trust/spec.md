# Spec Delta: config-layering-and-trust

## Purpose

Enforces workspace trust before reading project-local configuration, layers project, user, and built-in rule sources with deterministic override semantics, and protects built-in deny rules from being overridden or disabled.

## ADDED Requirements

### Requirement: Workspace trust gate for project configuration
The extension SHALL check `ctx.IsProjectTrusted()` at `session_start` and each `bash` `tool_call` without caching trust state. It SHALL read `<cwd>/.pig/command-policy.json` only when `cwd` is non-empty and `IsProjectTrusted()` returns `(true, nil)`; otherwise (empty `cwd`, `false`, or error) project config including project `deny`/`block` rules SHALL NOT be read.

#### Scenario: Empty cwd skips project config
- **WHEN** `ctx.Cwd()` returns `""`
- **THEN** `<cwd>/.pig/command-policy.json` is not read via a relative path and evaluation falls back to non-project policy

#### Scenario: Trusted project reads project config
- **WHEN** `ctx.Cwd()` is non-empty and `ctx.IsProjectTrusted()` returns `(true, nil)`
- **THEN** `<cwd>/.pig/command-policy.json` is loaded and participates in evaluation normally

### Requirement: Untrusted project notification and block behavior
When `ctx.IsProjectTrusted()` returns `false` or an error, the extension SHALL notify the user once at `session_start` via `ctx.Notify(..., "warning")` and SHALL block unmatched commands regardless of `onUnlisted` with the reason in the block `reason` rather than repeating `Notify` per `tool_call`.

#### Scenario: Untrusted project ignores project config and blocks unmatched commands
- **WHEN** `IsProjectTrusted()` returns `false` (or an error) and `<cwd>/.pig/command-policy.json` sets `onUnlisted: "allow"` (or defines project `allow`/`deny` rules)
- **THEN** project config has no effect, commands matching built-in or user rules (or `defaultPolicy` `Allow`/`Deny` in Stage 2 prior to Stage 3/5) follow their own decision, any unmatched command is blocked regardless of `onUnlisted`, and the user is notified once at `session_start` that project config was ignored

### Requirement: Three-tier config source layering
The judgment layer SHALL support three config sources—`project` (`<cwd>/.pig/command-policy.json` when trusted), `user` (`<ConfigHome>/command-policy.json` via `ctx.ConfigHome()`), and `builtin`—loaded in order `project` then `user`, without reading `~/.factory/settings.json` (Decision 4).

#### Scenario: User config loads from ConfigHome
- **WHEN** `ctx.ConfigHome()` returns a directory containing `command-policy.json`
- **THEN** the extension loads user rules from that file and layers them above `builtin` rules

### Requirement: Same-id override and enabled flag
When the same rule `id` appears in a higher layer (`project` > `user` > `builtin`), the higher layer SHALL override the lower layer's rule (unless protected), and setting `enabled: false` on that `id` SHALL disable the lower layer's non-protected rule.

#### Scenario: User overrides or disables a non-protected built-in rule
- **WHEN** the user config defines a rule with the same `id` as a non-protected built-in rule (or sets `enabled: false` for that `id`)
- **THEN** the user definition replaces or disables the built-in rule

### Requirement: Cross-id decision strength precedence
Across different rule `id`s, `block > ask > allow` SHALL always apply regardless of which layer defined each rule.

#### Scenario: Project allow cannot remove user block with different id
- **WHEN** a user rule blocks a command under one `id` and a trusted project rule allows it under a different `id`
- **THEN** the final decision remains `block`

### Requirement: Protected built-in deny rules
Built-in rules with `decision: "block"` (the default deny entries such as `echo`, `printenv`, `env`, `printf`) SHALL be protected so neither user nor project config can override them by the same `id` or disable them with `enabled: false`.

#### Scenario: User attempt to override or disable built-in echo deny rule
- **WHEN** the user config specifies the built-in `echo` rule's `id` with `decision: "allow"` or `enabled: false`
- **THEN** `echo hi` remains `block`
