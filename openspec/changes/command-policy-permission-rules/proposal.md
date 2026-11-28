# Proposal: Port Droid-style `permissionRules` into `command-policy`

## Why

The current `command-policy` extension checks only the basename of the first word in each command segment against flat `allow` and `deny` lists, without checking workspace trust or validating configuration files. As a result, denied programs pass through behind shell keywords (`if`, `for`), brace groups (`{ }`), wrappers with flags (`nice -n`, `time -p`, `sudo`, `xargs`), and nested commands (`bash -c`, `eval`), allowed programs can still overwrite files via redirects (`cat a > b`), and untrusted repositories can weaken policy with `onUnlisted: "allow"`.

Replacing the flat-list format with a Droid-compatible `permissionRules` format (`id`, `decision`, `reason`, `match.prefix`, `tests`) closes these bypasses, explains why commands are stopped, surfaces config mistakes as warnings, and layers user configuration over protected built-in deny rules.

## What Changes

- **Shell command parsing (Stage 1, merged; extended in Stage 3)**: Strip shell reserved words and braces, recognize 11 command wrappers with bounded option tables, recursively inspect `bash`/`sh`/`zsh -c` and `eval` up to depth 8, fail closed on malformed syntax, and detect redirects and command substitutions.
- **Workspace trust gate (Stage 2)**: Read `<cwd>/.pig/command-policy.json` only when `ctx.IsProjectTrusted()` returns `true`. In untrusted projects, ignore project config, apply built-in (and later user) rules, block anything unmatched regardless of `onUnlisted`, and notify the user.
- **BREAKING — Rule-based judgment format (Stage 3)**: Replace the legacy `{allow, deny, onUnlisted}` format with `{version, onUnlisted, rules}` where each rule carries `id`, `decision` (`allow` / `ask` / `block`), `reason`, `match.prefix`, and `tests`. The legacy `allow`/`deny` list format is no longer read (accepted breaking change for 0.1.0). Restrict `allow` rules so they do not apply across redirects, command substitutions, wrappers, or basename-only absolute paths.
- **Self-testing and config diagnostics (Stage 4)**: Strictly decode config JSON (`DisallowUnknownFields`), drop a whole source on structural errors (missing required fields, invalid `decision`, duplicate `id`), skip individual rules whose `tests` fail without executing commands, emit `session_start` warnings, and display active rule and problem counts in the status bar.
- **User-level config layering and built-in deny protection (Stage 5)**: Load user rules from `<ConfigHome>/command-policy.json`, layer `project > user > builtin` by `id` with `enabled: false` support, apply `block > ask > allow` across different `id`s, and protect built-in `block` rules from user override or disabling.
- **Inspection slash commands (Stage 6)**: Add `/command-policy check <command>` (dry-run evaluation showing decision, deciding rule `id`/source, and all matched rules) and bare `/command-policy` (status of loaded sources, active rule count, disabled sources with reasons, and failing rules).

## Capabilities

### New Capabilities

- `shell-command-parsing`: Lexical splitting, shell keyword and brace stripping, 11-wrapper prefix parsing, depth-bounded `-c`/`eval` recursion, redirect and command-substitution detection, and fail-closed parse errors.
- `rule-evaluation`: Droid-compatible rule schema (`version`, `onUnlisted`, `rules`), positional `match.prefix` evaluation, `allow < ask < block` precedence, allow-condition restrictions, dual wrapper matching, absolute-path handling, and non-interactive mode behavior.
- `config-validation`: Strict JSON decoding, source-level structural error rejection, non-executing rule `tests` self-verification, `session_start` warning notifications, and status-bar diagnostics.
- `config-layering-and-trust`: Workspace trust enforcement via `IsProjectTrusted()`, three-tier source layering (`project`, `user`, `builtin`), same-`id` override and `enabled: false`, cross-`id` strength precedence, and immutable built-in deny protection.
- `policy-inspection-commands`: Read-only `/command-policy check <command>` and `/command-policy` status slash commands for inspecting decisions and loaded configuration.

### Modified Capabilities

<!-- None: this change establishes the initial OpenSpec capability baseline for command-policy. -->

## Impact

- **Code**: `extensions/command-policy/extension.go` (PiG SDK connection layer), plus new SDK-free files `extensions/command-policy/policy.go` and `extensions/command-policy/shell.go`, and table tests in `extensions/command-policy/extension_test.go`.
- **Docs**: `README.md` (Configuration, How it works, Limitations in Stage 3; slash commands in Stage 6).
- **Dependencies**: None added (`go.mod` and `mise.toml` unchanged).
- **Breaking change**: Existing `.pig/command-policy.json` files using the legacy `allow`/`deny` list format will stop taking effect in Stage 3 without automatic migration.
- **Explicit non-goals**: Droid's Org/Runtime/Folder layers, Droid's autonomy risk judgment, a standalone CLI, reading `~/.factory/settings.json`, full shell parsing (variable expansion, shell functions, aliases, here-doc bodies, script files, `find -exec`), and automatic legacy config conversion.
