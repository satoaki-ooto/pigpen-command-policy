# AGENTS.md

Guidance for agents (and humans) working on this repository. Read this first.

## What this repository is

A [PiG](https://github.com/MichaelKinsy/PiG) extension (`command-policy`) that decides whether each `bash` tool call runs, is blocked, or asks for confirmation. The extension lives in `extensions/command-policy`. `README.md` describes the current user-facing behavior; it will change as the redesign below lands.

## Current work: permissionRules-style redesign

Work is tracked in one milestone, split into six stages. Each stage is one issue and has its own branch.

- Milestone: "command-policy: permissionRules-style rule format" (#1 on GitHub)
- Issues: #3 (Stage 1) to #8 (Stage 6)
- Branches (created from `main` and linked to the issues):

| Issue | Stage | Branch | Depends on |
| --- | --- | --- | --- |
| #3 | 1. Close deny bypass in command parsing | `fix/command-policy-stage-1-deny-bypass` | none |
| #4 | 2. Do not read project config in untrusted projects | `fix/command-policy-stage-2-untrusted-project` | none |
| #5 | 3. Judge commands by rule format | `feat/command-policy-stage-3-rule-format` | 1, 2 |
| #6 | 4. Self-test rules and warn on config errors | `feat/command-policy-stage-4-rule-self-test` | 3 |
| #7 | 5. Layer user config with protected built-in deny rules | `feat/command-policy-stage-5-user-config` | 3, 4 |
| #8 | 6. Add `/command-policy check` and status commands | `feat/command-policy-stage-6-slash-commands` | 3, 4, 5 |

Work on the issue's branch only. One PR per issue; the PR should close its issue. Do not combine stages.

The full design is not in the repository (the design document lives in an untracked `docs.local/` folder). The issue bodies are self-contained and are the source of truth for each stage. The settled decisions are summarized below so they are not re-opened by accident.

### Settled decisions

These come from the project owner. Change them only with the owner.

1. **Wrappers** (`env`, `sudo`, `timeout`, `xargs`, ...): for ask/block, match both with and without the stripped prefix. `env ls` is stopped too.
2. **Absolute paths**: for ask/block, match on basename. For allow, match on the original token, so `/tmp/x/ls` does not match the `ls` allow rule.
3. **Failing `tests`**: skip only that rule and show a warning.
4. **Config location**: pig-specific files only (`.pig/command-policy.json` for project, `command-policy.json` under `ctx.ConfigHome()` for user). Load order: project, then user. Decision strength is separate from load order. Droid's settings file is not read.
5. **No standalone CLI.** Only the PiG extension uses the judgment logic. `policy.go` and `shell.go` must not import the PiG SDK, so they can be split out later.
6. **Old `allow`/`deny` format is not read.** New format only.
7. **Trust**: if the project is trusted (`ctx.IsProjectTrusted()` is true), read the project config. If not trusted (false or error), do not read it. Built-in and user rules decide by their own decision. Anything unmatched is blocked, regardless of `onUnlisted`.
8. **Built-in deny rules are protected.** A user config cannot override them by the same `id`, and `enabled: false` does not disable them.
9. **Non-interactive mode**: `ask` cannot be confirmed, so it blocks. Nothing waits for input.

## Commands

All tasks are defined in `mise.toml`. Install the toolchain once with `mise trust && mise install`, then:

```sh
mise run setup    # generate go.work (git-ignored) so the PiG SDK resolves; re-run after upgrading PiG
mise run fmt      # gofmt -w extensions
mise run lint     # gofmt check and go vet
mise run test     # go test (alias: t); extra args pass through, e.g. `mise run test -run Evaluate -v`
mise run validate # pig install --validate-only --json . (does not change PiG settings)
mise run check    # lint + test + validate; run this before opening a PR
mise run dev      # pig -e ./extensions/command-policy
```

Run `mise run check` before every PR. Do not use `pig install` outside `--validate-only`. It changes the user's PiG settings.

## Coding rules

- A method is either a command (side effects, returns nothing) or a query (returns a value, no side effects). Not both.
- Prefer names over comments. Comments explain *why*, not *what*.
- Keep functions small: about 7 variables and about 7 branches as a guideline. When exceeded, use early returns, extract a function, or use a table.
- If you deviate from a guideline, leave a one-line comment at the deviation saying why.
- Mark deliberate simplifications with `// deliberate:` and name the ceiling and the upgrade path.
- Non-trivial logic gets one runnable check: a table test is the default.
- Do not add dependencies, abstractions, or files that were not asked for. Go libraries stay in each extension's `go.mod`.
- Validate input at trust boundaries. Fail closed: when the parser cannot determine the program name, the result must not be allow.

## Testing

- Keep existing tests passing. `TestEvaluate` and `TestEvaluateOnUnlisted` are the current baseline.
- Table tests for the parser and judgment should be readable as usage examples.
- When behavior differs from Droid's `permissionRules` on purpose, say so in a comment in the test.
- Droid results used as expected values come from `droid rules check --file <rules.json> --command '<cmd>' --json`.

## Git and PR conventions

- Commits: imperative subject line, then a body that explains why when it is not obvious.
- End commit messages with:
  `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`
- End PR descriptions with:
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`
- Branch prefixes in use: `feat/`, `fix/`, `docs/`, `chore/`.
- Never commit `.pig/` project settings, `.claude/settings.local.json`, or `go.work`.

## Known inconsistencies

- Go version: `mise.toml` pins `go = "1.27"`, `extensions/command-policy/go.mod` says `go 1.26`, and `README.md` says "1.26+". Decide one and align them before a release; do not change it silently inside a stage PR.
- `README.md` describes the current behavior (two lists plus `onUnlisted`). Update its Configuration, How it works, and Limitations sections in Stage 3, when the new format lands, not earlier.
