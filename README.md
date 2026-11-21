# Project-local PiG configuration

> PiG is a derivative of pi, but pi does not read `.pig/`. The pi port of this
> configuration lives in `.pi/`; keep the two in sync when the policy changes.

This folder configures PiG for this project only. It ports the `permissions`
(Exec allow / deny) from `.devin/config.local.json`.

## Devin to PiG mapping

Devin's `Exec(<program>)` corresponds to PiG's `bash` tool call. PiG has no
declarative per-command permission setting, so a project extension intercepts
the `tool_call` event to reproduce the same behavior.

| Devin | PiG |
| --- | --- |
| `permissions.allow` | `allow` in `.pig/command-policy.json` |
| `permissions.deny` | `deny` in `.pig/command-policy.json` |
| Confirm for unlisted commands | `onUnlisted: "ask"` |

## Files

- `.pig/command-policy.json` — command names to allow and deny, and how to treat
  everything else.
- `.pig/extensions/command-policy/` — Go extension that applies the policy to
  the `bash` tool. Anything under `.pig/extensions` is loaded automatically.

Defaults (used when `command-policy.json` is missing or malformed):

- allow: `rg`, `find`, `cat`, `ls`, `sed`, `od`, `wc`, `grep`
- deny: `printf`, `echo`, `printenv`, `env`
- unlisted: `ask`

## Behavior

Before a `bash` command runs, the extension parses the command line and decides:

- Every program is on the allow list → run as-is.
- Any program is on the deny list → block and return the reason to the model.
- Neither → show a confirmation dialog and run only when approved. Without a
  UI, it fails closed and blocks.

Pipes, `&&`, `;`, command substitution `$(...)`, and backticks are all
inspected. `command` / `builtin` / `exec` / `nohup` / `nice` / `time` are
skipped transparently so the real program after them is checked. `env` is not
skipped: it is a deny target.

## Enabling it

Project configuration is read only after the project is trusted.

1. Start PiG in this folder and run `/trust` to trust the project.
2. Run `/reload` to apply it to a running session. Trust is evaluated at session
   start, so the first activation requires a restart.

`defaultProjectTrust` is read only from the global settings file
(`~/.pig/agent/settings.json`). We do not change it here.
