# pigpen-command-policy

A [PiG](https://github.com/MichaelKinsy/PiG) extension package that enforces a per-project **allow / deny / confirm** policy on `bash` tool calls.

Run safe read-only commands without interruption, block disallowed commands outright, and prompt for confirmation before running anything else — all configured via a plain JSON file in each project.

> **Note:** This package is built with PiG's Go extension SDK and reads `.pig/command-policy.json`. It targets PiG rather than upstream Node/TypeScript Pi.

## Prerequisites

- [PiG](https://github.com/MichaelKinsy/PiG)
- A Go toolchain (1.26+) for PiG's first-use build of this extension. If Go is not installed on your machine, run `pig setup go`.

## Installation

### Global (recommended for personal use)

Install once for your user account. The extension will run in every PiG session and automatically read `.pig/command-policy.json` from the current project when present:

```sh
pig install git:github.com/satoaki-ooto/pigpen-command-policy
```

### Project-local (recommended for shared repositories)

Install into the current project's `.pig/settings.json`:

```sh
pig install --local git:github.com/satoaki-ooto/pigpen-command-policy
```

PiG only loads project-local packages after the project is trusted. Start PiG in the project directory and approve the startup trust prompt — or run `/trust` and restart PiG so the saved decision takes effect. For non-interactive runs (`pig -p`, JSON, or RPC mode), pass `--approve` if the project is not already trusted.

### Try without installing

From a local clone of this repository:

```sh
pig -e ./extensions/command-policy
```

### Update or remove

```sh
pig update git:github.com/satoaki-ooto/pigpen-command-policy
pig remove git:github.com/satoaki-ooto/pigpen-command-policy   # add --local if installed project-locally
```

## Configuration

Create `.pig/command-policy.json` in your project root to customize the policy for that repository. If the file does not exist, the built-in defaults apply automatically.

```json
{
  "allow": ["rg", "find", "cat", "ls", "sed", "od", "wc", "grep"],
  "deny": ["printf", "echo", "printenv", "env"],
  "onUnlisted": "ask"
}
```

### Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `allow` | `string[]` | `["rg", "find", "cat", "ls", "sed", "od", "wc", "grep"]` | Program basenames allowed to run without confirmation. |
| `deny` | `string[]` | `["printf", "echo", "printenv", "env"]` | Program basenames that are always blocked. |
| `onUnlisted` | `"ask" \| "allow" \| "deny"` | `"ask"` | Action to take when a command is in neither `allow` nor `deny`. |

### Configuration details

- **Live reload:** `.pig/command-policy.json` is read on every `bash` tool call, so edits take effect immediately without restarting PiG. (The status bar summary is populated on session start; run `/reload` or start a new session to refresh it.)
- **Status indicator:** On session start, PiG displays the active `allow` and `deny` lists in the status bar under `command-policy`.
- **Replace, not merge:** A non-empty `allow` or `deny` array replaces the corresponding default list rather than appending to it.
- **Fallback behavior:** If `.pig/command-policy.json` is missing or contains invalid JSON, all built-in defaults are used. Omitting a field, setting `allow` or `deny` to an empty array `[]`, or setting an unrecognized `onUnlisted` value falls back to that field's built-in default.

## How it works

Before PiG executes a `bash` tool call, the extension extracts every program name from the command line and evaluates them in this order:

1. **Any program is in `deny`** → Blocked immediately. A warning notification is shown and the reason is returned to the model. `deny` always takes precedence over `allow`.
2. **Every program is in `allow`** → Runs automatically without confirmation.
3. **At least one program is unlisted** → Follows `onUnlisted`:
   - `"ask"` (default): Shows a confirmation dialog (`Run this non-allowlisted bash command?`) with the full command. Runs only if approved. In headless / non-UI modes (such as `pig -p`, JSON, or RPC without a boolean approval), it **fails closed** and blocks the command.
   - `"allow"`: Runs without confirmation.
   - `"deny"`: Blocked immediately.

### Command parsing

The extension inspects compound commands, not just the first word:

- **Compound syntax:** Pipelines (`|`), lists (`&&`, `||`, `;`, `&`, newlines), subshells `(...)`, and command substitutions `$(...)` / `` `...` `` are all split and checked. Redirections like `2>&1` are preserved and not treated as separators.
- **Quotes:** Operators inside single or double quotes are ignored.
- **Assignments and paths:** Leading `VAR=value` assignments are skipped, and paths are reduced to their basename (`/usr/bin/ls` → `ls`).
- **Transparent wrappers:** `command`, `builtin`, `exec`, `nohup`, `nice`, and `time` are skipped so the program that follows is evaluated. `env` is **not** skipped — it is evaluated as `env` itself (and is denied by default).

Examples with the default policy:

| Command | Result | Why |
| --- | --- | --- |
| `rg foo \| wc -l && cat README.md` | Allow | All programs (`rg`, `wc`, `cat`) are in `allow` |
| `FOO=1 command /usr/bin/grep 'a\|echo' file` | Allow | Assignment, wrapper, path, and quoted `\|` are handled (`grep` is allowed) |
| `ls 2>&1` | Allow | Redirection `2>&1` is not a command separator |
| `cat $(printenv HOME)` | Deny | `printenv` inside `$(...)` is in `deny` |
| `nohup env` | Deny | `nohup` is skipped; `env` is in `deny` |
| `ls \| git log` | Ask | `git` is unlisted (`onUnlisted: "ask"`) |

## Limitations

- **Program names only:** Matching checks command basenames, not flags or arguments. For example, allowing `sed` or `find` allows any flags passed to them (such as `sed -i` or `find -exec`).
- **Best-effort parser, not a security sandbox:** Command extraction handles common shell constructs rather than a full POSIX/bash grammar (for example, substitutions inside double quotes, shell functions, or aliases are not expanded). Treat this extension as a workflow guardrail rather than an isolation boundary.
- **`bash` tool only:** Only PiG's `bash` tool is intercepted. Built-in file tools (`read`, `edit`, `write`, etc.), MCP tools, and Windows `powershell` calls are unaffected.

## Development

[mise](https://mise.jdx.dev/) pins the toolchain (Go, PiG) and runs the tasks in `mise.toml`. Go libraries are not managed by mise: they stay in each extension's `go.mod`, and the PiG SDK resolves to the copy PiG stages locally.

```sh
mise trust && mise install   # once per clone
mise run setup               # generate go.work (re-run after upgrading PiG)
mise run test                # go test; extra args pass through, e.g. `mise run test -run Evaluate -v`
mise run check               # lint + test + validate, what CI should run
mise run dev                 # start PiG here with this extension loaded
```

`setup` writes a git-ignored `go.work` that replaces the SDK import with PiG's staged SDK (`pig reload --sdk-path`), so `go build`, `go test`, and gopls work outside PiG. `validate` runs `pig install --validate-only --json .`, which builds and starts the extension as PiG does without changing any settings. `mise tasks ls` lists every task.
