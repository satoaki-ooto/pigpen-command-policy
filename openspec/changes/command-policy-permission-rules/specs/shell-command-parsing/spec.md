# Spec Delta: shell-command-parsing

## Purpose

Lexically parses bash command strings into executable segments and metadata so command-policy can evaluate shell syntax, wrappers, nested command strings, redirects, and substitutions while failing closed on malformed input.

## ADDED Requirements

### Requirement: Shell keyword and brace-group stripping
The lexical layer SHALL recognize segment-leading `if`, `then`, `elif`, `else`, `fi`, `for`, `while`, `until`, `do`, `done`, `{`, `}`, and `!` as shell syntax and inspect the effective commands inside them without treating keywords, braces, or `for` loop headers as programs.

#### Scenario: Denied program inside conditional or loop body
- **WHEN** a command line is `if true; then echo hi; fi`, `for i in 1; do printenv; done`, or `{ echo hi; }`
- **THEN** the lexical layer extracts `echo` or `printenv` as an effective command segment

#### Scenario: Loop variable matching a denied program name
- **WHEN** a command line is `for echo in 1; do ls; done`
- **THEN** the loop variable `echo` in the `for` header is not extracted as an executed program

### Requirement: Wrapper prefix stripping with bounded option tables
The lexical layer SHALL recognize leading `NAME=value` assignments and the 11 wrappers `command`, `builtin`, `exec`, `nohup`, `nice`, `time`, `sudo`, `doas`, `env`, `timeout`, and `xargs` (including absolute-path invocations), parse their documented execution-prefix options and operands, and emit both unstripped and stripped command forms.

#### Scenario: Wrapper with flags and operands
- **WHEN** a command line is `nice -n 5 echo hi`, `time -p printenv`, `sudo -u root echo hi`, `env -u FOO printenv`, `timeout 5 echo hi`, or `xargs -n 1 printenv`
- **THEN** the lexical layer strips the wrapper and its option/duration operands and exposes both the outer wrapper form and the inner command (`echo` or `printenv`)

#### Scenario: Bare xargs implies echo
- **WHEN** a command line invokes `xargs` with no explicit utility operand
- **THEN** the lexical layer exposes `echo` as the effective inner command

#### Scenario: Informational wrapper flags do not execute operands
- **WHEN** a command line invokes a wrapper with informational flags such as `--help`, `--version`, `command -v`, or `command -V`
- **THEN** the operands are not reported as executed inner programs

#### Scenario: Unknown wrapper option or missing operand fails closed
- **WHEN** a recognized wrapper receives an unlisted option, an unsupported combined short-option cluster, or a missing option/duration operand
- **THEN** the lexical layer returns a parse error instead of guessing the inner command

### Requirement: Depth-bounded recursive inspection of nested shells and eval
The lexical layer SHALL recursively parse the command-string operand of `bash -c`, `sh -c`, and `zsh -c` (including absolute-path shell invocations) and space-joined `eval` arguments, applying keyword, wrapper, and substitution extraction uniformly up to nesting depth 8.

#### Scenario: Nested shell or eval command within depth limit
- **WHEN** a command line is `bash -c 'echo hi'`, `sh -c 'printenv'`, `zsh -c 'echo hi'`, `eval 'echo hi'`, or `sudo bash -c 'nice -n 5 echo hi'` (up to 8 nested levels from depth 0)
- **THEN** the lexical layer recursively extracts the inner command segments (`echo`, `printenv`) while ignoring positional parameters after the `-c` command string

#### Scenario: Empty eval has no nested command
- **WHEN** a command line invokes bare `eval` with no arguments
- **THEN** the lexical layer succeeds without a parse error and emits no nested command

#### Scenario: Nesting depth exceeding 8 fails closed
- **WHEN** nested `-c` or `eval` command strings reach depth 9
- **THEN** the lexical layer returns a parse error

#### Scenario: Missing -c operand or ambiguous shell options fail closed
- **WHEN** a shell `-c` invocation is missing its command string or contains an unrecognized/ambiguous shell option sequence
- **THEN** the lexical layer returns a parse error

### Requirement: Malformed lexical syntax fails closed
The lexical layer SHALL distinguish malformed lexical input from valid input with no program and return a parse error on unterminated single/double quotes or incomplete backslash escapes, causing `tool_call` to return a Go error before bash executes.

#### Scenario: Unterminated quote or trailing escape
- **WHEN** a command line contains an unterminated single quote, unterminated double quote, or incomplete trailing backslash escape
- **THEN** the lexical layer returns a parse error and `tool_call` fails before executing bash

### Requirement: Redirect, command substitution, and wrapper metadata detection
The lexical layer SHALL record per-segment metadata indicating whether a segment contains a shell redirect (`>`, `>>`, `<`, `2>`, and similar), whether the command line contains a command substitution, and whether a wrapper was stripped.

#### Scenario: Output redirect detected on segment
- **WHEN** a command line is `cat a > b`
- **THEN** the lexical layer marks the `cat` segment as having a redirect

#### Scenario: Command substitution detected
- **WHEN** a command line contains `$(...)` or backtick command substitution
- **THEN** the lexical layer marks command substitution as present so allow rules are suppressed
