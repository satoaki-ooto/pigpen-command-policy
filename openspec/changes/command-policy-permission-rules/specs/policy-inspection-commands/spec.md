# Spec Delta: policy-inspection-commands

## Purpose

Provides read-only slash commands so users can dry-run command-policy evaluation and inspect loaded configuration sources, active rule counts, disabled sources, and failing rules without executing any shell command.

## ADDED Requirements

### Requirement: Dry-run command check slash command
The extension SHALL register `/command-policy check <command>` to evaluate `<command>` without executing it and print the final decision, the deciding rule's `id` and source (`project`, `user`, or `builtin`), and all rules that matched.

#### Scenario: Checking a blocked command
- **WHEN** a user runs `/command-policy check echo hi`
- **THEN** the command prints decision `block`, the deciding rule's `id`, its source (`builtin`), and all matched rules without executing `echo hi`

#### Scenario: Checking an allowed command
- **WHEN** a user runs `/command-policy check ls`
- **THEN** the command prints decision `allow` and the matching rule details without executing `ls`

### Requirement: Policy status slash command
The extension SHALL handle bare `/command-policy` (with no arguments) by printing all loaded config sources, the active rule count, any disabled or rejected sources with reasons (such as untrusted project or structural error), and any rules skipped for failing `tests`.

#### Scenario: Inspecting policy status with untrusted project or failing rules
- **WHEN** a user runs `/command-policy` with no arguments
- **THEN** the output lists loaded sources, the active rule count, disabled sources with their reasons, and any rules that failed self-tests
