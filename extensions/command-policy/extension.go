// Package command_policy implements a project-local Pig extension that mirrors
// the Exec allow/deny policy from .devin/config.local.json.
//
// Devin:
//
//	permissions.allow: Exec(rg), Exec(find), Exec(cat), Exec(ls),
//	                   Exec(sed), Exec(od), Exec(wc), Exec(grep)
//	permissions.deny:  Exec(printf), Exec(echo), Exec(printenv), Exec(env)
//
// Pig has no declarative per-command permission setting, so this extension
// intercepts the `tool_call` event for the `bash` tool (Pig's equivalent of
// Devin's Exec) and applies three outcomes:
//
//   - a command whose program is allowlisted runs without confirmation;
//   - a command whose program is denylisted is blocked;
//   - anything else is confirmed interactively, and blocked when no UI exists.
//
// The lists and the unlisted-command behavior live in
// .pig/command-policy.json so the policy stays folder-local and editable
// without touching Go. Missing or malformed entries fall back to the defaults
// below.
package command_policy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"

	sdk "github.com/MichaelKinsy/PiG/extensions/sdk"
)

// defaultPolicy mirrors .devin/config.local.json.
var defaultPolicy = policy{
	Allow:      []string{"rg", "find", "cat", "ls", "sed", "od", "wc", "grep"},
	Deny:       []string{"printf", "echo", "printenv", "env"},
	OnUnlisted: "ask",
}

type policy struct {
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
	// OnUnlisted decides what happens to a command that is neither allowed nor
	// denied: "ask" (default), "allow", or "deny".
	OnUnlisted string `json:"onUnlisted"`
}

// transparentWrappers are leading words that re-dispatch to the command that
// follows, so the policy must inspect the word after them. `env` is
// deliberately absent: it is a denylisted program in its own right.
var transparentWrappers = map[string]bool{
	"command": true,
	"builtin": true,
	"exec":    true,
	"nohup":   true,
	"nice":    true,
	"time":    true,
}

func Extension() *sdk.Extension {
	e := sdk.New("command-policy")

	e.OnSessionStart(func(ctx sdk.Context, _ map[string]any) (any, error) {
		p := loadPolicy(ctx.Cwd())
		ctx.SetStatus("command-policy", "allow="+strings.Join(p.Allow, ",")+" deny="+strings.Join(p.Deny, ","))
		return nil, nil
	})

	e.OnEvent(sdk.EventToolCall, func(ctx sdk.Context, data map[string]any) (any, error) {
		if name, _ := data["toolName"].(string); name != "bash" {
			return nil, nil
		}
		command := bashCommand(data)
		if strings.TrimSpace(command) == "" {
			return nil, nil
		}

		p := loadPolicy(ctx.Cwd())
		switch p.evaluate(command) {
		case verdictAllow:
			return nil, nil
		case verdictDeny:
			reason := "command-policy: blocked by this project's Exec deny list: " + command
			ctx.Notify("command-policy blocked a denied command", "warn")
			return map[string]any{"block": true, "reason": reason}, nil
		default:
			if !ctx.HasUI() {
				return map[string]any{
					"block":  true,
					"reason": "command-policy: not on the allow list and no UI is available to confirm: " + command,
				}, nil
			}
			answer, err := ctx.Confirm("Run this non-allowlisted bash command?", command)
			if err != nil {
				return map[string]any{
					"block":  true,
					"reason": "command-policy: confirmation failed: " + err.Error(),
				}, nil
			}
			// RPC クライアントは confirmed に任意の JSON を返せるため、
			// bool 以外(nil 含む)はすべて拒否扱いにする。
			confirmed, _ := answer.(bool)
			if !confirmed {
				return map[string]any{"block": true, "reason": "command-policy: denied by operator: " + command}, nil
			}
			return nil, nil
		}
	})

	return e
}

// loadPolicy reads <cwd>/.pig/command-policy.json and overlays it on the
// built-in defaults. Any unreadable or invalid input keeps the defaults.
func loadPolicy(cwd string) policy {
	p := defaultPolicy
	if cwd == "" {
		return p
	}
	raw, err := os.ReadFile(filepath.Join(cwd, ".pig", "command-policy.json"))
	if err != nil {
		return p
	}
	var file policy
	if err := json.Unmarshal(raw, &file); err != nil {
		return p
	}
	if len(file.Allow) > 0 {
		p.Allow = file.Allow
	}
	if len(file.Deny) > 0 {
		p.Deny = file.Deny
	}
	switch file.OnUnlisted {
	case "ask", "allow", "deny":
		p.OnUnlisted = file.OnUnlisted
	}
	return p
}

type verdict int

const (
	verdictAllow verdict = iota
	verdictAsk
	verdictDeny
)

// evaluate classifies a whole shell command line. If any program in the line is
// denylisted the verdict is deny; if every program is allowlisted the verdict is
// allow; otherwise it defers to OnUnlisted.
func (p policy) evaluate(command string) verdict {
	names := commandNames(command)
	if len(names) == 0 {
		return verdictAllow
	}
	unlisted := false
	for _, name := range names {
		if contains(p.Deny, name) {
			return verdictDeny
		}
		if !contains(p.Allow, name) {
			unlisted = true
		}
	}
	if !unlisted {
		return verdictAllow
	}
	switch p.OnUnlisted {
	case "allow":
		return verdictAllow
	case "deny":
		return verdictDeny
	default:
		return verdictAsk
	}
}

// commandNames extracts the program name of every simple command in a shell
// line, so that pipes, lists, subshells, and command substitutions are all
// inspected. It is a best-effort parser, not a full shell grammar.
func commandNames(command string) []string {
	var names []string
	for _, segment := range splitSegments(command) {
		words := splitWords(segment)
		i := 0
		for i < len(words) && isAssignment(words[i]) {
			i++
		}
		for i < len(words) && transparentWrappers[words[i]] {
			i++
		}
		if i < len(words) {
			if name := commandName(words[i]); name != "" {
				names = append(names, name)
			}
		}
	}
	return names
}

// splitSegments breaks a command line at unquoted control operators. `&` is a
// separator unless it belongs to a redirection such as 2>&1.
func splitSegments(command string) []string {
	var (
		segments []string
		b        strings.Builder
		quote    rune
		escaped  bool
		prev     rune
	)
	flush := func() {
		if strings.TrimSpace(b.String()) != "" {
			segments = append(segments, b.String())
		}
		b.Reset()
	}
	for _, r := range command {
		if escaped {
			b.WriteRune(r)
			escaped = false
			prev = r
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
			}
			b.WriteRune(r)
			prev = r
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			b.WriteRune(r)
		case '\\':
			escaped = true
			b.WriteRune(r)
		case '|', ';', '(', ')', '`', '\n':
			flush()
		case '&':
			if prev != '>' && prev != '<' {
				flush()
			} else {
				b.WriteRune(r)
			}
		default:
			b.WriteRune(r)
		}
		prev = r
	}
	flush()
	return segments
}

// splitWords tokenizes one segment, honoring single quotes, double quotes, and
// backslash escapes. Quotes are removed from the resulting words.
func splitWords(segment string) []string {
	var (
		words   []string
		b       strings.Builder
		quote   rune
		escaped bool
		started bool
	)
	flush := func() {
		if started {
			words = append(words, b.String())
			b.Reset()
			started = false
		}
	}
	for _, r := range segment {
		if escaped {
			b.WriteRune(r)
			escaped = false
			started = true
			continue
		}
		if quote != 0 {
			if quote == '"' && r == '\\' {
				escaped = true
				continue
			}
			if r == quote {
				quote = 0
				continue
			}
			b.WriteRune(r)
			started = true
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			started = true
		case '\\':
			escaped = true
			started = true
		case ' ', '\t', '\r':
			flush()
		default:
			b.WriteRune(r)
			started = true
		}
	}
	flush()
	return words
}

// isAssignment reports whether w is a leading NAME=value environment
// assignment rather than a command.
func isAssignment(w string) bool {
	i := strings.IndexByte(w, '=')
	if i <= 0 {
		return false
	}
	for j, r := range w[:i] {
		switch {
		case r == '_':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case j > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

// commandName reduces a word to its program name, dropping quotes and any path.
func commandName(w string) string {
	w = strings.Trim(w, `"'`)
	if w == "" {
		return ""
	}
	if i := strings.LastIndexByte(w, '/'); i >= 0 {
		w = w[i+1:]
	}
	return w
}

// bashCommand pulls the shell command string out of the tool_call payload,
// tolerating the `input`/`args` naming used across Pi versions.
func bashCommand(data map[string]any) string {
	input, ok := data["input"].(map[string]any)
	if !ok {
		input, ok = data["args"].(map[string]any)
	}
	if !ok {
		return ""
	}
	command, _ := input["command"].(string)
	return command
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
