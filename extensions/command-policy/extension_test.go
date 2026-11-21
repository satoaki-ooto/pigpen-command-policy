package command_policy

import (
	"reflect"
	"testing"
)

func TestEvaluate(t *testing.T) {
	cases := []struct {
		command string
		want    verdict
	}{
		{"ls -la", verdictAllow},
		{"rg foo | wc -l && cat README.md", verdictAllow},
		{"FOO=1 command grep x file", verdictAllow},
		{"/usr/bin/ls", verdictAllow},
		{"ls 2>&1", verdictAllow},
		{"echo hi", verdictDeny},
		{"ls; env", verdictDeny},
		{"cat $(printenv HOME)", verdictDeny},
		{"ls `printf x`", verdictDeny},
		{"nohup env", verdictDeny},
		{"echo foo\\; ls", verdictDeny},
		{"grep 'a|echo' file", verdictAllow},
		{"git status", verdictAsk},
		{"ls | git log", verdictAsk},
	}
	for _, c := range cases {
		got, err := defaultPolicy.evaluate(c.command)
		if err != nil {
			t.Errorf("evaluate(%q) returned error: %v", c.command, err)
			continue
		}
		if got != c.want {
			t.Errorf("evaluate(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}

func TestEvaluateOnUnlisted(t *testing.T) {
	p := defaultPolicy
	p.OnUnlisted = "deny"
	got, err := p.evaluate("git status")
	if err != nil {
		t.Fatalf("evaluate returned error: %v", err)
	}
	if got != verdictDeny {
		t.Errorf(`onUnlisted "deny": got %v, want deny`, got)
	}
}

// Issue #10 reproduction rows: the deny lookup must see the program behind
// shell keywords and brace groups under every onUnlisted setting.
func TestEvaluateShellKeywordsDeny(t *testing.T) {
	cases := []string{
		"if true; then echo hi; fi",
		"for i in 1; do printenv; done",
		"{ echo hi; }",
		"! echo hi",
		"while true; do echo hi; done",
		"until printenv x; do ls; done",
		"if ls; then echo hi; else wc; fi",
		"for i do echo hi; done",
	}
	for _, onUnlisted := range []string{"ask", "allow", "deny"} {
		p := defaultPolicy
		p.OnUnlisted = onUnlisted
		for _, command := range cases {
			got, err := p.evaluate(command)
			if err != nil {
				t.Errorf("evaluate(%q) returned error: %v", command, err)
				continue
			}
			if got != verdictDeny {
				t.Errorf("evaluate(%q) with onUnlisted %q = %v, want deny", command, onUnlisted, got)
			}
		}
	}
}

// Reserved words, braces, and `for` headers are shell syntax rather than
// programs: they must not produce deny matches by themselves. A denylisted
// loop-variable name or `in` word is not a command.
func TestEvaluateShellKeywordsNoFalseDeny(t *testing.T) {
	cases := []struct {
		command string
		want    verdict
	}{
		{"for echo in 1; do ls; done", verdictAsk},
		{"for printenv in 1; do ls; done", verdictAsk},
		{"for echo do ls; done", verdictAsk},
		{"for i in echo printenv; do ls; done", verdictAsk},
		{"if ls; then wc; fi", verdictAsk},
		{"while ls; do wc; done", verdictAsk},
		{"{ ls; }", verdictAsk},
		{"! ls", verdictAsk},
	}
	for _, c := range cases {
		got, err := defaultPolicy.evaluate(c.command)
		if err != nil {
			t.Errorf("evaluate(%q) returned error: %v", c.command, err)
			continue
		}
		if got != c.want {
			t.Errorf("evaluate(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}

// onUnlisted "allow" must not widen: shell keywords keep a non-denied command
// on its previous unlisted-command flow.
func TestEvaluateOnUnlistedAllowKeywordCommands(t *testing.T) {
	p := defaultPolicy
	p.OnUnlisted = "allow"
	cases := []struct {
		command string
		want    verdict
	}{
		{"for echo in 1; do ls; done", verdictAllow},
		{"if ls; then wc; fi", verdictAllow},
		{"{ ls; }", verdictAllow},
		{"! ls", verdictAllow},
		{"git status", verdictAllow},
	}
	for _, c := range cases {
		got, err := p.evaluate(c.command)
		if err != nil {
			t.Errorf("evaluate(%q) returned error: %v", c.command, err)
			continue
		}
		if got != c.want {
			t.Errorf("evaluate(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}

// Unterminated quotes and incomplete backslash escapes are lexical errors:
// evaluate must return an error instead of an allow/ask/deny verdict. The
// tool_call handler turns that error into an error result before execution.
func TestEvaluateMalformed(t *testing.T) {
	cases := []string{
		"echo 'unterminated",
		`echo "unterminated`,
		"echo 'foo; ls",
		`echo "a\"`,
		"ls \\",
	}
	for _, command := range cases {
		if got, err := defaultPolicy.evaluate(command); err == nil {
			t.Errorf("evaluate(%q) = %v, want parse error", command, got)
		}
	}
}

func TestDenyCandidates(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{"ls", []string{"ls"}},
		{"if true; then echo hi; fi", []string{"true", "echo"}},
		{"for i in 1; do printenv; done", []string{"printenv"}},
		{"for echo in 1; do ls; done", []string{"ls"}},
		{"for i in echo printenv; do ls; done", []string{"ls"}},
		{"{ echo hi; }", []string{"echo"}},
		{"! echo hi", []string{"echo"}},
	}
	for _, c := range cases {
		got, err := denyCandidates(c.command)
		if err != nil {
			t.Errorf("denyCandidates(%q) returned error: %v", c.command, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("denyCandidates(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}
