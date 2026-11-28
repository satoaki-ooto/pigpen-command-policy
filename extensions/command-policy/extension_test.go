package command_policy

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
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
		{"ls | for", verdictAsk},
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
		// A `for` header cut short by the segment end must not push the
		// candidate index past the last word.
		{"for", nil},
		{"for x", nil},
		{"ls | for", []string{"ls"}},
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

// Issue #11 reproduction rows: wrapper flags and wrapper programs must not
// hide a denylisted program, under every onUnlisted setting.
func TestEvaluateWrappersDeny(t *testing.T) {
	cases := []string{
		"nice -n 5 echo hi",
		"time -p printenv",
		"sudo echo hi",
		"xargs echo < f",
		"env ls",
		"/usr/bin/env",
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

// Every wrapper family must reach the denylisted program behind it, including
// absolute-path invocation, leading assignments, and value-taking options.
func TestEvaluateWrapperFamiliesDeny(t *testing.T) {
	cases := []string{
		"command echo hi",
		"command -p echo hi",
		"command -- echo hi",
		"builtin echo hi",
		"builtin -- echo hi",
		"exec echo hi",
		"exec -c echo hi",
		"exec -l echo hi",
		"exec -a name echo hi",
		"nohup echo hi",
		"nohup -- echo hi",
		"nice echo hi",
		"nice -n 5 echo hi",
		"nice --adjustment=5 echo hi",
		"nice -5 echo hi",
		"time echo hi",
		"time -p echo hi",
		"sudo echo hi",
		"sudo -n echo hi",
		"sudo -E echo hi",
		"sudo -u root echo hi",
		"sudo -u root -g wheel echo hi",
		"sudo -p prompt echo hi",
		"sudo -- echo hi",
		"doas echo hi",
		"doas -n echo hi",
		"doas -u root echo hi",
		"doas -C /etc/doas.conf echo hi",
		"env echo hi",
		"env -i echo hi",
		"env --ignore-environment echo hi",
		"env -u FOO echo hi",
		"env --unset=FOO echo hi",
		"env -C /tmp echo hi",
		"env --chdir=/tmp echo hi",
		"env FOO=1 echo hi",
		"env -- echo hi",
		"timeout 5 echo hi",
		"timeout -k 2 5 echo hi",
		"timeout --kill-after=2 -s KILL 5 echo hi",
		"timeout --preserve-status 5 echo hi",
		"timeout --foreground 5 echo hi",
		"timeout -- 5 echo hi",
		"timeout 5 sudo echo hi",
		"xargs echo hi",
		"xargs -n 1 echo hi",
		"xargs -0 -r echo hi",
		"xargs -I {} echo hi",
		"xargs --max-args=1 echo hi",
		"xargs",
		"xargs -r",
		"xargs < f",
		"xargs >/dev/null",
		"xargs 2>&1",
		"/usr/bin/sudo echo hi",
		"/usr/bin/env printenv",
		"/usr/bin/xargs echo hi",
		"FOO=1 sudo echo hi",
		"FOO=1 env printenv",
		"sudo env printenv",
	}
	for _, command := range cases {
		got, err := defaultPolicy.evaluate(command)
		if err != nil {
			t.Errorf("evaluate(%q) returned error: %v", command, err)
			continue
		}
		if got != verdictDeny {
			t.Errorf("evaluate(%q) = %v, want deny", command, got)
		}
	}
}

// Informational forms execute nothing behind them: --help, --version, and
// command -v/-V keep their operands off the deny path.
func TestEvaluateInformationalForms(t *testing.T) {
	cases := []string{
		"sudo --help",
		"sudo --version",
		"doas --help",
		"nice --help",
		"time --version",
		"xargs --help",
		"command -v echo",
		"command -V printenv",
	}
	for _, command := range cases {
		got, err := defaultPolicy.evaluate(command)
		if err != nil {
			t.Errorf("evaluate(%q) returned error: %v", command, err)
			continue
		}
		if got != verdictAsk {
			t.Errorf("evaluate(%q) = %v, want ask", command, got)
		}
	}
}

// Wrapper allow/ask behavior is untouched: only the deny path strips wrappers
// with their options, so sudo ls and xargs ls stay unlisted instead of
// inheriting the verdict of the command behind them.
func TestEvaluateWrappersPreserveNonDeny(t *testing.T) {
	cases := []struct {
		command string
		want    verdict
	}{
		{"FOO=1 command grep x file", verdictAllow},
		{"sudo ls", verdictAsk},
		{"xargs ls", verdictAsk},
		{"doas ls", verdictAsk},
		{"timeout 5 ls", verdictAsk},
		{"nice -n 5 ls", verdictAsk},
		{"time -p ls", verdictAsk},
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

// Unknown wrapper options, unsupported combined short-option clusters, and
// missing option/duration operands are parse errors, so the tool_call stops
// before bash can interpret the prefix itself.
func TestEvaluateWrapperParseErrors(t *testing.T) {
	cases := []string{
		"sudo --bogus ls",
		"sudo -Z ls",
		"sudo -uroot ls",
		"sudo -nH ls",
		"sudo -u",
		"sudo -g",
		"doas -q ls",
		"doas -u",
		"doas -C",
		"env --posix ls",
		"env --unset FOO ls",
		"env -u",
		"env -C",
		"nice -q ls",
		"nice -n",
		"nice -n5 ls",
		"nice --adjustment 5 ls",
		"exec -x ls",
		"exec -a",
		"time -v ls",
		"time --verbose ls",
		"command -x ls",
		"command -px ls",
		"builtin -x ls",
		"nohup -x ls",
		"timeout -v ls",
		"timeout -k",
		"timeout -s",
		"timeout",
		"timeout 5",
		"timeout --kill-after 2 5 ls",
		"xargs -x ls",
		"xargs -n",
		"xargs -I",
	}
	for _, command := range cases {
		if got, err := defaultPolicy.evaluate(command); err == nil {
			t.Errorf("evaluate(%q) = %v, want parse error", command, got)
		}
	}
}

func TestDenyCandidatesWrappers(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{"env ls", []string{"env", "ls"}},
		{"/usr/bin/env", []string{"env"}},
		{"sudo echo hi", []string{"sudo", "echo"}},
		{"sudo -u root echo hi", []string{"sudo", "echo"}},
		{"env -u FOO printenv", []string{"env", "printenv"}},
		{"env FOO=1 printenv", []string{"env", "printenv"}},
		{"timeout 5 echo hi", []string{"timeout", "echo"}},
		{"timeout 5 sudo echo hi", []string{"timeout", "sudo", "echo"}},
		{"timeout -- 5 echo hi", []string{"timeout", "echo"}},
		{"xargs -n 1 printenv", []string{"xargs", "printenv"}},
		{"xargs", []string{"xargs", "echo"}},
		{"xargs -0", []string{"xargs", "echo"}},
		{"xargs < f", []string{"xargs", "echo"}},
		{"xargs >/dev/null", []string{"xargs", "echo"}},
		{"xargs 2>&1", []string{"xargs", "echo"}},
		{"xargs echo < f", []string{"xargs", "echo"}},
		{"sudo env ls", []string{"sudo", "env", "ls"}},
		{"nohup env", []string{"nohup", "env"}},
		{"nice -n 5 echo hi", []string{"nice", "echo"}},
		{"nice -5 ls", []string{"nice", "ls"}},
		{"time -p printenv", []string{"time", "printenv"}},
		{"exec -a foo echo hi", []string{"exec", "echo"}},
		{"FOO=1 command grep x file", []string{"command", "grep"}},
		{"command -v echo", []string{"command"}},
		{"sudo --help ls", []string{"sudo"}},
		{"env --version printenv", []string{"env"}},
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

func TestDenyCandidatesWrapperErrors(t *testing.T) {
	cases := []string{
		"sudo --bogus ls",
		"sudo -u",
		"sudo -uroot ls",
		"sudo -nH ls",
		"env --unset FOO ls",
		"nice -n",
		"timeout",
		"timeout 5",
		"xargs -n",
		"time -v ls",
		"exec -x ls",
		"command -px ls",
	}
	for _, command := range cases {
		if got, err := denyCandidates(command); err == nil {
			t.Errorf("denyCandidates(%q) = %v, want parse error", command, got)
		}
	}
}

// Issue #12 reproduction row plus equivalent shell and eval cases: the deny
// lookup must reach the program inside the command string of bash/sh/zsh -c
// and of eval, behind wrappers and keywords, under every onUnlisted setting.
func TestEvaluateNestedShellsDeny(t *testing.T) {
	cases := []string{
		"bash -c 'echo hi'",
		"sh -c 'printenv'",
		"zsh -c 'echo hi'",
		"/bin/bash -c 'echo hi'",
		"/usr/bin/zsh -c 'echo hi'",
		// Without quotes the command string is only the next word; hi is $0.
		"bash -c echo hi",
		"eval 'echo hi'",
		"eval echo hi",
		"eval 'echo' 'hi'",
		"sudo bash -c 'nice -n 5 echo hi'",
		"env bash -c 'echo hi'",
		"timeout 5 sh -c 'printenv'",
		"xargs bash -c 'echo hi'",
		"command bash -c 'echo hi'",
		"FOO=1 bash -c 'echo hi'",
		"if true; then bash -c 'echo hi'; fi",
		"bash -c 'bash -c \"echo hi\"'",
		"bash -c 'cat $(printenv HOME)'",
		"bash -xc 'echo hi'",
		"bash -lc 'echo hi'",
		"bash -li -c 'echo hi'",
		"bash -o errexit -c 'echo hi'",
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

// Nested inspection is deny-only: an allowed nested command must not widen
// the verdict, the outer shell or eval stays judged by its own name, and
// forms that execute nothing nested keep their outer flow. With
// onUnlisted "allow" the outer unlisted shell behaves as before the feature.
func TestEvaluateNestedShellsPreserveNonDeny(t *testing.T) {
	defaultCases := []struct {
		command string
		want    verdict
	}{
		{"bash -c 'ls'", verdictAsk},
		{"eval 'ls'", verdictAsk},
		{"bash -c 'git push'", verdictAsk},
		{"eval 'git status'", verdictAsk},
		{"bash", verdictAsk},
		{"sh", verdictAsk},
		{"zsh", verdictAsk},
		{"eval", verdictAsk},
		// Script files stay unexamined in Stage 1.
		{"bash script.sh", verdictAsk},
		{"/bin/bash /tmp/x.sh", verdictAsk},
		// Informational forms execute nothing nested, so echo never runs.
		{"bash --version", verdictAsk},
		{"bash --version -c 'echo hi'", verdictAsk},
		// Empty command strings and bare eval run nothing and are not errors.
		{"bash -c ''", verdictAsk},
		{"eval ''", verdictAsk},
		// Operands after the command string are positional parameters.
		{"bash -c 'ls' arg0 arg1", verdictAsk},
	}
	for _, c := range defaultCases {
		got, err := defaultPolicy.evaluate(c.command)
		if err != nil {
			t.Errorf("evaluate(%q) returned error: %v", c.command, err)
			continue
		}
		if got != c.want {
			t.Errorf("evaluate(%q) = %v, want %v", c.command, got, c.want)
		}
	}

	p := defaultPolicy
	p.OnUnlisted = "allow"
	allowCases := []struct {
		command string
		want    verdict
	}{
		{"bash -c 'ls'", verdictAllow},
		{"eval 'ls'", verdictAllow},
	}
	for _, c := range allowCases {
		got, err := p.evaluate(c.command)
		if err != nil {
			t.Errorf("evaluate(%q) returned error: %v", c.command, err)
			continue
		}
		if got != c.want {
			t.Errorf("evaluate(%q) with onUnlisted allow = %v, want %v", c.command, got, c.want)
		}
	}
}

// Missing -c command strings, malformed nested quoting or escaping, and
// ambiguous or unsupported shell option sequences are parse errors, so the
// tool_call stops before bash interprets the nested string itself.
func TestEvaluateNestedParseErrors(t *testing.T) {
	cases := []string{
		"bash -c",
		"sh -c",
		"zsh -c",
		"sudo bash -c",
		"bash -c 'echo \"hi'",
		"eval 'echo \"hi'",
		"bash -c 'echo \\'",
		"bash -cx 'echo hi'",
		"bash -Q -c 'echo hi'",
		"bash --rcfile f -c 'echo hi'",
		"bash +x -c 'echo hi'",
		"bash -o",
	}
	for _, command := range cases {
		if got, err := defaultPolicy.evaluate(command); err == nil {
			t.Errorf("evaluate(%q) = %v, want parse error", command, got)
		}
	}
}

func TestDenyCandidatesNested(t *testing.T) {
	cases := []struct {
		command string
		want    []string
	}{
		{"bash -c 'echo hi'", []string{"bash", "echo"}},
		{"sh -c 'printenv'", []string{"sh", "printenv"}},
		{"zsh -c 'echo hi'", []string{"zsh", "echo"}},
		{"/bin/bash -c 'echo hi'", []string{"bash", "echo"}},
		{"bash -c echo hi", []string{"bash", "echo"}},
		{"eval 'echo hi'", []string{"eval", "echo"}},
		// eval joins its arguments with single spaces before judging them.
		{"eval echo hi", []string{"eval", "echo"}},
		{"eval 'echo' 'hi'", []string{"eval", "echo"}},
		{"eval 'echo' ';printenv'", []string{"eval", "echo", "printenv"}},
		{"eval", []string{"eval"}},
		{"eval ''", []string{"eval"}},
		{"bash", []string{"bash"}},
		{"bash script.sh", []string{"bash"}},
		{"bash -li", []string{"bash"}},
		{"bash -c ''", []string{"bash"}},
		{"bash -c 'ls' arg0 arg1", []string{"bash", "ls"}},
		{"sudo bash -c 'nice -n 5 echo hi'", []string{"sudo", "bash", "nice", "echo"}},
		{"env bash -c 'echo hi'", []string{"env", "bash", "echo"}},
		{"xargs bash -c 'echo hi'", []string{"xargs", "bash", "echo"}},
		{"timeout 5 sh -c 'printenv'", []string{"timeout", "sh", "printenv"}},
		{"command bash -c 'echo hi'", []string{"command", "bash", "echo"}},
		{"FOO=1 bash -c 'echo hi'", []string{"bash", "echo"}},
		{"bash -c 'if true; then printenv; fi'", []string{"bash", "true", "printenv"}},
		{"bash -c 'cat $(printenv HOME)'", []string{"bash", "cat", "printenv"}},
		{"bash -c 'exec printenv'", []string{"bash", "exec", "printenv"}},
		{"bash -c 'env ls'", []string{"bash", "env", "ls"}},
		{"bash --version", []string{"bash"}},
		{"bash --version -c 'echo hi'", []string{"bash"}},
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

func TestDenyCandidatesNestedErrors(t *testing.T) {
	cases := []string{
		"bash -c",
		"sh -c",
		"zsh -c",
		"sudo bash -c",
		"bash -c 'echo \"hi'",
		"eval 'echo \"hi'",
		"bash -c 'echo \\'",
		"bash -cx 'echo hi'",
		"bash -Q -c 'echo hi'",
		"bash --rcfile f -c 'echo hi'",
		"bash +x -c 'echo hi'",
		"bash -o",
	}
	for _, command := range cases {
		if got, err := denyCandidates(command); err == nil {
			t.Errorf("denyCandidates(%q) = %v, want parse error", command, got)
		}
	}
}

// Eight nested -c / eval command strings are analyzed; the ninth is a parse
// error instead of an unbounded recursion.
func TestEvaluateNestedDepthLimit(t *testing.T) {
	wraps := []struct {
		name string
		wrap func(string) string
	}{
		{"eval", func(s string) string { return "eval " + s }},
		{"bash -c", func(s string) string { return "bash -c " + strconv.Quote(s) }},
	}
	for _, w := range wraps {
		for n := 1; n <= nestedDepthLimit; n++ {
			cmd := "printenv"
			for i := 0; i < n; i++ {
				cmd = w.wrap(cmd)
			}
			got, err := defaultPolicy.evaluate(cmd)
			if err != nil {
				t.Errorf("evaluate(%s nested %d) returned error: %v", w.name, n, err)
				continue
			}
			if got != verdictDeny {
				t.Errorf("evaluate(%s nested %d) = %v, want deny", w.name, n, got)
			}
		}
		for _, n := range []int{nestedDepthLimit + 1, nestedDepthLimit + 2} {
			cmd := "printenv"
			for i := 0; i < n; i++ {
				cmd = w.wrap(cmd)
			}
			if got, err := defaultPolicy.evaluate(cmd); err == nil {
				t.Errorf("evaluate(%s nested %d) = %v, want parse error", w.name, n, got)
			}
		}
	}
}

// Issue #19: the project config is read only when the cwd is known and the
// workspace is trusted. Untrusted, a failed trust check (with either bool
// value), and an empty cwd all keep the built-in defaults, so a cloned repo's
// .pig/command-policy.json cannot loosen the policy before the user trusts
// the project.
func TestPolicyForTrustGate(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".pig"), 0o755); err != nil {
		t.Fatal(err)
	}
	config := []byte(`{"allow": ["projectcmd"], "onUnlisted": "deny"}`)
	if err := os.WriteFile(filepath.Join(dir, ".pig", "command-policy.json"), config, 0o644); err != nil {
		t.Fatal(err)
	}

	projectApplied := defaultPolicy
	projectApplied.Allow = []string{"projectcmd"}
	projectApplied.OnUnlisted = "deny"

	trustErr := errors.New("host unreachable")
	cases := []struct {
		name     string
		cwd      string
		trusted  bool
		trustErr error
		chdir    bool // run from dir so a relative .pig/ read would hit the fixture
		want     policy
	}{
		{"trusted project reads config", dir, true, nil, false, projectApplied},
		{"untrusted project skips config", dir, false, nil, false, defaultPolicy},
		{"trust error skips config", dir, true, trustErr, false, defaultPolicy},
		{"untrusted trust error skips config", dir, false, trustErr, false, defaultPolicy},
		{"empty cwd skips config", "", true, nil, true, defaultPolicy},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.chdir {
				t.Chdir(dir)
			}
			got := policyFor(c.cwd, c.trusted, c.trustErr)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("policyFor(%q, %v, %v) = %+v, want %+v", c.cwd, c.trusted, c.trustErr, got, c.want)
			}
		})
	}
}
