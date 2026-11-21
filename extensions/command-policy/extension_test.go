package command_policy

import "testing"

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
		{"grep 'a|echo' file", verdictAllow},
		{"git status", verdictAsk},
		{"ls | git log", verdictAsk},
	}
	for _, c := range cases {
		if got := defaultPolicy.evaluate(c.command); got != c.want {
			t.Errorf("evaluate(%q) = %v, want %v", c.command, got, c.want)
		}
	}
}

func TestEvaluateOnUnlisted(t *testing.T) {
	p := defaultPolicy
	p.OnUnlisted = "deny"
	if got := p.evaluate("git status"); got != verdictDeny {
		t.Errorf(`onUnlisted "deny": got %v, want deny`, got)
	}
}
