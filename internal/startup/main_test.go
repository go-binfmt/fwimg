package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	got, err := parse([]string{"a=echo hi there", "b=true"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].label != "a" || strings.Join(got[0].argv, " ") != "echo hi there" || got[1].argv[0] != "true" {
		t.Fatalf("parse = %+v", got)
	}
	for _, bad := range [][]string{nil, {"noequals"}, {"=true"}, {"a="}} {
		if _, err := parse(bad); err == nil {
			t.Errorf("parse(%q) accepted", bad)
		}
	}
}

func TestRun(t *testing.T) {
	var w bytes.Buffer
	if err := run([]string{"-rounds", "3", "-cmd", "t=true", "-cmd", "e=echo x"}, &w); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"rounds: 3", "| t |", "| e |"} {
		if !strings.Contains(w.String(), want) {
			t.Errorf("output lacks %q:\n%s", want, w.String())
		}
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"-rounds", "0", "-cmd", "t=true"}, "-rounds must be at least 1"},
		{[]string{"-rounds", "1"}, "at least one -cmd"},
		{[]string{"-rounds", "1", "-cmd", "m=/nonexistent/binary"}, "m: "},
		{[]string{"-bogus", "-cmd", "t=true"}, "bogus"},
	} {
		err := run(c.args, &bytes.Buffer{})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("run(%q) = %v, want an error containing %q", c.args, err, c.want)
		}
	}
}

func TestTimeOne(t *testing.T) {
	d, _, err := timeOne([]string{"true"})
	if err != nil || d <= 0 {
		t.Fatalf("timeOne(true) = %v, %v", d, err)
	}
	if _, _, err := timeOne([]string{"false"}); err == nil || !strings.Contains(err.Error(), "exit status 1") {
		t.Errorf("timeOne(false) = %v, want exit status 1", err)
	}
}
