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
	for _, args := range [][]string{
		{"-rounds", "0", "-cmd", "t=true"},
		{"-rounds", "1"},
		{"-rounds", "1", "-cmd", "m=/nonexistent/binary"},
		{"-bogus"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("run(%q) succeeded", args)
		}
	}
}
