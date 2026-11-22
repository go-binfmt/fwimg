package main

import (
	"bytes"
	"os"
	"testing"
)

func TestRootCmdDoesNothing(t *testing.T) {
	var out, errb bytes.Buffer
	c := RootCmd()
	c.SetOut(&out)
	c.SetErr(&errb)
	c.SetArgs(nil)
	if err := c.Execute(); err != nil {
		t.Fatal(err)
	}
	if out.Len() != 0 || errb.Len() != 0 {
		t.Errorf("printed %q %q", out.String(), errb.String())
	}
}

// A build tag may install work; it runs with exactly two arguments, its error
// fails the command, and any other argument count leaves it alone.
func TestWork(t *testing.T) {
	old := work
	defer func() { work = old }()
	var got [][2]string
	var fail error
	work = func(in, out string) error { got = append(got, [2]string{in, out}); return fail }
	run := func(args ...string) error {
		c := RootCmd()
		c.SetOut(&bytes.Buffer{})
		c.SetErr(&bytes.Buffer{})
		c.SetArgs(args)
		return c.Execute()
	}
	if err := run("a", "b"); err != nil || len(got) != 1 || got[0] != [2]string{"a", "b"} {
		t.Fatalf("two arguments: err %v, calls %v", err, got)
	}
	if err := run("a"); err != nil || len(got) != 1 {
		t.Errorf("one argument: err %v, calls %v", err, got)
	}
	fail = os.ErrInvalid
	if err := run("a", "b"); err != os.ErrInvalid {
		t.Errorf("failing work: err = %v", err)
	}
}

func TestMain_(t *testing.T) {
	old, oldExit := os.Args, osExit
	defer func() { os.Args, osExit = old, oldExit }()
	code := -1
	osExit = func(c int) { code = c }
	os.Args = []string{"cobraonly"}
	main()
	if code != -1 {
		t.Errorf("exit %d on a clean run", code)
	}
	os.Args = []string{"cobraonly", "--nonsense"}
	main()
	if code != 1 {
		t.Errorf("exit %d on an unknown flag, want 1", code)
	}
}
