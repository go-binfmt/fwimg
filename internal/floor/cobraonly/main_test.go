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
