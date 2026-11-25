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
	var gotN []int
	var fail error
	work = func(in, out string, n int) (int, int, error) {
		got = append(got, [2]string{in, out})
		gotN = append(gotN, n)
		return 0, 0, fail
	}
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
	if err := run("a", "b", "1024"); err != nil || len(got) != 2 || gotN[1] != 1024 || gotN[0] != 0 {
		t.Errorf("three arguments: err %v, calls %v, sizes %v", err, got, gotN)
	}
	if err := run("a", "b", "x"); err == nil || len(got) != 2 {
		t.Errorf("a size that is not a number: err %v, calls %v", err, got)
	}
	if err := run("a", "b", "1", "2"); err != nil || len(got) != 2 {
		t.Errorf("four arguments: err %v, calls %v", err, got)
	}
	fail = os.ErrInvalid
	if err := run("a", "b"); err != os.ErrInvalid {
		t.Errorf("failing work: err = %v", err)
	}
}

func TestShape(t *testing.T) {
	old := transform
	defer func() { transform = old }()
	transform = nil
	b := []byte("0123456789")
	for _, c := range []struct {
		n    int
		want string
	}{{0, "0123456789"}, {4, "0123"}, {10, "0123456789"}, {99, "0123456789"}} {
		if got, err := shape(b, c.n); err != nil || string(got) != c.want {
			t.Errorf("shape(n=%d) = %q, %v; want %q", c.n, got, err, c.want)
		}
	}
	transform = func(in []byte) ([]byte, error) { return append([]byte("T"), in...), nil }
	if got, _ := shape(b, 3); string(got) != "T01" {
		t.Errorf("transform then cut = %q, want T01", got)
	}
	transform = func([]byte) ([]byte, error) { return []byte("never"), os.ErrInvalid }
	if got, err := shape(b, 0); err != os.ErrInvalid || got != nil {
		t.Errorf("failing transform = %q, %v", got, err)
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
