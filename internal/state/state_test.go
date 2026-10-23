package state

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"testing"
	"time"
)

func TestConcurrentUpdatesAndLifecycle(t *testing.T) {
	s := Store{Dir: t.TempDir()}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- s.With(ctx, func(st *State) error { return Change(st, "add", fmt.Sprintf("device%d", i)) }, true)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var old string
	if err := s.With(ctx, func(st *State) error {
		if len(st.Devices) != 16 || st.Revision != 16 {
			t.Fatal("lost concurrent update")
		}
		seen := map[string]bool{}
		for _, d := range st.Devices {
			if seen[d.Password] || len(d.Password) < 32 {
				t.Fatal("credential not unique")
			}
			seen[d.Password] = true
		}
		old = st.Devices["device0"].Password
		return nil
	}, false); err != nil {
		t.Fatal(err)
	}
	if err := s.With(ctx, func(st *State) error { return Change(st, "rotate", "device0") }, true); err != nil {
		t.Fatal(err)
	}
	if err := s.With(ctx, func(st *State) error {
		if st.Devices["device0"].Password == old {
			t.Fatal("rotation did not change secret")
		}
		return Change(st, "revoke", "device0")
	}, true); err != nil {
		t.Fatal(err)
	}
	if err := s.With(ctx, func(st *State) error {
		d := st.Devices["device0"]
		if !d.Revoked || d.Password != "" {
			t.Fatal("revoked credential retained")
		}
		if Change(st, "rotate", "device0") == nil {
			t.Fatal("revoked credential reactivated")
		}
		if Change(st, "add", "device0") == nil {
			t.Fatal("revoked name reused")
		}
		return nil
	}, false); err != nil {
		t.Fatal(err)
	}
}

func TestSeparateProcesses(t *testing.T) {
	if dir := os.Getenv("VPNCTL_STATE_TEST_DIR"); dir != "" {
		s := Store{Dir: dir}
		if err := s.With(context.Background(), func(st *State) error {
			return Change(st, "add", os.Getenv("VPNCTL_STATE_TEST_NAME"))
		}, true); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := t.TempDir()
	var commands []*exec.Cmd
	for i := range 4 {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSeparateProcesses$")
		cmd.Env = append(os.Environ(), "VPNCTL_STATE_TEST_DIR="+dir, fmt.Sprintf("VPNCTL_STATE_TEST_NAME=worker%d", i))
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, cmd)
	}
	for _, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	if err := (Store{Dir: dir}).With(context.Background(), func(st *State) error {
		if len(st.Devices) != 4 || st.Revision != 4 {
			t.Fatal("lost update between CLI processes")
		}
		return nil
	}, false); err != nil {
		t.Fatal(err)
	}
}
