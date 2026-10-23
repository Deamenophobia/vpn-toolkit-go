package state

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Deamenophobia/vpn-toolkit-go/internal/config"
	"github.com/Deamenophobia/vpn-toolkit-go/internal/privatefs"
	"github.com/gofrs/flock"
)

type Device struct {
	Password string `json:"password,omitempty"`
	Revoked  bool   `json:"revoked"`
}
type State struct {
	Version  int               `json:"version"`
	Revision uint64            `json:"revision"`
	Devices  map[string]Device `json:"devices"`
}
type Store struct{ Dir string }

func (s Store) With(ctx context.Context, fn func(*State) error, save bool) error {
	if err := privatefs.Dir(s.Dir); err != nil {
		return err
	}
	lock := flock.New(filepath.Join(s.Dir, "state.lock"))
	ok, err := lock.TryLockContext(ctx, 25*time.Millisecond)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("state is busy; try again")
	}
	defer lock.Close()
	path := filepath.Join(s.Dir, "state.json")
	st := State{Version: 1, Devices: map[string]Device{}}
	data, err := privatefs.Read(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil {
		if json.Unmarshal(data, &st) != nil || st.Version != 1 || st.Devices == nil {
			return errors.New("invalid state file; restore a private backup")
		}
		for n, d := range st.Devices {
			if !config.Name(n) || (!d.Revoked && len(d.Password) < 32) {
				return errors.New("invalid device state")
			}
		}
	}
	if err = fn(&st); err != nil {
		return err
	}
	if !save {
		return nil
	}
	st.Revision++
	data, err = json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return privatefs.Write(path, append(data, '\n'))
}
func Password() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func Change(st *State, action, name string) error {
	if !config.Name(name) {
		return errors.New("device name must be 1-48 letters, digits, underscores or hyphens, starting with a letter or digit")
	}
	d, exists := st.Devices[name]
	switch action {
	case "add":
		if exists {
			return errors.New("device name already exists; use a new name")
		}
	case "rotate":
		if !exists || d.Revoked {
			return errors.New("active device not found")
		}
	case "revoke":
		if !exists {
			return errors.New("device not found")
		}
		d.Revoked = true
		d.Password = ""
		st.Devices[name] = d
		return nil
	default:
		return fmt.Errorf("unknown device operation")
	}
	p, err := Password()
	if err != nil {
		return err
	}
	st.Devices[name] = Device{Password: p}
	return nil
}
