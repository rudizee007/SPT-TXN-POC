package trustsnapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// FileState is a StateStore backed by one JSON file. The file records the id
// and issued_ms of the last snapshot this verifier accepted, so a later load
// can refuse anything older. It belongs to the verifier, not to the snapshot
// distribution: keep it on a path the snapshot publisher and any sync or
// deploy job cannot write, or it records whatever they choose.
//
// Writes are temp-file-then-rename so a crash leaves either the old record or
// the new one, never a torn file. Mode 0600.
type FileState struct{ Path string }

// Load implements StateStore. A missing file is "never accepted anything";
// an unreadable or malformed file is an error, not an absence — a verifier
// that cannot read its own record must not proceed as if it had none.
func (f FileState) Load() (State, bool, error) {
	b, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, false, nil
	}
	if err != nil {
		return State{}, false, err
	}
	var st State
	if err := json.Unmarshal(b, &st); err != nil {
		return State{}, false, fmt.Errorf("parse %s: %w", f.Path, err)
	}
	if st.ID == "" {
		return State{}, false, fmt.Errorf("parse %s: empty snapshot id", f.Path)
	}
	return st, true, nil
}

// Save implements StateStore.
func (f FileState) Save(st State) error {
	b, err := json.Marshal(st)
	if err != nil {
		return err
	}
	dir := filepath.Dir(f.Path)
	tmp, err := os.CreateTemp(dir, ".snapshot-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, f.Path); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}
