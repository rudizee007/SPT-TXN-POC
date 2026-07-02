//go:build openbsd

package main

// Real pledge(2)/unveil(2) confinement on OpenBSD via golang.org/x/sys/unix.
// pledge restricts the syscall set; unveil restricts the visible filesystem. A
// violation terminates the process with a logged syscall in /var/log/messages,
// which is how the minimal sets are tuned. Mirrors cmd/trsvc.

import (
	"log"

	"golang.org/x/sys/unix"
)

// pledge restricts this process to the given promise set. Called after the key
// and signers are loaded and the socket is bound, so the serving loop needs
// only a small set (notably NOT inet — deanon is never network-reachable).
func pledge(promises string) error {
	return unix.PledgePromises(promises)
}

// unveil exposes a single path with the given permissions ("r","w","c","x").
// After the first call the filesystem is hidden by default; unveilLock
// finalizes the set.
func unveil(path, perms string) {
	if err := unix.Unveil(path, perms); err != nil {
		log.Printf("unveil %s (%s): %v", path, perms, err)
	}
}

// unveilLock finalizes the unveil set; no further unveil calls are permitted.
func unveilLock() {
	if err := unix.UnveilBlock(); err != nil {
		log.Printf("unveil lock: %v", err)
	}
}

// withTightUmask runs fn with the process umask set to 0o177 so the deanon
// socket node is born mode 0600 with no TOCTOU window between Listen and Chmod.
func withTightUmask(fn func()) {
	old := unix.Umask(0o177)
	defer unix.Umask(old)
	fn()
}
