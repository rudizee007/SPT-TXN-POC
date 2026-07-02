//go:build !openbsd

package main

// Stub implementations for non-OpenBSD builds (development on Linux/macOS).
// pledge and unveil are no-ops outside OpenBSD; the socket's mode is still
// tightened by the explicit os.Chmod in main.

func pledge(_ string) error { return nil }
func unveil(_, _ string)    {}
func unveilLock()           {}

func withTightUmask(fn func()) { fn() }
