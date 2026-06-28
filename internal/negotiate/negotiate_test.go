package negotiate

import (
	"errors"
	"testing"
)

func caps(m ...Mode) Capabilities { return Capabilities{Modes: m} }

func TestNegotiate_PicksStrongestShared(t *testing.T) {
	local := caps(ModeZK, ModeSealedTRISA, ModeCleartextTRP)
	remote := caps(ModeSealedTRISA, ModeCleartextTRP)
	got, err := Negotiate(local, remote, ModeCleartextTRP)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != ModeSealedTRISA {
		t.Fatalf("got %q, want sealed-trisa (strongest shared)", got)
	}
}

func TestNegotiate_PrefersZKWhenBothSupport(t *testing.T) {
	local := caps(ModeZK, ModeCleartextTRP)
	remote := caps(ModeZK, ModeSealedTRISA)
	got, err := Negotiate(local, remote, ModeSealedTRISA)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if got != ModeZK {
		t.Fatalf("got %q, want zk", got)
	}
}

func TestNegotiate_RefusesBelowFloor(t *testing.T) {
	// We require at least sealed; counterparty only does cleartext.
	local := caps(ModeZK, ModeSealedTRISA, ModeCleartextTRP)
	remote := caps(ModeCleartextTRP)
	_, err := Negotiate(local, remote, ModeSealedTRISA)
	if !errors.Is(err, ErrBelowFloor) {
		t.Fatalf("got %v, want ErrBelowFloor", err)
	}
}

func TestNegotiate_NoCommonMode(t *testing.T) {
	local := caps(ModeZK)
	remote := caps(ModeCleartextTRP)
	_, err := Negotiate(local, remote, ModeCleartextTRP)
	if !errors.Is(err, ErrNoCommonMode) {
		t.Fatalf("got %v, want ErrNoCommonMode", err)
	}
}

func TestNegotiate_UnknownMode(t *testing.T) {
	if _, err := Negotiate(caps("bogus"), caps("bogus"), ModeCleartextTRP); !errors.Is(err, ErrUnknownMode) {
		t.Fatalf("got %v, want ErrUnknownMode", err)
	}
	if _, err := Negotiate(caps(ModeZK), caps(ModeZK), "bogus"); !errors.Is(err, ErrUnknownMode) {
		t.Fatalf("got %v, want ErrUnknownMode for floor", err)
	}
}

func TestStronger(t *testing.T) {
	if !Stronger(ModeZK, ModeSealedTRISA) || !Stronger(ModeSealedTRISA, ModeCleartextTRP) {
		t.Fatal("rank order wrong")
	}
	if Stronger(ModeCleartextTRP, ModeZK) {
		t.Fatal("cleartext must not outrank zk")
	}
}
