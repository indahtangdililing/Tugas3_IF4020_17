package app

import (
	"errors"
	"regexp"

	"kelompok17/internal/contract"
)

var ErrCoreUnavailable = errors.New("core backend has not been connected")
var versionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$`)
var artifactPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

type Service struct{ Core contract.Core }

type KeyInfo struct{ KeyID, Algorithm string }

type KeygenOptions struct {
	Algorithm, Out string
	Force          bool
}

type SignOptions struct{ File, Package, Version, Key, Out string }

type TrustAddOptions struct{ Key, Package, Store string }
