package profile

import (
	"crypto"
	"errors"
)

const (
	RSAPSS  = "rsa-pss-sha256"
	ECDSA   = "ecdsa-p256-sha256"
	Ed25519 = "ed25519"
)

var ErrKey = errors.New("profile: unsupported key type or parameters")

type Profile interface {
	Name() string
	GenerateKey() (crypto.Signer, error)
	CheckKey(pub crypto.PublicKey) error
	Sign(priv crypto.PrivateKey, message []byte) ([]byte, error)
	Verify(pub crypto.PublicKey, message, signature []byte) bool
}

var registry = []Profile{rsaPSS{}, ecdsaP256{}, ed25519Profile{}}

func Get(name string) (Profile, bool) {
	for _, p := range registry {
		if p.Name() == name {
			return p, true
		}
	}
	return nil, false
}

func ForKey(pub crypto.PublicKey) (Profile, error) {
	for _, p := range registry {
		if p.CheckKey(pub) == nil {
			return p, nil
		}
	}
	return nil, ErrKey
}

func checkPrivate(p Profile, priv crypto.PrivateKey) error {
	if signer, ok := priv.(crypto.Signer); ok && p.CheckKey(signer.Public()) == nil {
		return nil
	}
	return ErrKey
}
