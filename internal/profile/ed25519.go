package profile

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
)

type ed25519Profile struct{}

func (ed25519Profile) Name() string { return Ed25519 }

func (ed25519Profile) GenerateKey() (crypto.Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	return priv, err
}

func (ed25519Profile) CheckKey(pub crypto.PublicKey) error {
	if k, ok := pub.(ed25519.PublicKey); ok && len(k) == ed25519.PublicKeySize {
		return nil
	}
	return ErrKey
}

func (p ed25519Profile) Sign(priv crypto.PrivateKey, message []byte) ([]byte, error) {
	if err := checkPrivate(p, priv); err != nil {
		return nil, err
	}
	return ed25519.Sign(priv.(ed25519.PrivateKey), message), nil
}

func (p ed25519Profile) Verify(pub crypto.PublicKey, message, signature []byte) bool {
	return p.CheckKey(pub) == nil && len(signature) == ed25519.SignatureSize &&
		ed25519.Verify(pub.(ed25519.PublicKey), message, signature)
}
