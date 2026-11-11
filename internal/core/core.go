package core

import (
	"crypto"
	"errors"

	"kelompok17/internal/b64"
	"kelompok17/internal/contract"
	"kelompok17/internal/keys"
	"kelompok17/internal/manifest"
	"kelompok17/internal/profile"
	"kelompok17/internal/strictjson"
)

type Core struct{}

var _ contract.Core = Core{}

func (Core) Generate(algorithm string) ([]byte, []byte, error) {
	p, ok := profile.Get(algorithm)
	if !ok {
		return nil, nil, errors.New("unsupported algorithm")
	}
	priv, err := p.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	return keys.Encode(priv)
}

func (Core) Sign(algorithm string, key crypto.PrivateKey, message []byte) ([]byte, error) {
	p, ok := profile.Get(algorithm)
	if !ok {
		return nil, errors.New("unsupported algorithm")
	}
	return p.Sign(key, message)
}

func (Core) Verify(algorithm string, key crypto.PublicKey, message, signature []byte) bool {
	p, ok := profile.Get(algorithm)
	return ok && p.Verify(key, message, signature)
}

func (Core) LoadPrivate(pem []byte) (crypto.PrivateKey, string, string, error) {
	return keys.LoadPrivate(pem)
}

func (Core) LoadPublic(pem []byte) (crypto.PublicKey, string, string, error) {
	return keys.LoadPublic(pem)
}

func (Core) StrictJSON(data []byte, target any) error              { return strictjson.Unmarshal(data, target) }
func (Core) ParseManifest(data []byte) (contract.Manifest, error)  { return manifest.Parse(data) }
func (Core) CanonicalManifest(m contract.Manifest) ([]byte, error) { return manifest.Canonical(m) }
func (Core) DecodeBase64(value string) ([]byte, error)             { return b64.Decode(value) }
