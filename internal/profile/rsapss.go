package profile

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
)

var pssOptions = &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}

type rsaPSS struct{}

func (rsaPSS) Name() string { return RSAPSS }

func (rsaPSS) GenerateKey() (crypto.Signer, error) { return rsa.GenerateKey(rand.Reader, 3072) }

func (rsaPSS) CheckKey(pub crypto.PublicKey) error {
	if k, ok := pub.(*rsa.PublicKey); ok && k.N.BitLen() == 3072 && k.E == 65537 {
		return nil
	}
	return ErrKey
}

func (p rsaPSS) Sign(priv crypto.PrivateKey, message []byte) ([]byte, error) {
	if err := checkPrivate(p, priv); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(message)
	return rsa.SignPSS(rand.Reader, priv.(*rsa.PrivateKey), crypto.SHA256, digest[:], pssOptions)
}

func (p rsaPSS) Verify(pub crypto.PublicKey, message, signature []byte) bool {
	if p.CheckKey(pub) != nil || len(signature) != 384 {
		return false
	}
	digest := sha256.Sum256(message)
	return rsa.VerifyPSS(pub.(*rsa.PublicKey), crypto.SHA256, digest[:], signature, pssOptions) == nil
}
