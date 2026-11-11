package profile

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

var message = []byte(`{"schema":"minisign-manifest/v1"}`)

func generate(t *testing.T) map[string]crypto.Signer {
	t.Helper()
	out := map[string]crypto.Signer{}
	for _, p := range registry {
		k, err := p.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		out[p.Name()] = k
	}
	return out
}

func TestSignVerify(t *testing.T) {
	signers := generate(t)
	sizes := map[string]int{RSAPSS: 384, ECDSA: 64, Ed25519: 64}
	for _, p := range registry {
		key := signers[p.Name()]
		sig, err := p.Sign(key, message)
		if err != nil || len(sig) != sizes[p.Name()] || !p.Verify(key.Public(), message, sig) {
			t.Fatalf("%s: sign/verify failed (len %d, %v)", p.Name(), len(sig), err)
		}
		bad := bytes.Clone(sig)
		bad[0] ^= 1
		if p.Verify(key.Public(), message, bad) || p.Verify(key.Public(), append(bytes.Clone(message), '!'), sig) ||
			p.Verify(key.Public(), message, sig[1:]) || p.Verify(key.Public(), message, append(sig, 0)) {
			t.Errorf("%s: tampered or wrong-length signature accepted", p.Name())
		}
		for _, other := range registry {
			if other != p && (other.Verify(key.Public(), message, sig) || other.CheckKey(key.Public()) == nil) {
				t.Errorf("%s key accepted by profile %s", p.Name(), other.Name())
			}
			if _, err := other.Sign(key, message); other != p && err == nil {
				t.Errorf("%s key signed under profile %s", p.Name(), other.Name())
			}
		}
	}
}

func TestNoDoubleHashing(t *testing.T) {
	signers := generate(t)
	digest := sha256.Sum256(message)
	for _, p := range registry {
		key := signers[p.Name()]
		sig, _ := p.Sign(key, message)
		var ok bool
		switch pub := key.Public().(type) {
		case *rsa.PublicKey:
			ok = rsa.VerifyPSS(pub, crypto.SHA256, digest[:], sig, nil) == nil
		case *ecdsa.PublicKey:
			der, _ := RawToDER(sig)
			ok = ecdsa.VerifyASN1(pub, digest[:], der)
		case ed25519.PublicKey:
			ok = ed25519.Verify(pub, message, sig)
		}
		if !ok {
			t.Errorf("%s: signature is not over the expected input", p.Name())
		}
	}
}

func TestU14SignTwice(t *testing.T) {
	signers := generate(t)
	for _, p := range registry {
		key := signers[p.Name()]
		a, _ := p.Sign(key, message)
		b, _ := p.Sign(key, message)
		identical := bytes.Equal(a, b)
		t.Logf("%s: identical=%v", p.Name(), identical)
		if identical != (p.Name() == Ed25519) || !p.Verify(key.Public(), message, a) || !p.Verify(key.Public(), message, b) {
			t.Errorf("%s: identical=%v or verify failed", p.Name(), identical)
		}
	}
}

func TestECDSAOutOfDomainAndConversion(t *testing.T) {
	key := generate(t)[ECDSA]
	n := elliptic.P256().Params().N
	for _, rs := range [][2]*big.Int{{big.NewInt(0), big.NewInt(1)}, {big.NewInt(1), big.NewInt(0)}, {n, big.NewInt(1)}, {big.NewInt(1), n}} {
		raw := make([]byte, 64)
		rs[0].FillBytes(raw[:32])
		rs[1].FillBytes(raw[32:])
		if (ecdsaP256{}).Verify(key.Public(), message, raw) {
			t.Errorf("r=%v s=%v accepted", rs[0], rs[1])
		}
	}
	sig, _ := (ecdsaP256{}).Sign(key, message)
	s := new(big.Int).SetBytes(sig[32:])
	flipped := bytes.Clone(sig)
	new(big.Int).Sub(n, s).FillBytes(flipped[32:])
	if !(ecdsaP256{}).Verify(key.Public(), message, flipped) {
		t.Error("non-low-S signature rejected")
	}
	der, _ := asn1.Marshal(ecdsaSig{big.NewInt(0x0102), big.NewInt(0x7f)})
	raw, err := DERToRaw(der)
	want := make([]byte, 64)
	want[30], want[31], want[63] = 1, 2, 0x7f
	if err != nil || !bytes.Equal(raw, want) {
		t.Fatalf("DERToRaw = %x, %v", raw, err)
	}
	if back, _ := RawToDER(raw); !bytes.Equal(back, der) {
		t.Fatal("RawToDER round trip mismatch")
	}
	if _, err := DERToRaw(append(der, 0)); err == nil {
		t.Fatal("trailing DER accepted")
	}
}
