package keys

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"strings"
	"testing"

	"kelompok17/internal/profile"
)

type spki struct {
	Algorithm pkix.AlgorithmIdentifier
	PublicKey asn1.BitString
}

type pkcs8 struct {
	Version    int
	Algorithm  pkix.AlgorithmIdentifier
	PrivateKey []byte
}

func generate(t *testing.T, name string) (priv, pub []byte) {
	t.Helper()
	p, _ := profile.Get(name)
	k, err := p.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err = Encode(k)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func toPEM(label string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: label, Bytes: der})
}

func mutate[T any](t *testing.T, label string, data []byte, f func(*T)) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	var v T
	if _, err := asn1.Unmarshal(block.Bytes, &v); err != nil {
		t.Fatal(err)
	}
	f(&v)
	der, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return toPEM(label, der)
}

func TestLoad(t *testing.T) {
	for _, name := range []string{profile.RSAPSS, profile.ECDSA, profile.Ed25519} {
		privPEM, pubPEM := generate(t, name)
		_, a1, id1, err1 := LoadPrivate(privPEM)
		_, a2, id2, err2 := LoadPublic(pubPEM)
		if err1 != nil || err2 != nil || a1 != name || a2 != name || id1 != id2 || len(id1) != 64 {
			t.Fatalf("%s: %v %v %s %s", name, err1, err2, id1, id2)
		}
		lines := strings.Split(strings.TrimSpace(string(pubPEM)), "\n")
		body := strings.Join(lines[1:len(lines)-1], "")
		wrapped := lines[0] + "\n"
		for i := 0; i < len(body); i += 40 {
			wrapped += body[i:min(i+40, len(body))] + "\n"
		}
		wrapped += lines[len(lines)-1]
		for _, variant := range [][]byte{bytes.ReplaceAll(pubPEM, []byte("\n"), []byte("\r\n")), []byte(wrapped), append([]byte("\n  "), pubPEM...)} {
			if _, _, id, err := LoadPublic(variant); err != nil || id != id1 {
				t.Errorf("%s: keyid changed with PEM layout: %v", name, err)
			}
		}
	}
}

func TestRejectedKeys(t *testing.T) {
	rsaPriv, rsaPub := generate(t, profile.RSAPSS)
	ecPriv, ecPub := generate(t, profile.ECDSA)
	edPriv, edPub := generate(t, profile.Ed25519)
	rsa2048, _ := rsa.GenerateKey(rand.Reader, 2048)
	der2048pub, _ := x509.MarshalPKIXPublicKey(&rsa2048.PublicKey)
	der2048priv, _ := x509.MarshalPKCS8PrivateKey(rsa2048)
	pub3072, _, _, _ := LoadPublic(rsaPub)
	derE3, _ := x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: pub3072.(*rsa.PublicKey).N, E: 3})
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	derP384, _ := x509.MarshalPKIXPublicKey(&p384.PublicKey)
	ecKey, _, _, _ := LoadPublic(ecPub)
	compressed := elliptic.MarshalCompressed(elliptic.P256(), ecKey.(*ecdsa.PublicKey).X, ecKey.(*ecdsa.PublicKey).Y)
	pssOID := asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	null := asn1.RawValue{FullBytes: asn1.NullBytes}
	rsaParsed, _, _, _ := LoadPrivate(rsaPriv)
	x25519, _ := ecdh.X25519().GenerateKey(rand.Reader)
	derX25519, _ := x509.MarshalPKCS8PrivateKey(x25519)
	derX25519pub, _ := x509.MarshalPKIXPublicKey(x25519.PublicKey())

	public := map[string][]byte{
		"RSA 2048":            toPEM("PUBLIC KEY", der2048pub),
		"RSA e=3":             toPEM("PUBLIC KEY", derE3),
		"OID id-RSASSA-PSS":   mutate(t, "PUBLIC KEY", rsaPub, func(v *spki) { v.Algorithm.Algorithm = pssOID }),
		"EC P-384":            toPEM("PUBLIC KEY", derP384),
		"EC compressed":       mutate(t, "PUBLIC KEY", ecPub, func(v *spki) { v.PublicKey = asn1.BitString{Bytes: compressed, BitLength: 33 * 8} }),
		"EC explicit params":  mutate(t, "PUBLIC KEY", ecPub, func(v *spki) { v.Algorithm.Parameters = asn1.RawValue{FullBytes: []byte{0x30, 0}} }),
		"Ed25519 params NULL": mutate(t, "PUBLIC KEY", edPub, func(v *spki) { v.Algorithm.Parameters = null }),
		"label salah":         bytes.ReplaceAll(edPub, []byte("PUBLIC KEY"), []byte("RSA PUBLIC KEY")),
		"dua blok":            append(bytes.Clone(edPub), edPub...),
		"teks sebelum PEM":    append([]byte("junk\n"), edPub...),
		"private sebagai pub": edPriv,
		"X25519":              toPEM("PUBLIC KEY", derX25519pub),
	}
	for name, input := range public {
		if _, _, _, err := LoadPublic(input); err == nil {
			t.Errorf("public %s: accepted", name)
		}
	}
	private := map[string][]byte{
		"RSA 2048":              toPEM("PRIVATE KEY", der2048priv),
		"OID id-RSASSA-PSS":     mutate(t, "PRIVATE KEY", rsaPriv, func(v *pkcs8) { v.Algorithm = pkix.AlgorithmIdentifier{Algorithm: pssOID} }),
		"EC explicit params":    mutate(t, "PRIVATE KEY", ecPriv, func(v *pkcs8) { v.Algorithm.Parameters = asn1.RawValue{FullBytes: []byte{0x30, 0}} }),
		"Ed25519 params NULL":   mutate(t, "PRIVATE KEY", edPriv, func(v *pkcs8) { v.Algorithm.Parameters = null }),
		"PKCS#1":                toPEM("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(rsaParsed.(*rsa.PrivateKey))),
		"terenkripsi":           bytes.ReplaceAll(edPriv, []byte("PRIVATE KEY"), []byte("ENCRYPTED PRIVATE KEY")),
		"public sebagai priv":   edPub,
		"X25519 (bukan Signer)": toPEM("PRIVATE KEY", derX25519),
	}
	for name, input := range private {
		if _, _, _, err := LoadPrivate(input); err == nil {
			t.Errorf("private %s: accepted", name)
		}
	}
}
