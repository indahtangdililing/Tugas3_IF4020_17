package manifest

import (
	"strings"
	"testing"

	"kelompok17/internal/contract"
)

var (
	hexA = strings.Repeat("a", 64)
	hexB = strings.Repeat("b", 64)
	good = contract.Manifest{Schema: contract.ManifestSchema, Package: "demo", Version: "1.0.0+build.1", Algorithm: "ed25519", KeyID: hexA,
		Artifact: contract.Artifact{Name: "artifact.bin", Size: 1234, SHA256: hexB}}
	golden = `{"schema":"minisign-manifest/v1","package":"demo","version":"1.0.0+build.1","algorithm":"ed25519","keyid":"` + hexA +
		`","artifact":{"name":"artifact.bin","size":1234,"sha256":"` + hexB + `"}}`
)

func TestCanonicalRoundTrip(t *testing.T) {
	out, err := Canonical(good)
	if err != nil || string(out) != golden {
		t.Fatalf("canonical mismatch: %v\n%s", err, out)
	}
	if m, err := Parse(out); err != nil || m != good {
		t.Fatalf("round trip: %v", err)
	}
	odd := good
	odd.Algorithm = `x"y\z`
	out, _ = Canonical(odd)
	if m, err := Parse(out); err != nil || m.Algorithm != odd.Algorithm {
		t.Fatalf("unknown algorithm rejected: %v", err)
	}
}

func TestParseRejectsNonCanonical(t *testing.T) {
	r := func(old, new string) string { return strings.Replace(golden, old, new, 1) }
	for name, input := range map[string]string{
		"spasi":          r(`"package":"demo"`, `"package": "demo"`),
		"newline akhir":  golden + "\n",
		"urutan field":   r(`"package":"demo","version":"1.0.0+build.1"`, `"version":"1.0.0+build.1","package":"demo"`),
		"escape \\u":     r(`"demo"`, `"d\u0065mo"`),
		"escape \\/":     r(`manifest/v1`, `manifest\/v1`),
		"> 16 KiB (U10)": golden + strings.Repeat(" ", contract.MaxManifest),
	} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestValidate(t *testing.T) {
	for name, f := range map[string]func(*contract.Manifest){
		"package kapital":       func(m *contract.Manifest) { m.Package = "Demo" },
		"package newline akhir": func(m *contract.Manifest) { m.Package = "demo\n" },
		"package 65 karakter":   func(m *contract.Manifest) { m.Package = strings.Repeat("a", 65) },
		"version diawali titik": func(m *contract.Manifest) { m.Version = ".1" },
		"name dengan slash":     func(m *contract.Manifest) { m.Artifact.Name = "a/b" },
		"keyid kapital":         func(m *contract.Manifest) { m.KeyID = strings.ToUpper(hexA) },
		"sha256 63 karakter":    func(m *contract.Manifest) { m.Artifact.SHA256 = hexB[1:] },
		"size negatif":          func(m *contract.Manifest) { m.Artifact.Size = -1 },
		"size > 2^53-1":         func(m *contract.Manifest) { m.Artifact.Size = contract.MaxArtifactSize + 1 },
		"schema salah":          func(m *contract.Manifest) { m.Schema = "x" },
		"algorithm kontrol":     func(m *contract.Manifest) { m.Algorithm = "\x01" },
		"> 16 KiB (U10)":        func(m *contract.Manifest) { m.Algorithm = strings.Repeat("x", contract.MaxManifest) },
	} {
		m := good
		f(&m)
		if _, err := Canonical(m); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	m := good
	m.Artifact.Size = contract.MaxArtifactSize
	if _, err := Canonical(m); err != nil {
		t.Errorf("size 2^53-1 rejected: %v", err)
	}
}
