package core

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kelompok17/internal/app"
	"kelompok17/internal/contract"
)

func TestU14(t *testing.T) {
	expectIdentical := map[string]bool{"rsa-pss-sha256": false, "ecdsa-p256-sha256": false, "ed25519": true}
	service := app.Service{Core: Core{}}
	for _, algorithm := range []string{"rsa-pss-sha256", "ecdsa-p256-sha256", "ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			dir := t.TempDir()
			artifact := filepath.Join(dir, "artifact.bin")
			store := filepath.Join(dir, "trust.json")
			prefix := filepath.Join(dir, "publisher")
			if err := os.WriteFile(artifact, []byte("release payload\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := service.Keygen(app.KeygenOptions{Algorithm: algorithm, Out: prefix}); err != nil {
				t.Fatal(err)
			}
			if _, err := service.TrustAdd(app.TrustAddOptions{Key: prefix + ".pub.pem", Package: "demo", Store: store}); err != nil {
				t.Fatal(err)
			}
			bundles := make([]contract.Bundle, 2)
			for i, name := range []string{"a.json", "b.json"} {
				out := filepath.Join(dir, name)
				if err := service.Sign(app.SignOptions{File: artifact, Package: "demo", Version: "1.0.0", Key: prefix + ".key.pem", Out: out}); err != nil {
					t.Fatal(err)
				}
				data, _ := os.ReadFile(out)
				if err := json.Unmarshal(data, &bundles[i]); err != nil {
					t.Fatal(err)
				}
				result, code := app.Verify(Core{}, app.VerifyOptions{File: artifact, Bundle: out, TrustStore: store, Package: "demo", Version: "1.0.0"})
				t.Logf("%s: verify %s (exit %d)", name, result.Status, code)
				if code != 0 || result.Status != "OK" {
					t.Errorf("%s: %+v", name, result)
				}
			}
			if bundles[0].ManifestB64 != bundles[1].ManifestB64 {
				t.Fatal("manifests must be identical")
			}
			identical := bundles[0].SignatureB64 == bundles[1].SignatureB64
			t.Logf("%s: signature identical=%v (expected %v)", algorithm, identical, expectIdentical[algorithm])
			if identical != expectIdentical[algorithm] {
				t.Errorf("identical=%v, want %v", identical, expectIdentical[algorithm])
			}
		})
	}
}
