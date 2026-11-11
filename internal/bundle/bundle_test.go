package bundle

import (
	"strings"
	"testing"
)

func TestEncodeDecode(t *testing.T) {
	data, err := Encode([]byte("M"), []byte("sig"))
	if err != nil || !strings.HasSuffix(string(data), "\n") {
		t.Fatalf("encode: %v", err)
	}
	m, s, err := Decode(data)
	if err != nil || string(m) != "M" || string(s) != "sig" {
		t.Fatalf("decode: %v", err)
	}
	if _, _, err := Decode([]byte(`{"manifest_b64":"TQ==","signature_b64":"","schema":"minisign-bundle/v1"}`)); err != nil {
		t.Fatalf("free-layout bundle rejected: %v", err)
	}
	if _, err := Encode(make([]byte, 16385), nil); err == nil {
		t.Error("manifest > 16 KiB accepted")
	}
}

func TestDecodeRejects(t *testing.T) {
	for name, input := range map[string]string{
		"schema salah":     `{"schema":"x","manifest_b64":"TQ==","signature_b64":"TQ=="}`,
		"field ke-4":       `{"schema":"minisign-bundle/v1","manifest_b64":"TQ==","signature_b64":"TQ==","x":"y"}`,
		"duplicate key":    `{"schema":"minisign-bundle/v1","schema":"minisign-bundle/v1","manifest_b64":"TQ==","signature_b64":"TQ=="}`,
		"Base64 invalid":   `{"schema":"minisign-bundle/v1","manifest_b64":"TR==","signature_b64":"TQ=="}`,
		"> 64 KiB":         `{"schema":"minisign-bundle/v1","manifest_b64":"TQ==","signature_b64":"TQ=="}` + strings.Repeat(" ", 65536),
		"manifest > 16KiB": `{"schema":"minisign-bundle/v1","manifest_b64":"` + strings.Repeat("A", 21848) + `","signature_b64":""}`,
	} {
		if _, _, err := Decode([]byte(input)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
