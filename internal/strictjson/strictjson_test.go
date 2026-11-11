package strictjson

import (
	"strings"
	"testing"

	"kelompok17/internal/contract"
)

const valid = `{"schema":"s","package":"p","version":"v","algorithm":"a","keyid":"k","artifact":{"name":"n","size":12,"sha256":"h"}}`

func TestUnmarshal(t *testing.T) {
	var m contract.Manifest
	if err := Unmarshal([]byte(valid), &m); err != nil || m.Artifact.Size != 12 {
		t.Fatalf("valid input rejected: %v", err)
	}
	var b contract.Bundle
	if err := Unmarshal([]byte("{\r\n \"signature_b64\" : \"x\",\n\t\"schema\":\"s\", \"manifest_b64\":\"y\" }\n"), &b); err != nil {
		t.Fatalf("free-layout bundle rejected: %v", err)
	}
	var s contract.Store
	if err := Unmarshal([]byte(`{"schema":"s","keys":[]}`), &s); err != nil || s.Keys == nil {
		t.Fatalf("empty keys: %v", err)
	}
}

func TestUnmarshalRejects(t *testing.T) {
	r := func(old, new string) string { return strings.Replace(valid, old, new, 1) }
	cases := map[string]string{
		"duplicate key":             r(`"package":"p"`, `"package":"p","package":"p"`),
		"duplicate key di artifact": r(`"size":12`, `"size":12,"size":12`),
		"duplicate key ter-escape":  r(`"package":"p"`, `"package":"p","p\u0061ckage":"p"`),
		"null":                      r(`"package":"p"`, `"package":null`),
		"boolean sebagai integer":   r(`"size":12`, `"size":true`),
		"integer 1.0":               r(`"size":12`, `"size":1.0`),
		"integer 1e3":               r(`"size":12`, `"size":1e3`),
		"integer sebagai string":    r(`"size":12`, `"size":"12"`),
		"leading zero":              r(`"size":12`, `"size":012`),
		"string sebagai angka":      r(`"algorithm":"a"`, `"algorithm":1`),
		"field tambahan":            r(`"package":"p"`, `"package":"p","x":"y"`),
		"field beda kapital":        r(`"package":"p"`, `"Package":"p"`),
		"field hilang":              r(`"package":"p",`, ``),
		"artifact bukan objek":      r(`{"name":"n","size":12,"sha256":"h"}`, `[]`),
		"data sisa":                 valid + "{}",
		"BOM":                       "\xEF\xBB\xBF" + valid,
		"UTF-8 rusak":               r("p", "\xff"),
		"JSON tidak valid":          valid[:20],
	}
	for name, input := range cases {
		var m contract.Manifest
		if err := Unmarshal([]byte(input), &m); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	var s contract.Store
	if Unmarshal([]byte(`{"schema":"s","keys":null}`), &s) == nil {
		t.Error("keys null accepted")
	}
	if Unmarshal([]byte(`{"schema":"s","keys":[{"keyid":"a","algorithm":"b","public_key_pem":"c","packages":["x"],"keyid":"a"}]}`), &s) == nil {
		t.Error("duplicate key inside array element accepted")
	}
}
