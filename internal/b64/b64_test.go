package b64

import "testing"

func TestDecode(t *testing.T) {
	if got, err := Decode("QQ=="); err != nil || string(got) != "A" {
		t.Fatalf("valid input rejected: %v", err)
	}
	for _, bad := range []string{"QR==", "QQ", "QQ=", "QQ===", "QQ==\n", "QQ\r\n==", " QQ==", "-_8=", "Q", "QUJD$"} {
		if _, err := Decode(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}
