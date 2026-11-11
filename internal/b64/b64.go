package b64

import (
	"encoding/base64"
	"errors"
)

func Encode(data []byte) string { return base64.StdEncoding.EncodeToString(data) }

func Decode(s string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(s)
	if err != nil || Encode(data) != s {
		return nil, errors.New("base64: invalid or non-canonical encoding")
	}
	return data, nil
}
