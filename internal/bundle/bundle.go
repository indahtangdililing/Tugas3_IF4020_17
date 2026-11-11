package bundle

import (
	"encoding/json"
	"errors"

	"kelompok17/internal/b64"
	"kelompok17/internal/contract"
	"kelompok17/internal/strictjson"
)

func Decode(data []byte) (manifest, signature []byte, err error) {
	var b contract.Bundle
	if len(data) > contract.MaxBundle {
		return nil, nil, errors.New("bundle: exceeds 64 KiB")
	}
	if err = strictjson.Unmarshal(data, &b); err != nil {
		return nil, nil, err
	}
	if b.Schema != contract.BundleSchema {
		return nil, nil, errors.New("bundle: invalid schema")
	}
	if manifest, err = b64.Decode(b.ManifestB64); err != nil {
		return nil, nil, err
	}
	if signature, err = b64.Decode(b.SignatureB64); err != nil {
		return nil, nil, err
	}
	if len(manifest) > contract.MaxManifest {
		return nil, nil, errors.New("bundle: manifest exceeds 16 KiB")
	}
	return manifest, signature, nil
}

func Encode(manifest, signature []byte) ([]byte, error) {
	data, err := json.Marshal(contract.Bundle{Schema: contract.BundleSchema, ManifestB64: b64.Encode(manifest), SignatureB64: b64.Encode(signature)})
	if err == nil && (len(manifest) > contract.MaxManifest || len(data)+1 > contract.MaxBundle) {
		err = errors.New("bundle: manifest exceeds 16 KiB or bundle exceeds 64 KiB")
	}
	return append(data, '\n'), err
}
