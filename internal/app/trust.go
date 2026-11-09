package app

import (
	"fmt"
	"os"

	"kelompok17/internal/contract"
	"kelompok17/internal/trust"
)

func (service Service) TrustAdd(options TrustAddOptions) (contract.Entry, error) {
	if options.Key == "" || options.Store == "" || !trust.PackagePattern.MatchString(options.Package) || samePath(options.Store, options.Key) {
		return contract.Entry{}, fmt.Errorf("invalid package, key, or store path")
	}
	if service.Core == nil {
		return contract.Entry{}, ErrCoreUnavailable
	}
	store, err := trust.Load(options.Store, service.Core, true)
	if err != nil {
		return contract.Entry{}, err
	}
	pem, err := os.ReadFile(options.Key)
	if err != nil {
		return contract.Entry{}, err
	}
	_, algorithm, id, err := service.Core.LoadPublic(pem)
	if err != nil {
		return contract.Entry{}, fmt.Errorf("invalid public key")
	}
	if !contract.Supported(algorithm) || !trust.KeyIDPattern.MatchString(id) {
		return contract.Entry{}, fmt.Errorf("invalid public key profile or fingerprint")
	}
	entry := contract.Entry{KeyID: id, Algorithm: algorithm, PublicKeyPEM: string(pem), Packages: []string{options.Package}}
	trust.Add(&store, entry, options.Package)
	if err := trust.Save(options.Store, store); err != nil {
		return contract.Entry{}, err
	}
	for _, saved := range store.Keys {
		if saved.KeyID == id {
			return saved, nil
		}
	}
	return contract.Entry{}, fmt.Errorf("added trust entry not found")
}

func (service Service) TrustList(path string) ([]contract.Entry, error) {
	if path == "" {
		return nil, fmt.Errorf("missing trust store path")
	}
	if service.Core == nil {
		return nil, ErrCoreUnavailable
	}
	store, err := trust.Load(path, service.Core, false)
	if err != nil {
		return nil, err
	}
	return store.Keys, nil
}

func (service Service) TrustRemove(path, keyid string) error {
	if path == "" || !trust.KeyIDPattern.MatchString(keyid) {
		return fmt.Errorf("invalid keyid or store path")
	}
	if service.Core == nil {
		return ErrCoreUnavailable
	}
	store, err := trust.Load(path, service.Core, false)
	if err != nil {
		return err
	}
	if err := trust.Remove(&store, keyid); err != nil {
		return err
	}
	return trust.Save(path, store)
}
