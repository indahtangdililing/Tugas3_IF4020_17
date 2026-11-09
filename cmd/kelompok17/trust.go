package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"kelompok17/internal/app"
)

func newTrust(service app.Service) *cobra.Command {
	cmd := &cobra.Command{
		Use: "trust", Short: "manage trusted public keys", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error { return fmt.Errorf("choose trust add, list, or remove") },
	}
	cmd.AddCommand(newTrustAdd(service), newTrustList(service), newTrustRemove(service))
	return cmd
}

func newTrustAdd(service app.Service) *cobra.Command {
	var options app.TrustAddOptions
	cmd := &cobra.Command{
		Use: "add", Short: "authorize a public key for a package", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entry, err := service.TrustAdd(options)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s %s %s\n", entry.KeyID, entry.Algorithm, options.Package)
			return err
		},
	}
	requiredString(cmd, &options.Key, "key", "SPKI public PEM path")
	requiredString(cmd, &options.Package, "package", "authorized package")
	requiredString(cmd, &options.Store, "store", "trust store path")
	return cmd
}

func newTrustList(service app.Service) *cobra.Command {
	var store string
	cmd := &cobra.Command{
		Use: "list", Short: "list trusted keys and package permissions", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			entries, err := service.TrustList(store)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s %s %v\n", entry.KeyID, entry.Algorithm, entry.Packages); err != nil {
					return err
				}
			}
			return nil
		},
	}
	requiredString(cmd, &store, "store", "trust store path")
	return cmd
}

func newTrustRemove(service app.Service) *cobra.Command {
	var store, keyid string
	cmd := &cobra.Command{
		Use: "remove", Short: "remove a trusted key", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error { return service.TrustRemove(store, keyid) },
	}
	requiredString(cmd, &keyid, "keyid", "key fingerprint to remove")
	requiredString(cmd, &store, "store", "trust store path")
	return cmd
}
