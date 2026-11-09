package main

import (
	"fmt"

	"github.com/spf13/cobra"
	"kelompok17/internal/app"
)

func newKeygen(service app.Service) *cobra.Command {
	var options app.KeygenOptions
	cmd := &cobra.Command{
		Use: "keygen", Short: "generate a signing key pair", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, err := service.Keygen(options)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), info.KeyID)
			return err
		},
	}
	requiredString(cmd, &options.Algorithm, "algorithm", "rsa-pss-sha256, ecdsa-p256-sha256, or ed25519")
	requiredString(cmd, &options.Out, "out", "key output prefix")
	cmd.Flags().BoolVar(&options.Force, "force", false, "allow overwriting existing key files")
	return cmd
}
