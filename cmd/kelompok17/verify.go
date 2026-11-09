package main

import (
	"github.com/spf13/cobra"
	"kelompok17/internal/app"
)

func newVerify(service app.Service) *cobra.Command {
	var options app.VerifyOptions
	var asJSON bool
	cmd := &cobra.Command{
		Use: "verify", Short: "verify a release artifact", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, code := app.Verify(service.Core, options)
			return printResult(cmd, result, code, asJSON)
		},
	}
	requiredString(cmd, &options.File, "file", "artifact path")
	requiredString(cmd, &options.Bundle, "bundle", "bundle path")
	requiredString(cmd, &options.TrustStore, "trust-store", "trusted store path")
	requiredString(cmd, &options.Package, "package", "expected package")
	requiredString(cmd, &options.Version, "version", "expected version")
	cmd.Flags().BoolVar(&asJSON, "json", false, "write verification JSON to stdout")
	return cmd
}
