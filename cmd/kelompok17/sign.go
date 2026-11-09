package main

import (
	"github.com/spf13/cobra"
	"kelompok17/internal/app"
)

func newSign(service app.Service) *cobra.Command {
	var options app.SignOptions
	cmd := &cobra.Command{
		Use: "sign", Short: "sign a release artifact", Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error { return service.Sign(options) },
	}
	requiredString(cmd, &options.File, "file", "artifact path")
	requiredString(cmd, &options.Package, "package", "release package")
	requiredString(cmd, &options.Version, "version", "release version")
	requiredString(cmd, &options.Key, "key", "PKCS#8 private PEM path")
	requiredString(cmd, &options.Out, "out", "bundle output path")
	return cmd
}
