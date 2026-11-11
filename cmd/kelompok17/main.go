package main

import (
	"os"

	"kelompok17/internal/app"
	"kelompok17/internal/core"
)

var version = "dev"

func main() {
	os.Exit(execute(app.Service{Core: core.Core{}}, version, os.Args[1:], os.Stdout, os.Stderr))
}
