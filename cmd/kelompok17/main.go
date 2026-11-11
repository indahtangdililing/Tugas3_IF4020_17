package main

import (
	"os"

	"kelompok17/internal/app"
	"kelompok17/internal/core"
)

func main() {
	os.Exit(execute(app.Service{Core: core.Core{}}, "0.1.0-dev", os.Args[1:], os.Stdout, os.Stderr))
}
