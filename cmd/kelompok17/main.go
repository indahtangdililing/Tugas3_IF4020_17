package main

import (
	"os"

	"kelompok17/internal/app"
)

func main() {
	os.Exit(execute(app.Service{}, "0.1.0-dev", os.Args[1:], os.Stdout, os.Stderr))
}
