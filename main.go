package main

import (
	"flag"
	"os"

	"github.com/Method-Security/methodwebtest/cmd"
)

var version = "none"

func main() {
	flag.Parse()

	methodwebtest := cmd.NewMethodWebTest(version)
	methodwebtest.InitRootCommand()
	methodwebtest.InitPentestCommand()

	if err := methodwebtest.RootCmd.Execute(); err != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
