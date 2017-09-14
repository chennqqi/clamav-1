package main

import (
	"context"
	"flag"
	"os"

	"github.com/google/subcommands"
)

// Version stores the plugin's version
var Version = "1.0.0 alpha" 

// BuildTime stores the plugin's build time
var BuildTime string

func main() {
	subcommands.Register(&scanCmd{}, "")
	subcommands.Register(&updateCmd{}, "")
	subcommands.Register(&versionCmd{}, "")
	subcommands.Register(&webCmd{}, "")

	flag.Parse()
	ctx := context.Background()
	os.Exit(int(subcommands.Execute(ctx)))
}
