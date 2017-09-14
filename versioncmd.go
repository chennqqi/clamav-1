package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"

	"github.com/google/subcommands"
	//"github.com/malice-plugins/go-plugin-utils/utils"
)

type versionCmd struct {
}

func (p *versionCmd) Name() string {
	return "version"
}

func (p *versionCmd) Synopsis() string {
	return `version `
}

func (p *versionCmd) Usage() string {
	return `version`
}

func (p *versionCmd) SetFlags(*flag.FlagSet) {
}

func (p *versionCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	fmt.Println("version:", Version)
	update, _ := ioutil.ReadFile("/opt/malice/UPDATE")
	fmt.Println("update:", string(update))
	return subcommands.ExitSuccess
}
