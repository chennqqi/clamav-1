package main

import (
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"time"
	"regexp"

	"github.com/google/subcommands"
	"github.com/malice-plugins/go-plugin-utils/utils"
)

var versionExp = regexp.MustCompile(`(?m)(\d+\.\d+\.\d+)`)

type updateCmd struct {
	c subcommands.Command
}

func (p *updateCmd) Name() string {
	return "update"
}

func (p *updateCmd) Synopsis() string {
	return "update"
}

func (p *updateCmd) Usage() string {
	return "update"
}

func (p *updateCmd) SetFlags(*flag.FlagSet) {
}

func (p *updateCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	ctx := context.TODO()
	fmt.Println("Updating ClamAV...")
	fmt.Println(utils.RunCommand(ctx, "freshclam"))
	// Update UPDATED file
	t := time.Now().Format("20060102")
	ioutil.WriteFile("/opt/malice/UPDATED", []byte(t), 0644)
	return subcommands.ExitSuccess
}
