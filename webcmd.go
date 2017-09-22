package main

import (
	"context"
	"flag"
	"time"

	"github.com/google/subcommands"
)

type webCmd struct {
	port   int
	zipto  string
}

func (p *webCmd) Name() string {
	return "web"
}

func (p *webCmd) Synopsis() string {
	return "web"
}

func (p *webCmd) Usage() string {
	return "web -p port"
}

func (p *webCmd) SetFlags(f *flag.FlagSet) {
	f.IntVar(&p.port, "p", 8080, "set port")
	f.StringVar(&p.zipto, "timeout", "60s", "set scan timeout")
}

func (p *webCmd) Execute(context.Context, *flag.FlagSet, ...interface{}) subcommands.ExitStatus {
	to, err := time.ParseDuration(p.zipto)
	if err != nil {
		to, _ = time.ParseDuration("60s")
	}

	var w Web
	w.clav,_ = NewClamAV("", false)
	w.fileto = to
	w.zipto = to
	w.Run(p.port)
	return subcommands.ExitSuccess
}
