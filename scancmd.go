package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"time"

	"github.com/google/subcommands"
	//"github.com/malice-plugins/go-plugin-utils/utils"
)

type scanCmd struct {
	db string
	to string
}

func (p *scanCmd) Name() string {
	return "scan"
}

func (p *scanCmd) Synopsis() string {
	return "scan webshell in specific directory"
}

func (p *scanCmd) Usage() string {
	return "scan <targetdir>"
}

func (p *scanCmd) SetFlags(f *flag.FlagSet) {
	f.StringVar(&p.db, "d", "", "set database dir")
	f.StringVar(&p.to, "t", "60s", "set timeout")
}

func (p *scanCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	dirs := f.Args()
	if len(dirs) == 0 {
		fmt.Println("target dir is must")
		return subcommands.ExitUsageError
	}
	clam, err := NewClamAV(p.db, false)
	if err != nil {
		fmt.Println("ERROR:", err)
		return subcommands.ExitFailure
	}
	to, _ := time.ParseDuration(p.to)
	ctx, cancel := context.WithTimeout(context.TODO(), to)
	defer cancel()

	outChan := clam.ScanDir(dirs[0], ctx)
	var results []*ClamAVResult
	for {
		r, ok := <-outChan
		if !ok {
			break
		}
		results = append(results, r)
	}
	//TODO:
	txt, _ := json.Marshal(results)
	fmt.Println(string(txt))

	return subcommands.ExitSuccess
}
