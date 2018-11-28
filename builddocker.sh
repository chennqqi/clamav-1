#!/bin/bash
go build -o avscan -ldflags "-X main.Version=$(cat VERSION) -X main.BuildTime=$(date -u +%Y%m%d)" -v 
sudo docker build -t "sort/avscan:$(cat VERSION)" -f Dockerfile.local .

