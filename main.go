package main

///semi-trailer?

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"

	"flag"
	"log"
	"path/filepath"

	"github.com/dtylman/pathjacket/awsclient"
	"github.com/dtylman/pathjacket/dumper"
	"github.com/dtylman/pathjacket/events"
)

//Options ...
var Options struct {
	//LogFolder logs folder for read
	LogFolder string
	//Bucket bucket name to copy
	Bucket string
	//Outfile is the dump file for dump
	Outfile string
}

func processLogFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	reader, err := gzip.NewReader(file)
	if err != nil {
		return err
	}
	defer reader.Close()
	decoder := json.NewDecoder(reader)

	var l events.Log
	err = decoder.Decode(&l)
	if err != nil {
		return err
	}
	events.AddLog(l)
	return nil
}

func folderWalk(path string, info os.FileInfo, err error) error {
	if info.IsDir() {
		return nil
	}
	err = processLogFile(path)
	if err != nil {
		log.Printf("Failed to process '%v': '%v'", path, err)
	}
	return nil
}

func analyzeLogs() error {
	err := filepath.Walk(Options.LogFolder, folderWalk)
	if err != nil {
		return err
	}
	return events.Analyze()
}

func processCommand(command string) error {
	switch command {
	case "cloud":
		{
			return awsclient.Analayze()
		}
	case "logs":
		{
			return analyzeLogs()
		}
	case "bucket":
		{
			return dumper.DumpLogs(Options.LogFolder, Options.Outfile)
		}
	case "dump":
		{
			return awsclient.DumpBucket(Options.Bucket, Options.LogFolder)
		}
	case "assume-role":
		{
			return awsclient.AssumeRole()
		}
	}
	return fmt.Errorf("Unknwn command '%v' ", command)
}

func main() {
	var command string
	flag.StringVar(&command, "command", "cloud", `Specifies what to do, one of: 
	cloud - reads events from cloud trail and look for suspected activities
	logs - same as above, but reads evnets from a local log files
	bucket - dumps logs from AWS bucket to local files.
	dump - copy all data from local logs to a json file
	assume-role - get temporary credentials using AWS assume role`)

	flag.BoolVar(&events.Options.VerboseAssumeRoleEvents, "show-assume-role", false, "Log Assume Role Events")

	flag.StringVar(&awsclient.Options.AccessKey, "aws-access-key", "", "AWS accesskey")
	flag.StringVar(&awsclient.Options.Secret, "aws-secret", "", "AWS secret")
	flag.StringVar(&awsclient.Options.SessionToken, "aws-session-token", "", "AWS session token")
	flag.StringVar(&awsclient.Options.Region, "aws-region", "us-west-2", "AWS region")
	flag.IntVar(&awsclient.Options.MaxOnlineEvents, "max-events", 200, "Maximum number of online events to process")

	flag.StringVar(&Options.LogFolder, "logs-folder", "", "Specify a log folder for 'dump' or 'logs'")
	flag.StringVar(&Options.Outfile, "json-output", "", "Json output file used with 'dump'")
	flag.StringVar(&Options.Bucket, "s3-bucket-name", "", "Download from this s3 bucket")

	flag.Parse()

	err := processCommand(command)

	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Done")
	return
}
