package main

///semi-trailer?

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"time"

	"flag"
	"fmt"
	"log"
	"path/filepath"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/dtylman/pathjacket/dumper"
	"github.com/dtylman/pathjacket/events"
)

var options struct {
	accesskey       string
	secret          string
	region          string
	folder          string
	bucket          string
	outfile         string
	maxonlineevents int
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

func processLogs() error {
	return filepath.Walk(options.folder, folderWalk)
}

func awsSession() (*session.Session, error) {
	log.Println("Creating AWS session...")
	conf := &aws.Config{
		Region: aws.String(options.region),
	}

	if options.accesskey != "" {
		conf.Credentials = credentials.NewStaticCredentials(options.accesskey, options.secret, "")
	}

	return session.NewSession(conf)
}

func downloadFile(sess *session.Session, bucket string, item string) error {
	fileName := filepath.Join(bucket, item)
	err := os.MkdirAll(filepath.Dir(fileName), 0700)
	if err != nil {
		return err
	}
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()
	downloader := s3manager.NewDownloader(sess)
	log.Printf("Downloading %v from %v ... ", item, bucket)
	c, err := downloader.Download(file, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(item)})
	if err != nil {
		return err
	}
	log.Printf("done. (%v bytes)", c)
	return err
}

func findBucket(svc *s3.S3) error {
	resp, err := svc.ListBuckets(nil)
	if err != nil {
		return err
	}
	var names string
	for _, b := range resp.Buckets {
		name := aws.StringValue(b.Name)
		if options.bucket == name {
			return nil
		}
		names += name + "\n"
	}
	return fmt.Errorf("Bucket '%v' not found. Buckets found: %v", options.bucket, names)
}

func downloadBucket() error {
	sess, err := awsSession()
	if err != nil {
		return err
	}
	svc := s3.New(sess)
	log.Printf("Loading logs from '%v'...", options.bucket)
	err = findBucket(svc)
	if err != nil {
		return err
	}
	req := &s3.ListObjectsInput{Bucket: aws.String(options.bucket)}

	var hasMore = true

	for hasMore {
		resp, err := svc.ListObjects(req)
		if err != nil {
			return err
		}
		for _, object := range resp.Contents {
			itemName := aws.StringValue(object.Key)
			if aws.Int64Value(object.Size) == 0 {
				log.Printf("Skipping %v, either a folder or empty", itemName)
				continue
			}

			err := downloadFile(sess, options.bucket, itemName)
			if err != nil {
				log.Println(err)
			}
		}
		req.Marker = resp.NextMarker
		hasMore = *resp.IsTruncated
	}
	return nil
}

func processOnline() error {
	sess, err := awsSession()
	if err != nil {
		return err
	}
	svc := cloudtrail.New(sess)

	input := &cloudtrail.LookupEventsInput{
		MaxResults: aws.Int64(50),
		EndTime:    aws.Time(time.Now())}

	needMore := true
	totalEvents := 0
	for needMore {
		resp, err := svc.LookupEvents(input)
		if err != nil {
			return err
		}
		input.NextToken = resp.NextToken
		if aws.StringValue(resp.NextToken) == "" {
			needMore = false
			continue
		}
		for _, object := range resp.Events {
			totalEvents++
			if totalEvents > options.maxonlineevents {
				needMore = false
				continue
			}
			raw := aws.StringValue(object.CloudTrailEvent)
			var event events.Event
			err := json.Unmarshal([]byte(raw), &event)
			if err != nil {
				log.Println(err)
			} else {
				events.AddEvent(event)
			}
		}
		log.Printf("Read %v events", totalEvents)

	}
	return nil
}

func processCommand() error {
	if options.outfile != "" {
		return dumper.DumpLogs(options.folder, options.outfile)
	}

	if options.bucket != "" {
		return downloadBucket()
	}
	var err error
	if options.folder != "" {
		err = processLogs()
	} else {
		err = processOnline()
	}
	if err != nil {
		return err
	}
	return events.Analyze()
}

func main() {
	flag.StringVar(&options.accesskey, "accesskey", "", "AWS accesskey")
	flag.StringVar(&options.secret, "secret", "", "AWS secret")
	flag.StringVar(&options.folder, "logs", "", "Process local logs folder")
	flag.StringVar(&options.outfile, "outfile", "", "don't process, just dump logs to a json file")
	flag.StringVar(&options.region, "region", "us-west-2", "AWS region")
	flag.StringVar(&options.bucket, "bucket", "", "download from s3 bucket")
	flag.IntVar(&options.maxonlineevents, "maxoe", 200, "maximum number of online events to process")
	flag.Parse()

	err := processCommand()
	if err != nil {
		log.Println(err)
		return
	}
	log.Println("Done")
	return
}
