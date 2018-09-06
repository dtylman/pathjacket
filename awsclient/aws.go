package awsclient

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/dtylman/pathjacket/events"
)

//Options global options
var Options struct {
	//AccessKey AWS access key
	AccessKey string
	//Secret AWS secret
	Secret string
	//SessionToken AWS session token
	SessionToken string
	//Region os AWS region
	Region string
	//MaxOnlineEvents is the maximal number of events to load from cloudtrail
	MaxOnlineEvents int
}

//NewSession creates new AWS session
func NewSession() (*session.Session, error) {
	log.Println("Creating AWS session...")
	conf := &aws.Config{
		Region: aws.String(Options.Region),
	}

	if Options.AccessKey != "" {
		conf.Credentials = credentials.NewStaticCredentials(Options.AccessKey, Options.Secret, Options.SessionToken)
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

func findBucket(svc *s3.S3, bucket string) error {
	resp, err := svc.ListBuckets(nil)
	if err != nil {
		return err
	}
	var names string
	for _, b := range resp.Buckets {
		name := aws.StringValue(b.Name)
		if bucket == name {
			return nil
		}
		names += name + "\n"
	}
	return fmt.Errorf("Bucket '%v' not found. Buckets found: %v", bucket, names)
}

//DumpBucket dumps all files from a bucket
func DumpBucket(bucket string, basefolder string) error {
	sess, err := NewSession()
	if err != nil {
		return err
	}
	svc := s3.New(sess)
	log.Printf("Loading logs from '%v'...", bucket)
	err = findBucket(svc, bucket)
	if err != nil {
		return err
	}
	req := &s3.ListObjectsInput{Bucket: aws.String(bucket)}

	var hasMore = true

	for hasMore {
		resp, err := svc.ListObjects(req)
		if err != nil {
			return err
		}
		for _, object := range resp.Contents {
			itemName := filepath.Join(basefolder, aws.StringValue(object.Key))
			if aws.Int64Value(object.Size) == 0 {
				log.Printf("Skipping %v, either a folder or empty", itemName)
				continue
			}
			log.Printf("Downloading '%v'", itemName)
			err := downloadFile(sess, bucket, itemName)
			if err != nil {
				log.Println(err)
			}
		}
		req.Marker = resp.NextMarker
		hasMore = *resp.IsTruncated
	}
	return nil
}

//Analayze downloads all items from cloud trail and analyzes them.
func Analayze() error {
	sess, err := NewSession()
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
			if totalEvents > Options.MaxOnlineEvents {
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
	return events.Analyze()
}
