package awsclient

import (
	"log"
	"strconv"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/tcnksm/go-input"
)

//AssumeRole ...
func AssumeRole() error {
	ui := new(input.UI)
	arn, err := ui.Ask("Enter Assumed Role ARN", &input.Options{HideOrder: true, Required: true, Loop: true})
	if err != nil {
		return err
	}
	roleSession, err := ui.Ask("Enter Assumed Role Session Name", &input.Options{HideOrder: true, Required: false, Default: "PathJacket"})
	if err != nil {
		return err
	}
	duration, err := ui.Ask("Token Duration (in seconds)", &input.Options{HideOrder: true, Required: true, Default: "900"})
	if err != nil {
		return err
	}
	seconds, err := strconv.Atoi(duration)
	if err != nil {
		return err
	}
	sess, err := NewSession()
	if err != nil {
		return err
	}

	svc := sts.New(sess)

	req := &sts.AssumeRoleInput{
		RoleArn:         aws.String(arn),
		RoleSessionName: aws.String(roleSession),
		DurationSeconds: aws.Int64(int64(seconds)),
	}

	resp, err := svc.AssumeRole(req)
	if err != nil {
		return err
	}
	log.Println(resp.String())
	return nil
}
