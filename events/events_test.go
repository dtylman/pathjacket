package events

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEvent_BuildAssumedRuleARN(t *testing.T) {
	e := Event{}
	assert.Empty(t, e.BuildAssumedRoleARN())
	arn := "arn:aws:sts::789433625753:assumed-role/trailblazer/createsecuritygroup"
	e.ResponseElements.AssumedRoleUser.ARN = arn
	assert.Empty(t, e.BuildAssumedRoleARN())
	e.Name = "AssumeRole"
	assert.EqualValues(t, arn, e.BuildAssumedRoleARN())
	e.ResponseElements.AssumedRoleUser.ARN = ""
	e.RequestParameters.RoleArn = "arn:aws:iam::789433625753:role/trailblazer"
	e.RequestParameters.RoleSessionName = "createsecuritygroup"
	assert.EqualValues(t, arn, e.BuildAssumedRoleARN())
}
