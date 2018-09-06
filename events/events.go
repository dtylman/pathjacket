package events

import (
	"encoding/json"
	"strings"
	"time"
)

//Log ...
type Log struct {
	Records []Event `json:"Records"`
}

//UserIdentity ...
type UserIdentity struct {
	Type     string `json:"type"`
	ARN      string `json:"arn"`
	UserName string `json:"userName"`
}

//RequestParameters ...
type RequestParameters struct {
	RoleArn         string `json:"roleArn"`
	RoleSessionName string `json:"roleSessionName"`
}

//Credentials ...
type Credentials struct {
	AccessKeyID  string `json:"accessKeyId"`
	Expiration   string `json:"expiration"`
	SessionToken string `json:"sessionToken"`
}

//AssumedRoleUser ...
type AssumedRoleUser struct {
	AssumedRoleID string `json:"assumedRoleId"`
	ARN           string `json:"arn"`
}

//ResponseElements ...
type ResponseElements struct {
	Credentials     Credentials     `json:"credentials"`
	AssumedRoleUser AssumedRoleUser `json:"assumedRoleUser"`
}

// Resource ...
type Resource struct {
	ARN       string `json:"ARN"`
	AccountID string `json:"accountId"`
	Type      string `json:"type"`
}

//Event is AWS cloud trail event
type Event struct {
	Source             string            `json:"eventSource"`
	ErrorCode          string            `json:"errorCode"`
	Name               string            `json:"eventName"`
	UserIdentity       UserIdentity      `json:"userIdentity"`
	SourceIPAddress    string            `json:"sourceIPAddress"`
	UserAgent          string            `json:"userAgent"`
	Time               time.Time         `json:"eventTime"`
	Region             string            `json:"awsRegion"`
	RequestParameters  RequestParameters `json:"requestParameters"`
	ResponseElements   ResponseElements  `json:"responseElements"`
	RequestID          string            `json:"requestID"`
	ID                 string            `json:"eventID"`
	Resources          []Resource        `json:"resources"`
	Type               string            `json:"eventType"`
	RecipientAccountID string            `json:"recipientAccountId"`
}

// ByTime sorts events by time
type ByTime []Event

func (a ByTime) Len() int           { return len(a) }
func (a ByTime) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByTime) Less(i, j int) bool { return a[i].Time.Before(a[j].Time) }

var events []Event

//AddLog adds events from a log
func AddLog(log Log) {
	events = append(events, log.Records...)
}

//AddEvent adds one event
func AddEvent(event Event) {
	events = append(events, event)
}

// BuildAssumedRoleARN constructs assumed role ARN from event if applicable
func (e *Event) BuildAssumedRoleARN() string {
	if e.Name != "AssumeRole" {
		return ""
	}
	arn := e.ResponseElements.AssumedRoleUser.ARN
	if arn == "" {
		if e.RequestParameters.RoleArn == "" {
			return ""
		}
		colonparts := strings.Split(e.RequestParameters.RoleArn, ":")
		slashparts := strings.Split(colonparts[len(colonparts)-1], "/")
		slashparts = append(slashparts, e.RequestParameters.RoleSessionName)
		colonparts[len(colonparts)-1] = "assumed-role"
		colonparts[2] = "sts"
		arn = strings.Join(colonparts, ":") + "/" + strings.Join(slashparts[1:], "/")
	}
	return arn
}

//JSONString exports event as a JSON string
func (e *Event) JSONString() (string, error) {
	data, err := json.MarshalIndent(e, "", " ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

//HasError checks if errorcode is empty
func (e *Event) HasError() bool {
	return e.ErrorCode != ""
}
