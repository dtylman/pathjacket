package events

import (
	"log"
	"sort"
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

var items []Event

//Add adds events from a log
func Add(log Log) {
	items = append(items, log.Records...)
}

//Analyze analyses the enents
func Analyze() error {
	sort.Sort(ByTime(items))
	log.Printf("Added %v events", len(items))
	for _, e := range items {
		log.Printf("%v: %v", e.Time, e.Name)
	}
	return nil
}
