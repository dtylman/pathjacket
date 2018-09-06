package events

import (
	"log"
	"sort"
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

type record struct {
	session        string
	assumedroleARN string
	ips            map[string]bool
	time           time.Time
}

//AddLog adds events from a log
func AddLog(log Log) {
	events = append(events, log.Records...)
}

//AddEvent adds one event
func AddEvent(event Event) {
	events = append(events, event)
}

//Analyze analyses the events
func Analyze() error {
	assumeRoleEvents := 0
	compromisedEvents := 0
	records := make(map[string]record)

	log.Printf("Analyzing %v events...", len(events))
	sort.Sort(ByTime(events))
	for _, e := range events {
		if e.Name == "AssumeRole" {
			assumeRoleEvents++
			arn := e.BuildAssumedRoleARN()
			if arn == "" {
				log.Println(e)
			}
			r, ok := records[arn]
			if ok {
				r.ips[e.SourceIPAddress] = true
				r.time = e.Time
				records[arn] = r
			} else {
				records[arn] = record{
					session:        e.RequestParameters.RoleSessionName,
					assumedroleARN: e.BuildAssumedRoleARN(),
					ips:            map[string]bool{e.SourceIPAddress: true},
					time:           e.Time,
				}
			}
		}
		r, ok := records[e.UserIdentity.ARN]
		if ok {
			_, ok = r.ips[e.SourceIPAddress]
			if !ok {
				log.Printf("%v given to %v used from '%v' User: '%v' User Agent: '%v'", r.assumedroleARN, r.ips,
					e.SourceIPAddress, e.UserIdentity.UserName, e.UserAgent)
				compromisedEvents++
			}
		}
	}
	log.Printf("Analyzed %v events, %v 'AssumeRole', %v suspicious", len(events), assumeRoleEvents, compromisedEvents)
	return nil
}

// BuildAssumedRoleARN constructs assumed role ARN from event if applicable
func (e Event) BuildAssumedRoleARN() string {
	if e.Name != "AssumeRole" {
		return ""
	}
	arn := e.ResponseElements.AssumedRoleUser.ARN
	if arn == "" {
		colonparts := strings.Split(e.RequestParameters.RoleArn, ":")
		slashparts := strings.Split(colonparts[len(colonparts)-1], "/")
		slashparts = append(slashparts, e.RequestParameters.RoleSessionName)
		colonparts[len(colonparts)-1] = "assumed-role"
		colonparts[2] = "sts"
		arn = strings.Join(colonparts, ":") + "/" + strings.Join(slashparts[1:], "/")
	}
	return arn
}
