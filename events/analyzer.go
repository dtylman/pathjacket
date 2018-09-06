package events

import (
	"log"
	"sort"
	"time"
)

// Options defines analyzer global options
var Options struct {
	// VerboseAssumeRoleEvents if true, will log AssumeRoleEvents when are processed
	VerboseAssumeRoleEvents bool
}

type record struct {
	session        string
	assumedroleARN string
	ips            map[string]bool
	time           time.Time
}

//Analyze analyses the events
func Analyze() error {
	assumeRoleEvents := 0
	compromisedEvents := 0
	skipped := 0
	records := make(map[string]record)

	log.Printf("Analyzing %v events...", len(events))
	sort.Sort(ByTime(events))
	for _, e := range events {
		if e.HasError() {
			skipped++
			continue
		}
		if e.Name == "AssumeRole" {
			if Options.VerboseAssumeRoleEvents {
				estr, _ := e.JSONString()
				log.Println(estr)
			}
			assumeRoleEvents++
			arn := e.BuildAssumedRoleARN()
			if arn == "" {
				log.Println(e.JSONString())
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
	log.Printf("Analyzed %v events, Skipped '%v' with error codes, found '%v' 'AssumeRole', %v suspicious", len(events), skipped, assumeRoleEvents, compromisedEvents)
	return nil
}
