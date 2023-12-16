package monitor

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/Murilovisque/logs/v3"
	"github.com/nxadm/tail"
)

func NewRegexTailFileMonitor() *RegexTailFileMonitor {
	return &RegexTailFileMonitor{
		binders:      []StringsMatchedViolationBinder{},
		chStopSignal: make(chan bool),
		chStopped:    make(chan bool),
	}
}

type RegexTailFileMonitor struct {
	name            string
	tailedFile      *tail.Tail
	regex           *regexp.Regexp
	violationsMonit []*violationMonit
	binders         []StringsMatchedViolationBinder
	chStopSignal    chan bool
	chStopped       chan bool
	logger          logs.Logger
}

func (rm *RegexTailFileMonitor) GetName() string {
	return rm.name
}

func (rm *RegexTailFileMonitor) AddBinder(b StringsMatchedViolationBinder) {
	rm.binders = append(rm.binders, b)
}

func (rm *RegexTailFileMonitor) DecodeConfig(c MonitorConfig) error {
	var rej regexRuleJson
	err := json.Unmarshal(c.Specification, &rej)
	if err != nil {
		return fmt.Errorf("monitor '%s', fail to decode. Error: %w", c.Name, err)
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return fmt.Errorf("monitor with empty name")
	}
	rm.tailedFile, err = tail.TailFile(rej.File, tail.Config{
		Follow:    true,
		ReOpen:    true,
		MustExist: true,
		Location: &tail.SeekInfo{
			Offset: 0,
			Whence: io.SeekEnd,
		},
	})
	if err != nil {
		return fmt.Errorf("monitor '%s', fail to tail the file '%s'. Error: %w", c.Name, rej.File, err)
	}
	rm.regex, err = regexp.Compile(rej.Regex)
	if err != nil {
		return fmt.Errorf("monitor '%s', invalid regex '%s'", c.Name, rej.Regex)
	}
	if rej.Violations == nil || len(rej.Violations) == 0 {
		return fmt.Errorf("monitor '%s', empty violations settings", c.Name)
	}
	var vms []*violationMonit
	for _, v := range rej.Violations {
		var vm violationMonit
		if v.PenaltyLimit < 1 {
			return fmt.Errorf("monitor '%s', penalty limit value must be greater than zero", c.Name)
		}
		vm.penaltyLimit = v.PenaltyLimit
		od, err := time.ParseDuration(v.OccurenceDuration)
		if err != nil {
			return fmt.Errorf("monitor '%s', invalid occurence duration format %s", c.Name, v.OccurenceDuration)
		}
		vm.occurenceDuration = od
		od, err = time.ParseDuration(v.PenaltyDuration)
		if err != nil {
			return fmt.Errorf("monitor '%s', invalid penalty duration format %s", c.Name, v.PenaltyDuration)
		}
		vm.penaltyDuration = od
		vms = append(vms, &vm)
	}
	rm.violationsMonit = vms
	rm.name = c.Name
	rm.logger = logs.NewChildLogger(logs.FixedFieldValue("monitor", rm.name))
	rm.logger.Info("regex tail monitor config loaded")
	return nil
}

func (rm *RegexTailFileMonitor) Start() error {
	go func() {
		rm.logger.Info("regex tail file monitor started")
		for {
			select {
			case line := <-rm.tailedFile.Lines:
				matchStrings := rm.regex.FindStringSubmatch(line.Text)
				if len(matchStrings) > 0 {
					if len(matchStrings) > 1 { // there are groups in regex, getting only groups
						matchStrings = matchStrings[1:]
					}
					now := time.Now()
					for _, vm := range rm.violationsMonit {
						rm.logger.Infof("violation will be increased, counter: %d, limit: %d, last: %v, duration between: %v", vm.count, vm.penaltyLimit, vm.lastViolation.Format(time.DateTime), vm.occurenceDuration)
						vm.increment(now)
						if vm.isAchieved() {
							v := StringsMatchedViolation{
								MatchStrings:    matchStrings,
								Moment:          now,
								PenaltyDuration: vm.penaltyDuration,
							}
							for _, b := range rm.binders {
								b.ListenStringsMatchedViolation(v)
							}
							rm.logger.Infof("violation sent. Matched: %v, penalty duration: %v", v.MatchStrings, v.PenaltyDuration)
						}
					}
				}
			case <-rm.chStopSignal:
				rm.chStopped <- true
				return
			}
		}
	}()
	return nil
}

func (rm *RegexTailFileMonitor) StopAndWait() error {
	rm.chStopSignal <- true
	close(rm.chStopSignal)
	<-rm.chStopped
	close(rm.chStopped)
	return rm.tailedFile.Stop()
}

type regexRuleJson struct {
	Regex      string
	File       string
	Violations []regexViolationJson
}

type regexViolationJson struct {
	OccurenceDuration string
	PenaltyDuration   string
	PenaltyLimit      uint
}
