package monitor

import (
	"encoding/json"
	"time"
)

type MonitorType string

const (
	RegexTailFileMonitorType MonitorType = "REGEX_TAIL_FILE"
)

type MonitorConfig struct {
	Name           string
	Type           MonitorType
	TargetBlockers []string
	Specification  json.RawMessage
}

type Monitor interface {
	DecodeConfig(c MonitorConfig) error
	Start() error
	StopAndWait() error
	GetName() string
}

type StringsMatchedViolation struct {
	MatchStrings    []string
	Moment          time.Time
	PenaltyDuration time.Duration
}

type StringsMatchedViolationBinder interface {
	ListenStringsMatchedViolation(v StringsMatchedViolation)
}

type violationMonit struct {
	occurenceDuration time.Duration
	penaltyDuration   time.Duration
	penaltyLimit      uint
	count             uint
	lastViolation     time.Time
}

func (vm *violationMonit) increment(moment time.Time) {
	if vm.lastViolation.Add(vm.occurenceDuration).After(moment) {
		vm.count++
	} else {
		vm.count = 1
	}
	vm.lastViolation = moment
}

func (vm *violationMonit) isAchieved() bool {
	return vm.count >= vm.penaltyLimit
}
