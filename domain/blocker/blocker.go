package blocker

import (
	"encoding/json"
	"time"
)

type BlockerType string

const (
	UfwBlockerType BlockerType = "UFW_BLOCKER"
)

type BlockerConfig struct {
	Name          string
	Type          BlockerType
	Specification json.RawMessage
}

type Blocker interface {
	GetName() string
	DecodeConfig(c BlockerConfig) error
	Start() error
	StopAndWait() error
}

type blockingStrIP struct {
	expirationDate time.Time
	ip             string
}
