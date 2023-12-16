package blocker

import (
	"encoding/json"
	"fmt"
	"io"
	"monitor-blocker/domain/monitor"
	"net"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Murilovisque/logs/v3"
)

var (
	regexUfwBlock = regexp.MustCompile(`^\[\s*([0-9]+)\]+(.+)# monitor-blocker -> expiration: ([\s\-0-9:]+)$`)
	regexSpace    = regexp.MustCompile(`\s+`)
)

func NewUfwBlocker() *UfwBlocker {
	return &UfwBlocker{
		chStopSignal: make(chan bool),
		chStopped:    make(chan bool),
	}
}

type UfwBlocker struct {
	name                    string
	chBlockingStrIP         chan blockingStrIP
	ports                   []uint
	checkExpirationDuration time.Duration
	chStopped               chan bool
	chStopSignal            chan bool
	logger                  logs.Logger
}

func (rm *UfwBlocker) GetName() string {
	return rm.name
}

func (ub *UfwBlocker) DecodeConfig(c BlockerConfig) error {
	var ubj ufwBlockerJson
	err := json.Unmarshal(c.Specification, &ubj)
	if err != nil {
		return fmt.Errorf("blocker '%s', fail to decode. Error: %w", c.Name, err)
	}
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return fmt.Errorf("blocker with empty name")
	}
	if ubj.PoolSize < 1 {
		return fmt.Errorf("blocker '%s', ufw must have pool size bigger then zero", c.Name)
	}
	if ubj.Ports == nil {
		ubj.Ports = []uint{}
	}
	dur, err := time.ParseDuration(ubj.CheckExpirationDuration)
	if err != nil {
		return fmt.Errorf("blocker '%s', invalid penalty duration format %s", c.Name, ubj.CheckExpirationDuration)
	}
	ub.name = c.Name
	ub.ports = ubj.Ports
	ub.chBlockingStrIP = make(chan blockingStrIP, ubj.PoolSize)
	ub.checkExpirationDuration = dur
	ub.logger = logs.NewChildLogger(logs.FixedFieldValue("blocker", ub.name))
	ub.logger.Info("ufw blocker config loaded")
	return nil
}

func (ub *UfwBlocker) ListenStringsMatchedViolation(v monitor.StringsMatchedViolation) {
	for _, s := range v.MatchStrings {
		ub.chBlockingStrIP <- blockingStrIP{
			ip:             s,
			expirationDate: v.Moment.Add(v.PenaltyDuration),
		}
	}
}

func (ub *UfwBlocker) Start() error {
	go func() {
		ub.logger.Info("ufw blocker started")
		ticker := time.NewTicker(ub.checkExpirationDuration)
		defer ticker.Stop()
		for {
			select {
			case b := <-ub.chBlockingStrIP:
				ip := net.ParseIP(b.ip)
				if ip == nil {
					ub.logger.Errorf("ufw received an invalid IP '%s'", b.ip)
				} else {
					ub.blockIP(ip, b.expirationDate)
				}
			case <-ticker.C:
				ub.checkExpired()
			case <-ub.chStopSignal:
				ub.chStopped <- true
				return
			}
		}
	}()
	return nil
}

func (ub *UfwBlocker) checkExpired() {
	ub.logger.Info("Checking expired rules")
	cmd := exec.Command("ufw", "status", "numbered")
	out, err := cmd.CombinedOutput()
	if err != nil {
		ub.logger.Errorf("ufw failed to get status. Cmd %s. Error: %s", out, err)
		return
	}
	now := time.Now()
	lines := strings.Split(string(out), "\n")
	slices.Reverse(lines)
	for _, ln := range lines {
		matchStrings := regexUfwBlock.FindStringSubmatch(ln)
		if len(matchStrings) == 4 {
			dateExpirationStr := matchStrings[3]
			dateExpiration, err := time.ParseInLocation(time.DateTime, dateExpirationStr, now.Location())
			if err != nil {
				ub.logger.Errorf("ufw invalid comment, fail to parse date '%s'", dateExpirationStr)
				continue
			}
			rule := strings.TrimSpace(regexSpace.ReplaceAllString(matchStrings[2], " "))
			if dateExpiration.Before(now) {
				ruleId := matchStrings[1]
				cmd = exec.Command("ufw", "delete", ruleId)
				cmdStdin, err := cmd.StdinPipe()
				if err != nil {
					ub.logger.Errorf("ufw failed to get stdin. Err: %s", err)
					continue
				}
				go func() {
					defer cmdStdin.Close()
					io.WriteString(cmdStdin, "y\n")
				}()
				out, err := cmd.CombinedOutput()
				if err != nil {
					ub.logger.Errorf("ufw failed to delete rule. Cmd %s. Error: %s", out, err)
				} else {
					ub.logger.Infof("ufw rule '%s' deleted", rule)
				}
			} else {
				ub.logger.Infof("ufw rule '%s' is not expired yet. It will be expire after '%s'", rule, dateExpirationStr)
			}
		}
	}
}

func (ub *UfwBlocker) StopAndWait() error {
	ub.chStopSignal <- true
	close(ub.chStopSignal)
	close(ub.chBlockingStrIP)
	<-ub.chStopped
	close(ub.chStopped)
	return nil
}

func (ub *UfwBlocker) blockIP(ip net.IP, expirationDate time.Time) {
	ipStr := ip.String()
	if len(ub.ports) == 0 {
		args := []string{"prepend", "deny", "from", ipStr, "to", "any", "comment", buildBlockComment(expirationDate)}
		cmd := exec.Command("ufw", args...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			ub.logger.Errorf("ufw failed to block IP '%s'. Cmd %s. Error: %s", ipStr, out, err)
		} else {
			ub.logger.Infof("ufw rule created for IP '%s'", ipStr)
		}
	} else {
		for _, port := range ub.ports {
			args := []string{"prepend", "deny", "from", ipStr, "to", "any", "port", fmt.Sprint(port), "comment", buildBlockComment(expirationDate)}
			cmd := exec.Command("ufw", args...)
			out, err := cmd.CombinedOutput()
			if err != nil {
				ub.logger.Errorf("ufw failed to block IP '%s' and port %d. Cmd %s. Error: %s - ", ipStr, port, out, err)
			} else {
				ub.logger.Infof("ufw rule created for IP '%s' and port %d", ipStr, port)
			}
		}
	}
}

func buildBlockComment(expirationDate time.Time) string {
	return fmt.Sprintf("monitor-blocker -> expiration: %s", expirationDate.Format(time.DateTime))
}

type ufwBlockerJson struct {
	PoolSize                uint
	Ports                   []uint
	CheckExpirationDuration string
}
