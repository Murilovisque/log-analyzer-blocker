package app

import (
	"fmt"
	"monitor-blocker/config"
	"monitor-blocker/domain/blocker"
	"monitor-blocker/domain/monitor"
	"os"
	"os/signal"
	"syscall"

	"github.com/Murilovisque/logs/v3"
)

var (
	appStopped = make(chan bool, 1)
)

func Start() error {
	mapBlockers := make(map[string]blocker.Blocker)
	for _, bc := range config.Props.Blockers {
		switch bc.Type {
		case blocker.UfwBlockerType:
			b := blocker.NewUfwBlocker()
			err := b.DecodeConfig(bc)
			if err != nil {
				return err
			}
			mapBlockers[bc.Name] = b
		default:
			return fmt.Errorf("invalid blocker type '%s'", bc.Type)
		}
	}
	var sliceMonitors []monitor.Monitor
	for _, mc := range config.Props.Monitors {
		var vs []blocker.Blocker
		for _, tb := range mc.TargetBlockers {
			b, ok := mapBlockers[tb]
			if !ok {
				return fmt.Errorf("monitor '%s' refers an not exists blocker '%s'", mc.Name, tb)
			}
			vs = append(vs, b)
		}
		switch mc.Type {
		case monitor.RegexTailFileMonitorType:
			m := monitor.NewRegexTailFileMonitor()
			err := m.DecodeConfig(mc)
			if err != nil {
				return err
			}
			for _, t := range vs {
				smvb, ok := t.(monitor.StringsMatchedViolationBinder)
				if !ok {
					return fmt.Errorf("monitor '%s' refers blocker '%s' does not integrate", mc.Name, t.GetName())
				}
				m.AddBinder(smvb)
				logs.Infof("monitor '%s' bind to blocker '%s'", m.GetName(), t.GetName())
			}
			sliceMonitors = append(sliceMonitors, m)
		}
	}
	for _, b := range mapBlockers {
		b.Start()
	}
	for _, m := range sliceMonitors {
		m.Start()
	}
	prepareStopHandler(mapBlockers, sliceMonitors)
	<-appStopped
	return nil
}

func prepareStopHandler(mapBlockers map[string]blocker.Blocker, sliceMonitors []monitor.Monitor) {
	chSignal := make(chan os.Signal, 1)
	signal.Notify(chSignal, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		s := <-chSignal
		logs.Infof("signal received %v, stopping app...", s)
		for _, m := range sliceMonitors {
			err := m.StopAndWait()
			if err != nil {
				logs.Error(err)
			}
		}
		logs.Info("Monitors stopped")
		for _, b := range mapBlockers {
			err := b.StopAndWait()
			if err != nil {
				logs.Error(err)
			}
		}
		logs.Info("Blockers stopped")
		appStopped <- true
		close(appStopped)
	}()
}
