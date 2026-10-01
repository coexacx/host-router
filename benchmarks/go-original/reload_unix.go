//go:build !windows

package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

func installReload(m *manager) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			log.Printf("SIGHUP received, reloading config ...")
			if err := m.apply(); err != nil {
				log.Printf("reload failed: %v (keeping current config)", err)
			} else {
				log.Printf("reload applied")
			}
		}
	}()
}
