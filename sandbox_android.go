//go:build android && arm64

package wireproxy

import "log"

func (sb *Sandbox) Lock(stage string) {
	log.Printf("sanboxing is not supported on android")
}

func (sb *Sandbox) LockNetwork(sections []RoutineSpawner, infoAddr *string) {
	log.Printf("network sanboxing is not supported on android")
}
