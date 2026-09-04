//go:build linux && !android

package wireproxy

import (
	"fmt"
	"net"
	"strconv"

	"github.com/landlock-lsm/go-landlock/landlock"
)

func (sb *Sandbox) Lock(stage string) {
	switch stage {
	case "boot":
		if err := landlock.V1.BestEffort().RestrictPaths(landlock.RODirs("/")); err != nil {
			panic(err)
		}
	case "boot-daemon":
	case "read-config":
	case "ready":
		// no file access is allowed from now on, only networking
		net.DefaultResolver.PreferGo = true // needed to lock down dependencies

		rules := []landlock.Rule{
			landlock.ROFiles("/etc/resolv.conf").IgnoreIfMissing(),
			landlock.ROFiles("/dev/fd").IgnoreIfMissing(),
			landlock.ROFiles("/dev/zero").IgnoreIfMissing(),
			landlock.ROFiles("/dev/urandom").IgnoreIfMissing(),
			landlock.ROFiles("/etc/localtime").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/stat").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/status").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/locale").IgnoreIfMissing(),
			landlock.ROFiles("/proc/self/cmdline").IgnoreIfMissing(),
			landlock.ROFiles("/usr/share/zoneinfo").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/version").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/ngroups_max").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/kernel/cap_last_cap").IgnoreIfMissing(),
			landlock.ROFiles("/proc/sys/vm/overcommit_memory").IgnoreIfMissing(),
			landlock.RWFiles("/dev/log").IgnoreIfMissing(),
			landlock.RWFiles("/dev/null").IgnoreIfMissing(),
			landlock.RWFiles("/dev/full").IgnoreIfMissing(),
			landlock.RWFiles("/proc/self/fd").IgnoreIfMissing(),
		}

		if err := landlock.V1.BestEffort().RestrictPaths(rules...); err != nil {
			panic(err)
		}
	default:
		panic("invalid stage")
	}
}

func extractPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		panic(fmt.Errorf("failed to extract port from %s: %w", addr, err))
	}

	return uint16(port)
}

func (sb *Sandbox) LockNetwork(sections []RoutineSpawner, infoAddr *string) {
	var rules []landlock.Rule
	if infoAddr != nil && *infoAddr != "" {
		rules = append(rules, landlock.BindTCP(extractPort(*infoAddr)))
	}

	for _, section := range sections {
		switch section := section.(type) {
		case *TCPServerTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(extractPort(section.Target)))
		case *HTTPConfig:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		case *TCPClientTunnelConfig:
			rules = append(rules, landlock.ConnectTCP(uint16(section.BindAddress.Port)))
		case *Socks5Config:
			rules = append(rules, landlock.BindTCP(extractPort(section.BindAddress)))
		}
	}

	if err := landlock.V4.BestEffort().RestrictNet(rules...); err != nil {
		panic(err)
	}
}
