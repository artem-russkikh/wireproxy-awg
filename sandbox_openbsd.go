//go:build openbsd

package wireproxy

import (
	"log"
	"os"

	"suah.dev/protect"
)

// get the executable path via syscalls or infer it from argv
func executablePath() string {
	programPath, err := os.Executable()
	if err != nil {
		return os.Args[0]
	}
	return programPath
}

func (sb *Sandbox) Lock(stage string) {
	switch stage {
	case "boot":
		exePath := executablePath()

		if err := protect.Unveil("/", "r"); err != nil {
			panic(err)
		}

		if err := protect.Unveil(exePath, "x"); err != nil {
			panic(err)
		}

		// only allow standard stdio operation, file reading, networking, and exec
		// also remove unveil permission to lock unveil
		if err := protect.Pledge("stdio rpath inet dns proc exec"); err != nil {
			panic(err)
		}
	case "boot-daemon":
	case "read-config":
		if err := protect.Pledge("stdio rpath inet dns"); err != nil {
			panic(err)
		}
	case "ready":
		// no file access is allowed from now on, only networking
		if err := protect.Pledge("stdio inet dns"); err != nil {
			panic(err)
		}
	default:
		panic("invalid stage")
	}
}

func (sb *Sandbox) LockNetwork(sections []RoutineSpawner, infoAddr *string) {
	log.Printf("network sanboxing is not supported on OpenBSD")
}
