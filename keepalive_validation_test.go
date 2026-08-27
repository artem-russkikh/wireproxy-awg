package wireproxy

import (
	"strconv"
	"testing"
)

func TestCreateIPCRequestRejectsInvalidProgrammaticKeepalive(t *testing.T) {
	tests := []struct {
		name string
		peer PeerConfig
	}{
		{name: "negative minimum", peer: PeerConfig{KeepAlive: -1}},
		{name: "negative maximum", peer: PeerConfig{KeepAlive: 1, KeepAliveMax: -1}},
	}
	if strconv.IntSize == 64 {
		tooLargeUint32 := uint64(1) << 32
		tests = append(tests,
			struct {
				name string
				peer PeerConfig
			}{name: "minimum exceeds uint32", peer: PeerConfig{KeepAlive: int(tooLargeUint32)}},
			struct {
				name string
				peer PeerConfig
			}{name: "maximum exceeds uint32", peer: PeerConfig{KeepAlive: 1, KeepAliveMax: int(tooLargeUint32)}},
		)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := CreateIPCRequest(&DeviceConfig{Peers: []PeerConfig{tt.peer}}); err == nil {
				t.Fatal("expected invalid PersistentKeepalive error")
			}
		})
	}
}
