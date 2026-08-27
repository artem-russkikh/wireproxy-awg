package wireproxy

import (
	"testing"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// The IPC request is a plain string that amneziawg-go parses key by key, so a
// wrong key name or value format is only caught by the device itself. Feed the
// generated request to a real device to keep the two in sync.
func applyIPCRequest(t *testing.T, config string) {
	t.Helper()

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DeviceConfig{MTU: 1420}
	if err = ParseInterface(iniData, &cfg); err != nil {
		t.Fatal(err)
	}
	if err = ParsePeers(iniData, &cfg.Peers); err != nil {
		t.Fatal(err)
	}

	setting, err := CreateIPCRequest(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	tun, _, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		t.Fatal(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	defer dev.Close()

	if err = dev.IpcSet(setting.IpcRequest); err != nil {
		t.Fatalf("device rejected the IPC request: %v\n%s", err, setting.IpcRequest)
	}
}

func TestIPCRequestWithAWG3ParamsIsAcceptedByDevice(t *testing.T) {
	applyIPCRequest(t, `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 15
S3 = 18
S4 = 21
H1 = 100
H2 = 200
H3 = 300
H4 = 400
I1 = <b 0xA1B2C3D4E5F6><r 10>
HeaderProtectionKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 5
RejectAfterTime = 180-200
KeepaliveTimeout = 10-15
MaxHandshakeAttempts = 18-20

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 15-25
`)
}

func TestIPCRequestWithAWG31ParamsIsAcceptedByDevice(t *testing.T) {
	applyIPCRequest(t, `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
RandomTrailers = on
DisableCookies = on

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
`)
}

func TestIPCRequestWithAWG2ParamsIsAcceptedByDevice(t *testing.T) {
	applyIPCRequest(t, `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 50
S1 = 15
S2 = 18
S3 = 20
S4 = 23
H1 = 100-101
H2 = 102-103
H3 = 104
H4 = 105-106
I1 = <b 0xA1B2C3D4E5F6>

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25
`)
}

func TestIPCRequestWithPlainWireguardIsAcceptedByDevice(t *testing.T) {
	applyIPCRequest(t, `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
`)
}
