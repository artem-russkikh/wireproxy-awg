package wireproxy

import (
	"strings"
	"testing"

	"github.com/go-ini/ini"
)

func loadIniConfig(config string) (*ini.File, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	return ini.LoadSources(iniOpt, []byte(config))
}

func TestWireguardConfWithoutSubnet(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithSubnet(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2/23
DNS = 1.1.1.1

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithAWGParams(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 50
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that ASecConfig is created
	if cfg.ASecConfig == nil {
		t.Fatal("ASecConfig should be created")
	}

	// Verify that optional fields are nil (not set)
	if cfg.ASecConfig.i1 != nil {
		t.Error("i1 should be nil when not set")
	}
	if cfg.ASecConfig.i2 != nil {
		t.Error("i2 should be nil when not set")
	}
	if cfg.ASecConfig.i3 != nil {
		t.Error("i3 should be nil when not set")
	}
	if cfg.ASecConfig.i4 != nil {
		t.Error("i4 should be nil when not set")
	}
	if cfg.ASecConfig.i5 != nil {
		t.Error("i5 should be nil when not set")
	}

	// Verify that required fields are set correctly
	if cfg.ASecConfig.junkPacketCount != 5 {
		t.Error("junkPacketCount should be 5")
	}
	if cfg.ASecConfig.junkPacketMinSize != 10 {
		t.Error("junkPacketMinSize should be 10")
	}
	if cfg.ASecConfig.junkPacketMaxSize != 50 {
		t.Error("junkPacketMaxSize should be 50")
	}
	if cfg.ASecConfig.initPacketJunkSize != 0 {
		t.Error("initPacketJunkSize should be 0")
	}
	if cfg.ASecConfig.responsePacketJunkSize != 0 {
		t.Error("responsePacketJunkSize should be 0")
	}
	if cfg.ASecConfig.initPacketMagicHeader != 1 {
		t.Error("initPacketMagicHeader should be 1")
	}
	if cfg.ASecConfig.responsePacketMagicHeader != 2 {
		t.Error("responsePacketMagicHeader should be 2")
	}
	if cfg.ASecConfig.underloadPacketMagicHeader != 3 {
		t.Error("underloadPacketMagicHeader should be 3")
	}
	if cfg.ASecConfig.transportPacketMagicHeader != 4 {
		t.Error("transportPacketMagicHeader should be 4")
	}
}

func TestWireguardConfWithAWGParamsWithI1(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 50
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4
I1 = <b 0xA1B2C3D4E5F6>

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Verify that ASecConfig is created
	if cfg.ASecConfig == nil {
		t.Fatal("ASecConfig should be created")
	}

	// Verify that I1 is set correctly
	if cfg.ASecConfig.i1 == nil {
		t.Error("i1 should be set")
	} else if *cfg.ASecConfig.i1 != "<b 0xA1B2C3D4E5F6>" {
		t.Errorf("i1 should be '<b 0xA1B2C3D4E5F6>', got '%s'", *cfg.ASecConfig.i1)
	}

	// Verify that other optional fields are nil (not set)
	if cfg.ASecConfig.i2 != nil {
		t.Error("i2 should be nil when not set")
	}
	if cfg.ASecConfig.i3 != nil {
		t.Error("i3 should be nil when not set")
	}
	if cfg.ASecConfig.i4 != nil {
		t.Error("i4 should be nil when not set")
	}
	if cfg.ASecConfig.i5 != nil {
		t.Error("i5 should be nil when not set")
	}

	// Verify that required fields are set correctly
	if cfg.ASecConfig.junkPacketCount != 5 {
		t.Error("junkPacketCount should be 5")
	}
	if cfg.ASecConfig.junkPacketMinSize != 10 {
		t.Error("junkPacketMinSize should be 10")
	}
	if cfg.ASecConfig.junkPacketMaxSize != 50 {
		t.Error("junkPacketMaxSize should be 50")
	}
	if cfg.ASecConfig.initPacketJunkSize != 0 {
		t.Error("initPacketJunkSize should be 0")
	}
	if cfg.ASecConfig.responsePacketJunkSize != 0 {
		t.Error("responsePacketJunkSize should be 0")
	}
	if cfg.ASecConfig.initPacketMagicHeader != 1 {
		t.Error("initPacketMagicHeader should be 1")
	}
	if cfg.ASecConfig.responsePacketMagicHeader != 2 {
		t.Error("responsePacketMagicHeader should be 2")
	}
	if cfg.ASecConfig.underloadPacketMagicHeader != 3 {
		t.Error("underloadPacketMagicHeader should be 3")
	}
	if cfg.ASecConfig.transportPacketMagicHeader != 4 {
		t.Error("transportPacketMagicHeader should be 4")
	}
}

func TestWireguardConfWithInvalid1AWGParams(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 200
Jmin = 10
Jmax = 50
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	expectedError := "value of the Jc field must be within the range of 1 to 128"
	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err != nil && err.Error() != expectedError {
		t.Fatalf("error expected: %s, got: %s", expectedError, err.Error())
	}
}

func TestWireguardConfWithInvalid2AWGParams(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 55
Jmax = 50
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	expectedError := "value of the Jmin field must be less than or equal to Jmax field value"
	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err != nil && err.Error() != expectedError {
		t.Fatalf("error expected: %s, got: %s", expectedError, err.Error())
	}
}

func TestWireguardConfWithInvalid3AWGParams(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 1300
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	expectedError := "value of the Jmax field must be less than or equal 1280"
	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err != nil && err.Error() != expectedError {
		t.Fatalf("error expected: %s, got: %s", expectedError, err.Error())
	}
}

func TestWireguardConfWithInvalid4AWGParams(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 50
S1 = 0
S2 = 56
H1 = 1
H2 = 2
H3 = 3
H4 = 4

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	expectedError := "value of the field S1 + message initiation size (148) must not equal S2 + message response size (92)"
	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err != nil && err.Error() != expectedError {
		t.Fatalf("error expected: %s, got: %s", expectedError, err.Error())
	}
}

func TestWireguardConfWithInvalid5AWGParams(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 50
S1 = 0
S2 = 0
H1 = 1
H2 = 2
H3 = 2
H4 = 4

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	expectedError := "values of the H1-H4 fields must be unique"
	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err != nil && err.Error() != expectedError {
		t.Fatalf("error expected: %s, got: %s", expectedError, err.Error())
	}
}

func TestWireguardConfWithManyAddress(t *testing.T) {
	const config = `
[Interface]
PrivateKey = mBsVDahr1XIu9PPd17UmsDdB6E53nvmS47NbNqQCiFM=
Address = 100.96.0.190,2606:B300:FFFF:fe8a:2ac6:c7e8:b021:6f5f/128
DNS = 198.18.0.1,198.18.0.2

[Peer]
PublicKey = SHnh4C2aDXhp1gjIqceGhJrhOLSeNYcqWLKcYnzj00U=
AllowedIPs = 0.0.0.0/0,::/0
Endpoint = 192.200.144.22:51820`
	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}
}

func TestWireguardConfWithAWG2HandshakeOnly(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
	Address = 10.5.0.2
	DNS = 1.1.1.1
	I1 = <b 0xA1B2C3D4E5F6><c>
	`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.ASecConfig == nil {
		t.Fatal("ASecConfig should be created")
	}
	if cfg.ASecConfig.i1 == nil || *cfg.ASecConfig.i1 != "<b 0xA1B2C3D4E5F6><c>" {
		t.Fatal("i1 should be set")
	}

	ipcReq, err := CreateIPCRequest(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(ipcReq.IpcRequest, "jc=") {
		t.Fatal("jc should not be emitted when it is not set")
	}
	if strings.Contains(ipcReq.IpcRequest, "h1=") {
		t.Fatal("h1 should not be emitted when it is not set")
	}
	if !strings.Contains(ipcReq.IpcRequest, "i1=<b 0xA1B2C3D4E5F6><c>") {
		t.Fatal("i1 should be present in IPC request")
	}
}

func TestWireguardConfWithPartialDuplicateHeaders(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
H1 = 10
H2 = 10
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err.Error() != "values of the H1-H4 fields must be unique" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWireguardConfWithAWG2S3S4AndHeaderRanges(t *testing.T) {
	const config = `
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
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ASecConfig == nil {
		t.Fatal("ASecConfig should be created")
	}
	if !cfg.ASecConfig.hasCookieReplyPacketJunkSize || cfg.ASecConfig.cookieReplyPacketJunkSize != 20 {
		t.Fatal("S3 should be parsed")
	}
	if !cfg.ASecConfig.hasTransportPacketJunkSize || cfg.ASecConfig.transportPacketJunkSize != 23 {
		t.Fatal("S4 should be parsed")
	}
	if cfg.ASecConfig.initPacketMagicHeader != 100 || cfg.ASecConfig.initPacketMagicHeaderMax != 101 {
		t.Fatal("H1 range should be parsed")
	}
	if cfg.ASecConfig.transportPacketMagicHeader != 105 || cfg.ASecConfig.transportPacketMagicHeaderMax != 106 {
		t.Fatal("H4 range should be parsed")
	}

	ipcReq, err := CreateIPCRequest(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(ipcReq.IpcRequest, "s3=20") {
		t.Fatal("s3 should be emitted")
	}
	if !strings.Contains(ipcReq.IpcRequest, "s4=23") {
		t.Fatal("s4 should be emitted")
	}
	if !strings.Contains(ipcReq.IpcRequest, "h1=100-101") {
		t.Fatal("h1 range should be emitted to IPC")
	}
	if !strings.Contains(ipcReq.IpcRequest, "h4=105-106") {
		t.Fatal("h4 range should be emitted to IPC")
	}
}

func TestWireguardConfWithAWG2PacketSizeCollision(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
S1 = 8
S2 = 0
S3 = 92
S4 = 0
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	expectedError := "value of the field S1 + message initiation size (148) must not equal S2 + message response size (92) + S3 + cookie reply size (64) + S4 + transport packet size (32)"
	if err.Error() != expectedError {
		t.Fatalf("error expected: %s, got: %s", expectedError, err.Error())
	}
}

func TestWireguardConfWithOverconstrainedHeaderRanges(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
H1 = 1-2
H2 = 1-2
H3 = 1-2
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err.Error() != "values of the H1-H4 fields must be unique" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWireguardConfWithOverlappingHeaderRanges(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
H1 = 100-200
H2 = 200-300
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err.Error() != "values of the H1-H4 fields must be unique" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWireguardConfWithHeaderConflictAgainstDefaults(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
H1 = 2
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}

	err = ParseInterface(iniData, &cfg)
	if err == nil {
		t.Fatal("error expected")
	}
	if err.Error() != "values of the H1-H4 fields must be unique" {
		t.Fatalf("unexpected error: %v", err)
	}
}
