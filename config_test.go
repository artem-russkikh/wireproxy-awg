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

func TestWireguardConfWithAWG3Params(t *testing.T) {
	const config = `
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
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = ParseInterface(iniData, &cfg); err != nil {
		t.Fatal(err)
	}
	if err = ParsePeers(iniData, &cfg.Peers); err != nil {
		t.Fatal(err)
	}

	ipcReq, err := CreateIPCRequest(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, line := range []string{
		"header_protection_key=7bc2ca01cf9ff71133abd02befe31f291aecfa067fe32cefa5124b449fd5275c",
		"content_padding_addition=10-100",
		"rekey_after_time=100-120",
		"rekey_timeout=5",
		"reject_after_time=180-200",
		"keepalive_timeout=10-15",
		"max_handshake_attempts=18-20",
		"persistent_keepalive_interval=15-25",
	} {
		if !strings.Contains(ipcReq.IpcRequest, line) {
			t.Fatalf("%q should be present in IPC request:\n%s", line, ipcReq.IpcRequest)
		}
	}
}

func TestWireguardConfWithAWG31Params(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
RandomTrailers = on
DisableCookies = true

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = ParseInterface(iniData, &cfg); err != nil {
		t.Fatal(err)
	}
	if err = ParsePeers(iniData, &cfg.Peers); err != nil {
		t.Fatal(err)
	}

	ipcReq, err := CreateIPCRequest(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"random_trailers=true", "disable_cookies=true"} {
		if !strings.Contains(ipcReq.IpcRequest, line) {
			t.Fatalf("%q should be present in IPC request:\n%s", line, ipcReq.IpcRequest)
		}
	}
}

func TestWireguardConfWithDisabledAWG31Params(t *testing.T) {
	iniData, err := loadIniConfig(`[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
RandomTrailers = off
DisableCookies = false
`)
	if err != nil {
		t.Fatal(err)
	}

	var cfg DeviceConfig
	if err = ParseInterface(iniData, &cfg); err != nil {
		t.Fatal(err)
	}
	ipcReq, err := CreateIPCRequest(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"random_trailers=false", "disable_cookies=false"} {
		if !strings.Contains(ipcReq.IpcRequest, line) {
			t.Fatalf("%q should be present in IPC request:\n%s", line, ipcReq.IpcRequest)
		}
	}
}

func TestWireguardConfRejectsInvalidAWG31Params(t *testing.T) {
	iniData, err := loadIniConfig(`[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
RandomTrailers = sometimes
`)
	if err != nil {
		t.Fatal(err)
	}

	var cfg DeviceConfig
	err = ParseInterface(iniData, &cfg)
	if err == nil || !strings.Contains(err.Error(), "invalid RandomTrailers value") {
		t.Fatalf("expected invalid RandomTrailers error, got %v", err)
	}
}

func TestWireguardConfWithoutAWG3ParamsEmitsNothing(t *testing.T) {
	const config = `
[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
Jc = 5
Jmin = 10
Jmax = 50

[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = 25
`

	var cfg DeviceConfig
	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = ParseInterface(iniData, &cfg); err != nil {
		t.Fatal(err)
	}
	if err = ParsePeers(iniData, &cfg.Peers); err != nil {
		t.Fatal(err)
	}
	ipcReq, err := CreateIPCRequest(&cfg)
	if err != nil {
		t.Fatal(err)
	}

	for _, key := range []string{
		"header_protection_key=",
		"content_padding_addition=",
		"rekey_after_time=",
		"rekey_timeout=",
		"reject_after_time=",
		"keepalive_timeout=",
		"max_handshake_attempts=",
		"random_trailers=",
		"disable_cookies=",
	} {
		if strings.Contains(ipcReq.IpcRequest, key) {
			t.Fatalf("%q should not be emitted when it is not set", key)
		}
	}
	if !strings.Contains(ipcReq.IpcRequest, "persistent_keepalive_interval=25\n") {
		t.Fatalf("single PersistentKeepalive value should stay unchanged:\n%s", ipcReq.IpcRequest)
	}
}

func TestWireguardConfRejectsInvalidAWG3Params(t *testing.T) {
	tests := []struct {
		name       string
		parameters string
		wantError  string
	}{
		{
			name: "small header nonce padding",
			parameters: `S1 = 12
S2 = 15
S3 = 18
S4 = 11
HeaderProtectionKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=`,
			wantError: "values of the S1-S4 fields must all be at least 12 when HeaderProtectionKey is set",
		},
		{
			name: "missing header nonce padding",
			parameters: `S1 = 12
S2 = 15
S3 = 18
HeaderProtectionKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=`,
			wantError: "values of the S1-S4 fields must all be at least 12 when HeaderProtectionKey is set",
		},
		{
			name:       "descending range",
			parameters: "RekeyTimeout = 30-10",
			wantError:  "invalid RekeyTimeout value: invalid range: lower bound cannot exceed upper bound",
		},
		{
			name:       "invalid header protection key",
			parameters: "HeaderProtectionKey = not-a-key",
			wantError:  "invalid HeaderProtectionKey value:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := `[Interface]
PrivateKey = LAr1aNSNF9d0MjwUgAVC4020T0N/E5NUtqVv5EnsSz0=
Address = 10.5.0.2
DNS = 1.1.1.1
` + tt.parameters
			iniData, err := loadIniConfig(config)
			if err != nil {
				t.Fatal(err)
			}
			var cfg DeviceConfig
			err = ParseInterface(iniData, &cfg)
			if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("expected error containing %q, got %v", tt.wantError, err)
			}
		})
	}
}

func TestWireguardConfWithPersistentKeepaliveOff(t *testing.T) {
	const config = `
[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
Endpoint = 94.140.11.15:51820
PersistentKeepalive = off
`

	iniData, err := loadIniConfig(config)
	if err != nil {
		t.Fatal(err)
	}
	var peers []PeerConfig
	if err = ParsePeers(iniData, &peers); err != nil {
		t.Fatal(err)
	}
	if peers[0].KeepAlive != 0 || peers[0].KeepAliveMax != 0 {
		t.Fatalf("off should disable keepalive, got %d-%d", peers[0].KeepAlive, peers[0].KeepAliveMax)
	}
}

func TestPersistentKeepaliveRangeCrossesInt32Boundary(t *testing.T) {
	iniData, err := loadIniConfig(`[Peer]
PublicKey = e8LKAc+f9xEzq9Ar7+MfKRrs+gZ/4yzvpRJLRJ/VJ1w=
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 2147483647-2147483648
`)
	if err != nil {
		t.Fatal(err)
	}

	var peers []PeerConfig
	if err = ParsePeers(iniData, &peers); err != nil {
		t.Fatal(err)
	}
	setting, err := CreateIPCRequest(&DeviceConfig{Peers: peers})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(setting.IpcRequest, "persistent_keepalive_interval=2147483647-2147483648\n") {
		t.Fatalf("range corrupted: %s", setting.IpcRequest)
	}
}
