package wireproxy

import (
	"github.com/go-ini/ini"
	"testing"
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
