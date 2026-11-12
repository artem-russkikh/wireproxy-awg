package wireproxy

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/go-ini/ini"
)

const (
	amneziaScheme         = "vpn://"
	maxAmneziaProfileSize = 4 << 20
)

type amneziaProfile struct {
	DefaultContainer string `json:"defaultContainer"`
	DNS1             string `json:"dns1"`
	DNS2             string `json:"dns2"`
	Containers       []struct {
		Name      string          `json:"container"`
		AWG       amneziaProtocol `json:"awg"`
		WireGuard amneziaProtocol `json:"wireguard"`
	} `json:"containers"`
}

type amneziaProtocol struct {
	LastConfig string `json:"last_config"`
}

// ParseAmneziaConfig loads an Amnezia link and configures a SOCKS5 listener.
func ParseAmneziaConfig(link, bindAddress string) (*Configuration, error) {
	link = strings.TrimSpace(link)
	if !strings.HasPrefix(link, amneziaScheme) {
		return nil, errors.New("expected an Amnezia vpn:// link")
	}
	bindAddress = strings.TrimSpace(bindAddress)
	if bindAddress == "" {
		bindAddress = "127.0.0.1:1080"
	}
	_, port, err := net.SplitHostPort(bindAddress)
	if err != nil {
		return nil, errors.New("SOCKS5 bind address must be in host:port format")
	}
	if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
		return nil, errors.New("SOCKS5 bind port must be between 1 and 65535")
	}
	cfg, err := loadAmneziaConfig(configLoadOptions(), link)
	if err != nil {
		return nil, err
	}
	device, err := parseDeviceConfig(cfg)
	if err != nil {
		return nil, err
	}
	return &Configuration{
		Device: device,
		Routines: []RoutineSpawner{&Socks5Config{BindAddress: bindAddress}},
		Resolve: &ResolveConfig{ResolveStrategy: "auto"},
	}, nil
}

func loadAmneziaConfig(options ini.LoadOptions, link string) (*ini.File, error) {
	profile, err := decodeAmneziaProfile(link)
	if err != nil {
		return nil, err
	}

	var lastConfig string
	for _, container := range profile.Containers {
		if profile.DefaultContainer != "" && container.Name != profile.DefaultContainer {
			continue
		}
		candidate := container.AWG.LastConfig
		if candidate == "" {
			candidate = container.WireGuard.LastConfig
		}
		if candidate == "" {
			continue
		}
		if lastConfig != "" {
			return nil, errors.New("Amnezia profile has multiple matching VPN configurations")
		}
		lastConfig = candidate
	}
	if lastConfig == "" {
		return nil, errors.New("Amnezia profile has no selected AmneziaWG or WireGuard client configuration")
	}

	var client map[string]json.RawMessage
	if err := json.Unmarshal([]byte(lastConfig), &client); err != nil {
		return nil, errors.New("invalid Amnezia client configuration JSON")
	}
	var nativeConfig string
	if err := json.Unmarshal(client["config"], &nativeConfig); err != nil || strings.TrimSpace(nativeConfig) == "" {
		return nil, errors.New("Amnezia client configuration has no embedded WireGuard INI")
	}
	cfg, err := ini.LoadSources(options, []byte(nativeConfig))
	if err != nil {
		return nil, errors.New("invalid embedded WireGuard INI in Amnezia profile")
	}
	if iface, err := cfg.GetSection("Interface"); err == nil {
		if dns, err := iface.GetKey("DNS"); err == nil {
			dns.SetValue(strings.NewReplacer("$PRIMARY_DNS", profile.DNS1, "$SECONDARY_DNS", profile.DNS2).Replace(dns.Value()))
		}
		if err := applyAmneziaParameters(iface, client); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func decodeAmneziaProfile(link string) (*amneziaProfile, error) {
	payload := strings.TrimPrefix(link, amneziaScheme)
	if len(payload) > base64.URLEncoding.EncodedLen(maxAmneziaProfileSize+4) {
		return nil, errors.New("Amnezia VPN link is too large")
	}
	encoding := base64.RawURLEncoding
	if strings.HasSuffix(payload, "=") {
		encoding = base64.URLEncoding
	}
	packed, err := encoding.DecodeString(payload)
	if err != nil || len(packed) < 4 {
		return nil, errors.New("invalid Amnezia VPN link encoding")
	}
	// Qt qCompress prefixes the zlib stream with its uncompressed size.
	size := binary.BigEndian.Uint32(packed[:4])
	if size == 0 || size > maxAmneziaProfileSize {
		return nil, errors.New("invalid Amnezia profile size")
	}
	reader, err := zlib.NewReader(bytes.NewReader(packed[4:]))
	if err != nil {
		return nil, errors.New("invalid compressed Amnezia profile")
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, int64(size)+1))
	if err != nil || len(data) != int(size) {
		return nil, errors.New("invalid compressed Amnezia profile")
	}

	var profile amneziaProfile
	if err := json.Unmarshal(data, &profile); err != nil {
		return nil, errors.New("invalid Amnezia profile JSON")
	}
	return &profile, nil
}

func applyAmneziaParameters(iface *ini.Section, client map[string]json.RawMessage) error {
	// Amnezia also exports protocol parameters as fields alongside the INI.
	for _, name := range []string{
		"MTU", "Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4",
		"H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5",
		"HeaderProtectionKey", "ContentPaddingAddition", "RekeyAfterTime",
		"RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
		"MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
	} {
		raw, ok := client[name]
		if !ok && name == "MTU" {
			raw, ok = client["mtu"]
		}
		if !ok || string(raw) == "null" {
			continue
		}
		value := string(raw)
		switch value[0] {
		case '"':
			if err := json.Unmarshal(raw, &value); err != nil {
				return errors.New("invalid Amnezia parameter " + name)
			}
		case '{', '[':
			return errors.New("invalid Amnezia parameter " + name)
		}
		if value != "" {
			iface.Key(name).SetValue(value)
		}
	}
	return nil
}
