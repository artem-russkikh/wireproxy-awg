package wireproxy

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/go-ini/ini"

	"net/netip"
)

type PeerConfig struct {
	PublicKey    string
	PreSharedKey string
	Endpoint     *string
	KeepAlive    int
	AllowedIPs   []netip.Prefix
}

// DeviceConfig contains the information to initiate a wireguard connection
type DeviceConfig struct {
	SecretKey          string
	Endpoint           []netip.Addr
	Peers              []PeerConfig
	DNS                []netip.Addr
	MTU                int
	ListenPort         *int
	CheckAlive         []netip.Addr
	CheckAliveInterval int
	ASecConfig         *ASecConfigType
}

type TCPClientTunnelConfig struct {
	BindAddress *net.TCPAddr
	Target      string
}

type STDIOTunnelConfig struct {
	Target string
}

type TCPServerTunnelConfig struct {
	ListenPort int
	Target     string
}

type Socks5Config struct {
	BindAddress string
	Username    string
	Password    string
}

type HTTPConfig struct {
	BindAddress string
	Username    string
	Password    string
}

// PACConfig holds the configuration for the built-in gfwlist2pac HTTP server.
// The server listens on BindAddress and serves a generated PAC file at /proxy.pac.
//
// Example config section:
//
//	[PAC]
//	BindAddress = 127.0.0.1:8080
//	GFWList     = https://cdn.jsdelivr.net/gh/gfwlist/gfwlist/gfwlist.txt
//	CacheFile   = /var/cache/wireproxy/gfwlist.txt  # optional, recommended with URL
//	ExtraRules  = /etc/wireproxy/extra_rules.txt     # optional
//	ProxyOrder  = SOCKS5,SOCKS,DIRECT
type PACConfig struct {
	// BindAddress is the local address on which the PAC HTTP server listens,
	// e.g. "127.0.0.1:8080".
	BindAddress string
	// GFWList is either a local file path or an HTTP(S) URL pointing to a
	// GFWList-compatible file (plain ABP text, optionally base64-encoded).
	GFWList string
	// CacheFile is an optional path where a downloaded GFWList is persisted.
	// On startup the cached file is preferred over re-downloading.
	// Ignored when GFWList is a local path.
	CacheFile string
	// ExtraRules is an optional path to a plain-text file with additional
	// ABP-format rules that are merged in-memory on top of the base GFWList.
	// The file is never written to CacheFile.
	ExtraRules string
	// ProxyOrder is the ordered list of proxy types for PAC fallback,
	// e.g. ["SOCKS5", "SOCKS", "DIRECT"].
	// Recognised values: SOCKS5, SOCKS, PROXY, DIRECT.
	ProxyOrder []string
	// Proxy is the PAC proxy directive assembled automatically from ProxyOrder
	// and the addresses of the proxy sections in the config.
	// It is populated by ParseConfig and must not be set in the config file.
	Proxy string
}

type Configuration struct {
	Device   *DeviceConfig
	Routines []RoutineSpawner
}

func parseString(section *ini.Section, keyName string) (string, error) {
	key := section.Key(strings.ToLower(keyName))
	if key == nil {
		return "", errors.New(keyName + " should not be empty")
	}
	value := key.String()
	if strings.HasPrefix(value, "$") {
		if strings.HasPrefix(value, "$$") {
			return strings.Replace(value, "$$", "$", 1), nil
		}
		var ok bool
		value, ok = os.LookupEnv(strings.TrimPrefix(value, "$"))
		if !ok {
			return "", errors.New(keyName + " references unset environment variable " + key.String())
		}
		return value, nil
	}
	return key.String(), nil
}

func parsePort(section *ini.Section, keyName string) (int, error) {
	key := section.Key(keyName)
	if key == nil {
		return 0, errors.New(keyName + " should not be empty")
	}

	port, err := key.Int()
	if err != nil {
		return 0, err
	}

	if !(port >= 0 && port < 65536) {
		return 0, errors.New("port should be >= 0 and < 65536")
	}

	return port, nil
}

func parseTCPAddr(section *ini.Section, keyName string) (*net.TCPAddr, error) {
	addrStr, err := parseString(section, keyName)
	if err != nil {
		return nil, err
	}
	return net.ResolveTCPAddr("tcp", addrStr)
}

func parseBase64KeyToHex(section *ini.Section, keyName string) (string, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		return "", err
	}
	result, err := encodeBase64ToHex(key)
	if err != nil {
		return result, err
	}

	return result, nil
}

func encodeBase64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}

func parseNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Addr{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Addr, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func parseCIDRNetIP(section *ini.Section, keyName string) ([]netip.Addr, error) {
	key, err := parseString(section, keyName)
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Addr{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Addr, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}

		if addr, err := netip.ParseAddr(str); err == nil {
			ips = append(ips, addr)
		} else {
			prefix, err := netip.ParsePrefix(str)
			if err != nil {
				return nil, err
			}

			addr := prefix.Addr()
			ips = append(ips, addr)
		}
	}
	return ips, nil
}

func parseAllowedIPs(section *ini.Section) ([]netip.Prefix, error) {
	key, err := parseString(section, "AllowedIPs")
	if err != nil {
		if strings.Contains(err.Error(), "should not be empty") {
			return []netip.Prefix{}, nil
		}
		return nil, err
	}

	keys := strings.Split(key, ",")
	var ips = make([]netip.Prefix, 0, len(keys))
	for _, str := range keys {
		str = strings.TrimSpace(str)
		if len(str) == 0 {
			continue
		}
		prefix, err := netip.ParsePrefix(str)
		if err != nil {
			return nil, err
		}

		ips = append(ips, prefix)
	}
	return ips, nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

// ParseInterface parses the [Interface] section and extract the information into `device`
func ParseInterface(cfg *ini.File, device *DeviceConfig) error {
	sections, err := cfg.SectionsByName("Interface")
	if len(sections) != 1 || err != nil {
		return errors.New("one and only one [Interface] is expected")
	}
	section := sections[0]

	address, err := parseCIDRNetIP(section, "Address")
	if err != nil {
		return err
	}

	device.Endpoint = address

	privKey, err := parseBase64KeyToHex(section, "PrivateKey")
	if err != nil {
		return err
	}
	device.SecretKey = privKey

	dns, err := parseNetIP(section, "DNS")
	if err != nil {
		return err
	}
	device.DNS = dns

	if sectionKey, err := section.GetKey("MTU"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.MTU = value
	}

	if sectionKey, err := section.GetKey("ListenPort"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		device.ListenPort = &value
	}

	checkAlive, err := parseNetIP(section, "CheckAlive")
	if err != nil {
		return err
	}
	device.CheckAlive = checkAlive

	device.CheckAliveInterval = 5
	if sectionKey, err := section.GetKey("CheckAliveInterval"); err == nil {
		value, err := sectionKey.Int()
		if err != nil {
			return err
		}
		if len(checkAlive) == 0 {
			return errors.New("CheckAliveInterval is only valid when CheckAlive is set")
		}

		device.CheckAliveInterval = value
	}

	aSecConfig, err := ParseASecConfig(section)
	if err != nil {
		return err
	}
	device.ASecConfig = aSecConfig

	return nil
}

// ParsePeers parses the [Peer] section and extract the information into `peers`
func ParsePeers(cfg *ini.File, peers *[]PeerConfig) error {
	sections, err := cfg.SectionsByName("Peer")
	if len(sections) < 1 || err != nil {
		return errors.New("at least one [Peer] is expected")
	}

	for _, section := range sections {
		peer := PeerConfig{
			PreSharedKey: "0000000000000000000000000000000000000000000000000000000000000000",
			KeepAlive:    0,
		}

		decoded, err := parseBase64KeyToHex(section, "PublicKey")
		if err != nil {
			return err
		}
		peer.PublicKey = decoded

		if sectionKey, err := section.GetKey("PreSharedKey"); err == nil {
			value, err := encodeBase64ToHex(sectionKey.String())
			if err != nil {
				return err
			}
			peer.PreSharedKey = value
		}

		if sectionKey, err := section.GetKey("Endpoint"); err == nil {
			value := sectionKey.String()
			decoded, err = resolveIPPAndPort(strings.ToLower(value))
			if err != nil {
				return err
			}
			peer.Endpoint = &decoded
		}

		if sectionKey, err := section.GetKey("PersistentKeepalive"); err == nil {
			value, err := sectionKey.Int()
			if err != nil {
				return err
			}
			peer.KeepAlive = value
		}

		peer.AllowedIPs, err = parseAllowedIPs(section)
		if err != nil {
			return err
		}

		*peers = append(*peers, peer)
	}
	return nil
}

func parseTCPClientTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &TCPClientTunnelConfig{}
	tcpAddr, err := parseTCPAddr(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = tcpAddr

	targetSection, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = targetSection

	return config, nil
}

func parseSTDIOTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &STDIOTunnelConfig{}
	targetSection, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = targetSection

	return config, nil
}

func parseTCPServerTunnelConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &TCPServerTunnelConfig{}

	listenPort, err := parsePort(section, "ListenPort")
	if err != nil {
		return nil, err
	}
	config.ListenPort = listenPort

	target, err := parseString(section, "Target")
	if err != nil {
		return nil, err
	}
	config.Target = target

	return config, nil
}

func parseSocks5Config(section *ini.Section) (RoutineSpawner, error) {
	config := &Socks5Config{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, _ := parseString(section, "Username")
	config.Username = username

	password, _ := parseString(section, "Password")
	config.Password = password

	return config, nil
}

func parseHTTPConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &HTTPConfig{}

	bindAddress, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, err
	}
	config.BindAddress = bindAddress

	username, _ := parseString(section, "Username")
	config.Username = username

	password, _ := parseString(section, "Password")
	config.Password = password

	return config, nil
}

func parsePACConfig(section *ini.Section) (RoutineSpawner, error) {
	config := &PACConfig{}

	bindAddr, err := parseString(section, "BindAddress")
	if err != nil {
		return nil, fmt.Errorf("BindAddress: %w", err)
	}
	if bindAddr == "" {
		return nil, errors.New("BindAddress should not be empty")
	}
	if _, _, err := net.SplitHostPort(bindAddr); err != nil {
		return nil, fmt.Errorf("BindAddress: invalid address %q: %w", bindAddr, err)
	}
	config.BindAddress = bindAddr

	gfwlist, err := parseString(section, "GFWList")
	if err != nil {
		return nil, fmt.Errorf("GFWList: %w", err)
	}
	if gfwlist == "" {
		return nil, errors.New("GFWList should not be empty")
	}
	config.GFWList = gfwlist

	proxyOrderStr, err := parseString(section, "ProxyOrder")
	if err != nil {
		return nil, fmt.Errorf("ProxyOrder: %w", err)
	}
	if proxyOrderStr == "" {
		return nil, errors.New("ProxyOrder should not be empty")
	}
	validProxyTypes := map[string]bool{
		"SOCKS5": true,
		"SOCKS":  true,
		"PROXY":  true,
		"DIRECT": true,
	}
	for _, t := range strings.Split(proxyOrderStr, ",") {
		entry := strings.TrimSpace(t)
		if !validProxyTypes[strings.ToUpper(entry)] {
			return nil, fmt.Errorf("ProxyOrder: unknown proxy type %q (allowed: SOCKS5, SOCKS, PROXY, DIRECT)", entry)
		}
		config.ProxyOrder = append(config.ProxyOrder, entry)
	}

	// Optional fields — no error on missing/empty
	config.CacheFile, _ = parseString(section, "CacheFile")
	config.ExtraRules, _ = parseString(section, "ExtraRules")

	return config, nil
}

// buildProxyString assembles the PAC proxy directive
// (e.g. "SOCKS5 127.0.0.1:1088; SOCKS 127.0.0.1:1088; DIRECT")
// from an ordered list of proxy type names and the BindAddresses of the
// proxy sections already parsed into spawners.
//
// Recognised type names (case-insensitive):
//   - SOCKS5 → first [Socks5] section's BindAddress
//   - SOCKS  → first [Socks5] section's BindAddress
//   - PROXY  → first [HTTP] section's BindAddress
//   - DIRECT → no address required
func buildProxyString(order []string, spawners []RoutineSpawner) (string, error) {
	var socks5Addr, httpAddr string
	for _, s := range spawners {
		switch c := s.(type) {
		case *Socks5Config:
			if socks5Addr == "" {
				socks5Addr = c.BindAddress
			}
		case *HTTPConfig:
			if httpAddr == "" {
				httpAddr = c.BindAddress
			}
		}
	}

	var parts []string
	for _, raw := range order {
		switch strings.ToUpper(raw) {
		case "SOCKS5":
			if socks5Addr == "" {
				return "", errors.New("PAC ProxyOrder includes SOCKS5 but no [Socks5] section found")
			}
			parts = append(parts, "SOCKS5 "+socks5Addr)
		case "SOCKS":
			if socks5Addr == "" {
				return "", errors.New("PAC ProxyOrder includes SOCKS but no [Socks5] section found")
			}
			parts = append(parts, "SOCKS "+socks5Addr)
		case "PROXY":
			if httpAddr == "" {
				return "", errors.New("PAC ProxyOrder includes PROXY but no [HTTP] section found")
			}
			parts = append(parts, "PROXY "+httpAddr)
		case "DIRECT":
			parts = append(parts, "DIRECT")
		default:
			return "", fmt.Errorf("PAC ProxyOrder: unknown proxy type %q", raw)
		}
	}

	if len(parts) == 0 {
		return "", errors.New("PAC ProxyOrder is empty")
	}
	return strings.Join(parts, "; "), nil
}

// Takes a function that parses an individual section into a config, and apply it on all
// specified sections
func parseRoutinesConfig(
	routines *[]RoutineSpawner,
	cfg *ini.File,
	sectionName string,
	f func(*ini.Section) (RoutineSpawner, error),
) error {
	sections, err := cfg.SectionsByName(sectionName)
	if err != nil {
		return nil
	}

	for _, section := range sections {
		config, err := f(section)
		if err != nil {
			return err
		}

		*routines = append(*routines, config)
	}

	return nil
}

// ParseConfig takes the path of a configuration file and parses it into Configuration
func ParseConfig(path string) (*Configuration, error) {
	iniOpt := ini.LoadOptions{
		Insensitive:            true,
		AllowShadows:           true,
		AllowNonUniqueSections: true,
	}

	cfg, err := ini.LoadSources(iniOpt, path)
	if err != nil {
		return nil, err
	}

	device := &DeviceConfig{
		MTU: 1420,
	}

	root := cfg.Section("")
	wgConf, err := root.GetKey("WGConfig")
	wgCfg := cfg
	if err == nil {
		wgCfg, err = ini.LoadSources(iniOpt, wgConf.String())
		if err != nil {
			return nil, err
		}
	}

	err = ParseInterface(wgCfg, device)
	if err != nil {
		return nil, err
	}

	err = ParsePeers(wgCfg, &device.Peers)
	if err != nil {
		return nil, err
	}

	var routinesSpawners []RoutineSpawner

	err = parseRoutinesConfig(&routinesSpawners, cfg, "TCPClientTunnel", parseTCPClientTunnelConfig)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "STDIOTunnel", parseSTDIOTunnelConfig)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "TCPServerTunnel", parseTCPServerTunnelConfig)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "Socks5", parseSocks5Config)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "http", parseHTTPConfig)
	if err != nil {
		return nil, err
	}

	err = parseRoutinesConfig(&routinesSpawners, cfg, "PAC", parsePACConfig)
	if err != nil {
		return nil, err
	}

	// Build the Proxy string for each PAC config from ProxyOrder and the
	// addresses of the proxy sections already collected in routinesSpawners.
	for _, spawner := range routinesSpawners {
		pac, ok := spawner.(*PACConfig)
		if !ok {
			continue
		}
		pac.Proxy, err = buildProxyString(pac.ProxyOrder, routinesSpawners)
		if err != nil {
			return nil, err
		}
	}

	return &Configuration{
		Device:   device,
		Routines: routinesSpawners,
	}, nil
}
