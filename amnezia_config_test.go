package wireproxy

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseAmneziaConfig(t *testing.T) {
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	native := "[Interface]\nAddress = 10.8.0.2/32\nPrivateKey = " + key +
		"\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nJc = 3\nJmin = 10\nJmax = 50\n" +
		"[Peer]\nPublicKey = " + key + "\nEndpoint = 192.0.2.1:51820\n" +
		"AllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 20-25\n"
	client, err := json.Marshal(map[string]any{"config": native, "mtu": "1376", "Jc": 4})
	if err != nil {
		t.Fatal(err)
	}
	var profile amneziaProfile
	err = json.Unmarshal([]byte(`{"defaultContainer":"amnezia-awg2","dns1":"192.0.2.53",
		"containers":[{"container":"amnezia-awg","awg":{"last_config":"wrong config"}},
		              {"container":"amnezia-awg2"}]}`), &profile)
	if err != nil {
		t.Fatal(err)
	}
	profile.Containers[1].AWG.LastConfig = string(client)
	data, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	var packed bytes.Buffer
	packed.Write(binary.BigEndian.AppendUint32(nil, uint32(len(data))))
	writer := zlib.NewWriter(&packed)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	link := amneziaScheme + base64.RawURLEncoding.EncodeToString(packed.Bytes())
	dir := t.TempDir()
	plainConfig := filepath.Join(dir, "tunnel.conf")
	plain := strings.ReplaceAll(native, "$PRIMARY_DNS, $SECONDARY_DNS", "192.0.2.53")
	plain = strings.ReplaceAll(plain, "Jc = 3", "Jc = 4\nMTU = 1376")
	if err := os.WriteFile(plainConfig, []byte(plain), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, content, bindAddress string
	}{
		{"link file", "\uFEFF" + link + "\r\n", "127.0.0.1:1080"},
		{"inline link", "WGConfig = " + link + "\n[Socks5]\nBindAddress = 127.0.0.1:25344\n", "127.0.0.1:25344"},
		{"inline INI", plain + "[Socks5]\nBindAddress = 127.0.0.1:25344\n", "127.0.0.1:25344"},
		{"INI path", "WGConfig = " + plainConfig + "\n[Socks5]\nBindAddress = 127.0.0.1:25344\n", "127.0.0.1:25344"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "wireproxy.conf")
			if err := os.WriteFile(path, []byte(tc.content), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := ParseConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			device := cfg.Device
			if device.MTU != 1376 || !reflect.DeepEqual(device.DNS, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) ||
				device.ASecConfig == nil || device.ASecConfig.junkPacketCount != 4 ||
				len(device.Peers) != 1 || device.Peers[0].KeepAliveMax != 25 {
				t.Fatal("incorrect tunnel parameters")
			}
			if len(cfg.Routines) != 1 {
				t.Fatal("expected one proxy listener")
			}
			if socks, ok := cfg.Routines[0].(*Socks5Config); !ok || socks.BindAddress != tc.bindAddress {
				t.Fatal("incorrect SOCKS5 listener")
			}
		})
	}
}

func TestDecodeAmneziaProfileRejectsMalformedLink(t *testing.T) {
	for _, payload := range []string{"", "invalid!", "AAAKMg", "_____w"} {
		if _, err := decodeAmneziaProfile(amneziaScheme + payload); err == nil {
			t.Fatal("accepted malformed Amnezia link")
		}
	}
}
