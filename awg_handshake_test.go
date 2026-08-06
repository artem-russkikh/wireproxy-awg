package wireproxy

import (
	"bytes"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn/bindtest"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/tuntest"
)

// The obfuscation parameters have to match on both ends, and a mistake in one
// of them does not show up in the IPC request: the device takes the request,
// and only the handshake that follows fails. These tests therefore run our
// generated request against a second device configured as the peer, and check
// that a packet actually makes it through the tunnel.
//
// clientKey/serverKey are a matching private/public pair each, base64 as a
// config file spells them.
const (
	clientPrivateKey = "YKPH3Kd6yGqw8wbubzDDfQFE3iVOLqSfK2CIUFB9vFs="
	clientPublicKey  = "EPOSjEbCQZttA+BiG6iIDqyRu/xrTT9Jlvi65xHVRAk="
	serverPrivateKey = "2A8O4sFopoHJToUX7XdQ50+gHvoBM/Mq+yrtt654plU="
	serverPublicKey  = "fX1+LM/maMFUfF1A7s0KcEKlNIJbkMFECfSYvcRkyz8="

	clientIP = "1.0.0.1"
	serverIP = "1.0.0.2"

	// bindtest routes by endpoint port; this is the one the client's bind
	// delivers to the server's bind.
	serverEndpoint = "127.0.0.1:1"
)

// tunnelPair is a client device configured through the wireproxy config
// pipeline, wired to a server device configured directly.
type tunnelPair struct {
	clientTUN *tuntest.ChannelTUN
	serverTUN *tuntest.ChannelTUN
	client    *device.Device
	server    *device.Device
}

// newTunnelPair brings up both ends. clientConfig is an ini config parsed the
// way wireproxy parses a real one; serverParams are the [Interface] level UAPI
// lines the server needs to mirror the client's obfuscation.
func newTunnelPair(t *testing.T, clientConfig string, serverParams ...string) *tunnelPair {
	t.Helper()

	iniData, err := loadIniConfig(clientConfig)
	if err != nil {
		t.Fatal(err)
	}

	cfg := DeviceConfig{MTU: device.DefaultMTU}
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

	var serverRequest strings.Builder
	fmt.Fprintf(&serverRequest, "private_key=%s\n", mustHexKey(t, serverPrivateKey))
	for _, param := range serverParams {
		fmt.Fprintf(&serverRequest, "%s\n", param)
	}
	fmt.Fprintf(&serverRequest, "public_key=%s\n", mustHexKey(t, clientPublicKey))
	fmt.Fprintf(&serverRequest, "allowed_ip=%s/32\n", clientIP)

	binds := bindtest.NewChannelBinds()
	pair := &tunnelPair{
		clientTUN: tuntest.NewChannelTUN(),
		serverTUN: tuntest.NewChannelTUN(),
	}

	pair.client = startDevice(t, pair.clientTUN, binds[0], setting.IpcRequest, "client: ")
	pair.server = startDevice(t, pair.serverTUN, binds[1], serverRequest.String(), "server: ")

	pair.warmUp(t)

	return pair
}

// warmUp spends the first data packet, which amneziawg-go v3.0.3 loses whenever
// S4 is set: its TUN reader samples the transport padding once, before it
// blocks on the first read, and that happens while the device is still
// unconfigured. The packet then goes out without the padding and the peer,
// which by now expects it, cannot find the message type and drops it. Only the
// first one is affected - the reader picks up the real padding on its next
// pass. Reproducible against the library alone, so nothing here can avoid it.
func (pair *tunnelPair) warmUp(t *testing.T) {
	t.Helper()

	packet := tuntest.Ping(netip.MustParseAddr(serverIP), netip.MustParseAddr(clientIP))

	select {
	case pair.clientTUN.Outbound <- packet:
	case <-time.After(5 * time.Second):
		t.Fatal("the client tunnel did not accept the warm-up packet")
	}

	// It may or may not arrive, depending on whether the library still has the
	// bug; both are fine, the tunnel is warm either way.
	select {
	case <-pair.serverTUN.Inbound:
	case <-time.After(2 * time.Second):
	}
}

func startDevice(
	t *testing.T,
	channelTUN *tuntest.ChannelTUN,
	bind conn.Bind,
	request string,
	logPrefix string,
) *device.Device {
	t.Helper()

	logLevel := device.LogLevelSilent
	if testing.Verbose() {
		logLevel = device.LogLevelVerbose
	}

	dev := device.NewDevice(channelTUN.TUN(), bind, device.NewLogger(logLevel, logPrefix))
	t.Cleanup(dev.Close)

	if err := dev.IpcSet(request); err != nil {
		t.Fatalf("%sdevice rejected the IPC request: %v\n%s", logPrefix, err, request)
	}
	if err := dev.Up(); err != nil {
		t.Fatalf("%sfailed to bring the device up: %v", logPrefix, err)
	}

	return dev
}

// handshakeDone reports whether the device has completed a handshake with its
// only peer. Used to tell a failed handshake from a lost packet.
func handshakeDone(t *testing.T, dev *device.Device) bool {
	t.Helper()

	state, err := dev.IpcGet()
	if err != nil {
		t.Fatal(err)
	}
	return strings.Contains(state, "last_handshake_time_sec=") &&
		!strings.Contains(state, "last_handshake_time_sec=0\n")
}

// sendThrough pushes a packet into the client tunnel and expects it out of the
// server tunnel unchanged. The packet is also what triggers the handshake:
// wireguard only starts one once there is something to send.
func (pair *tunnelPair) sendThrough(t *testing.T) {
	t.Helper()

	sent := tuntest.Ping(netip.MustParseAddr(serverIP), netip.MustParseAddr(clientIP))

	select {
	case pair.clientTUN.Outbound <- sent:
	case <-time.After(5 * time.Second):
		t.Fatal("the client tunnel did not accept the packet")
	}

	select {
	case received := <-pair.serverTUN.Inbound:
		if !bytes.Equal(sent, received) {
			t.Fatal("the packet came out of the tunnel altered")
		}
	case <-time.After(15 * time.Second):
		if !handshakeDone(t, pair.client) {
			t.Fatal("the handshake never completed")
		}
		t.Fatal("the handshake completed but the packet did not make it through")
	}

	if !handshakeDone(t, pair.client) {
		t.Fatal("the packet arrived without a completed handshake")
	}
}

func mustHexKey(t *testing.T, base64Key string) string {
	t.Helper()

	hexKey, err := encodeBase64ToHex(base64Key)
	if err != nil {
		t.Fatal(err)
	}
	return hexKey
}

func clientConfig(awgParams string) string {
	return fmt.Sprintf(`
[Interface]
PrivateKey = %s
Address = %s/32
%s

[Peer]
PublicKey = %s
AllowedIPs = %s/32
Endpoint = %s
`, clientPrivateKey, clientIP, awgParams, serverPublicKey, serverIP, serverEndpoint)
}

func TestTunnelWithAWG3Params(t *testing.T) {
	pair := newTunnelPair(t, clientConfig(`
Jc = 4
Jmin = 50
Jmax = 500
S1 = 12
S2 = 15
S3 = 18
S4 = 21
H1 = 123456
H2 = 234567
H3 = 345678
H4 = 456789
I1 = <b 0x504f5354><rc 8><t>
HeaderProtectionKey = efpsQ5dEcds7RJIU6wZ5VdMItHGQTL/OBbza0xuVV1w=
ContentPaddingAddition = 10-100
RekeyAfterTime = 100-120
RekeyTimeout = 5
RejectAfterTime = 180-200
KeepaliveTimeout = 10-15
MaxHandshakeAttempts = 18-20
`),
		"s1=12", "s2=15", "s3=18", "s4=21",
		"h1=123456", "h2=234567", "h3=345678", "h4=456789",
		"header_protection_key="+mustHexKey(t, "efpsQ5dEcds7RJIU6wZ5VdMItHGQTL/OBbza0xuVV1w="),
		"content_padding_addition=10-100",
	)

	pair.sendThrough(t)
}

func TestTunnelWithAWG2Params(t *testing.T) {
	pair := newTunnelPair(t, clientConfig(`
Jc = 4
Jmin = 50
Jmax = 500
S1 = 15
S2 = 18
S3 = 20
S4 = 23
H1 = 100-101
H2 = 102-103
H3 = 104
H4 = 105-106
I1 = <b 0xA1B2C3D4E5F6><r 10>
`),
		"s1=15", "s2=18", "s3=20", "s4=23",
		"h1=100-101", "h2=102-103", "h3=104", "h4=105-106",
	)

	pair.sendThrough(t)
}

// A config with no obfuscation at all has to keep talking plain wireguard,
// which is what an AmneziaWG 3.0 build must not break.
func TestTunnelWithPlainWireguard(t *testing.T) {
	pair := newTunnelPair(t, clientConfig(""))

	pair.sendThrough(t)
}
