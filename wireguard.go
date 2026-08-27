package wireproxy

import (
	"bytes"
	"fmt"
	"strings"
	"sync"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/amnezia-vpn/amneziawg-go/v3/conn"
	"github.com/amnezia-vpn/amneziawg-go/v3/device"
	"github.com/amnezia-vpn/amneziawg-go/v3/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

func persistentKeepaliveRange(peer PeerConfig) (uintRange, error) {
	if peer.keepAliveRange != nil &&
		int(peer.keepAliveRange.min) == peer.KeepAlive &&
		int(peer.keepAliveRange.max) == peer.KeepAliveMax {
		return *peer.keepAliveRange, nil
	}

	maxUint32 := uint64(^uint32(0))
	if peer.KeepAlive < 0 || uint64(peer.KeepAlive) > maxUint32 {
		return uintRange{}, fmt.Errorf("PersistentKeepalive must be between 0 and %d", maxUint32)
	}
	if peer.KeepAliveMax < 0 || uint64(peer.KeepAliveMax) > maxUint32 {
		return uintRange{}, fmt.Errorf("PersistentKeepalive maximum must be between 0 and %d", maxUint32)
	}

	keepAlive := uintRange{min: uint32(peer.KeepAlive), max: uint32(peer.KeepAlive)}
	if peer.KeepAliveMax > peer.KeepAlive {
		keepAlive.max = uint32(peer.KeepAliveMax)
	}
	return keepAlive, nil
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	fmt.Fprintf(&request, "private_key=%s\n", conf.SecretKey)

	if conf.ListenPort != nil {
		fmt.Fprintf(&request, "listen_port=%d\n", *conf.ListenPort)
	}

	if conf.ASecConfig != nil {
		aSecConfig := conf.ASecConfig

		var aSecBuilder strings.Builder

		if aSecConfig.hasJunkPacketCount {
			fmt.Fprintf(&aSecBuilder, "jc=%d\n", aSecConfig.junkPacketCount)
		}
		if aSecConfig.hasJunkPacketMinSize {
			fmt.Fprintf(&aSecBuilder, "jmin=%d\n", aSecConfig.junkPacketMinSize)
		}
		if aSecConfig.hasJunkPacketMaxSize {
			fmt.Fprintf(&aSecBuilder, "jmax=%d\n", aSecConfig.junkPacketMaxSize)
		}
		if aSecConfig.hasInitPacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s1=%d\n", aSecConfig.initPacketJunkSize)
		}
		if aSecConfig.hasResponsePacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s2=%d\n", aSecConfig.responsePacketJunkSize)
		}
		if aSecConfig.hasCookieReplyPacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s3=%d\n", aSecConfig.cookieReplyPacketJunkSize)
		}
		if aSecConfig.hasTransportPacketJunkSize {
			fmt.Fprintf(&aSecBuilder, "s4=%d\n", aSecConfig.transportPacketJunkSize)
		}
		if aSecConfig.hasInitPacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h1=%s\n",
				formatMagicHeaderInterval(aSecConfig.initPacketMagicHeader, aSecConfig.initPacketMagicHeaderMax),
			)
		}
		if aSecConfig.hasResponsePacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h2=%s\n",
				formatMagicHeaderInterval(aSecConfig.responsePacketMagicHeader, aSecConfig.responsePacketMagicHeaderMax),
			)
		}
		if aSecConfig.hasUnderloadPacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h3=%s\n",
				formatMagicHeaderInterval(aSecConfig.underloadPacketMagicHeader, aSecConfig.underloadPacketMagicHeaderMax),
			)
		}
		if aSecConfig.hasTransportPacketMagicHeader {
			fmt.Fprintf(&aSecBuilder,
				"h4=%s\n",
				formatMagicHeaderInterval(aSecConfig.transportPacketMagicHeader, aSecConfig.transportPacketMagicHeaderMax),
			)
		}

		if aSecConfig.i1 != nil {
			fmt.Fprintf(&aSecBuilder, "i1=%s\n", *aSecConfig.i1)
		}
		if aSecConfig.i2 != nil {
			fmt.Fprintf(&aSecBuilder, "i2=%s\n", *aSecConfig.i2)
		}
		if aSecConfig.i3 != nil {
			fmt.Fprintf(&aSecBuilder, "i3=%s\n", *aSecConfig.i3)
		}
		if aSecConfig.i4 != nil {
			fmt.Fprintf(&aSecBuilder, "i4=%s\n", *aSecConfig.i4)
		}
		if aSecConfig.i5 != nil {
			fmt.Fprintf(&aSecBuilder, "i5=%s\n", *aSecConfig.i5)
		}

		if aSecConfig.headerProtectionKey != nil {
			fmt.Fprintf(&aSecBuilder, "header_protection_key=%s\n", *aSecConfig.headerProtectionKey)
		}
		if aSecConfig.contentPaddingAddition != nil {
			fmt.Fprintf(&aSecBuilder, "content_padding_addition=%s\n", aSecConfig.contentPaddingAddition)
		}
		if aSecConfig.rekeyAfterTime != nil {
			fmt.Fprintf(&aSecBuilder, "rekey_after_time=%s\n", aSecConfig.rekeyAfterTime)
		}
		if aSecConfig.rekeyTimeout != nil {
			fmt.Fprintf(&aSecBuilder, "rekey_timeout=%s\n", aSecConfig.rekeyTimeout)
		}
		if aSecConfig.rejectAfterTime != nil {
			fmt.Fprintf(&aSecBuilder, "reject_after_time=%s\n", aSecConfig.rejectAfterTime)
		}
		if aSecConfig.keepaliveTimeout != nil {
			fmt.Fprintf(&aSecBuilder, "keepalive_timeout=%s\n", aSecConfig.keepaliveTimeout)
		}
		if aSecConfig.maxHandshakeAttempts != nil {
			fmt.Fprintf(&aSecBuilder, "max_handshake_attempts=%s\n", aSecConfig.maxHandshakeAttempts)
		}
		if aSecConfig.randomTrailers != nil {
			fmt.Fprintf(&aSecBuilder, "random_trailers=%t\n", *aSecConfig.randomTrailers)
		}
		if aSecConfig.disableCookies != nil {
			fmt.Fprintf(&aSecBuilder, "disable_cookies=%t\n", *aSecConfig.disableCookies)
		}

		request.WriteString(aSecBuilder.String())
	}

	for _, peer := range conf.Peers {
		keepAlive, err := persistentKeepaliveRange(peer)
		if err != nil {
			return nil, err
		}

		fmt.Fprintf(&request, heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%s
				preshared_key=%s
			`),
			peer.PublicKey, keepAlive, peer.PreSharedKey,
		)
		if peer.Endpoint != nil {
			fmt.Fprintf(&request, "endpoint=%s\n", *peer.Endpoint)
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				fmt.Fprintf(&request, "allowed_ip=%s\n", ip.String())
			}
		} else {
			request.WriteString(heredoc.Doc(`
				allowed_ip=0.0.0.0/0
				allowed_ip=::0/0
			`))
		}
	}

	setting := &DeviceSetting{IpcRequest: request.String(), DNS: conf.DNS, DeviceAddr: conf.Endpoint, MTU: conf.MTU}
	return setting, nil
}

// StartWireguard creates a tun interface on netstack given a configuration
func StartWireguard(conf *DeviceConfig, logLevel int) (*VirtualTun, error) {
	setting, err := CreateIPCRequest(conf)
	if err != nil {
		return nil, err
	}

	tun, tnet, err := netstack.CreateNetTUN(setting.DeviceAddr, setting.DNS, setting.MTU)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(logLevel, ""))
	err = dev.IpcSet(setting.IpcRequest)
	if err != nil {
		return nil, err
	}

	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return &VirtualTun{
		Tnet:           tnet,
		Dev:            dev,
		Conf:           conf,
		SystemDNS:      len(setting.DNS) == 0,
		PingRecord:     make(map[string]uint64),
		PingRecordLock: new(sync.Mutex),
	}, nil
}
