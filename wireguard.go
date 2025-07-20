package wireproxy

import (
	"bytes"
	"fmt"
	"strings"

	"net/netip"

	"github.com/MakeNowJust/heredoc/v2"
	"github.com/amnezia-vpn/amneziawg-go/conn"
	"github.com/amnezia-vpn/amneziawg-go/device"
	"github.com/amnezia-vpn/amneziawg-go/tun/netstack"
)

// DeviceSetting contains the parameters for setting up a tun interface
type DeviceSetting struct {
	IpcRequest string
	DNS        []netip.Addr
	DeviceAddr []netip.Addr
	MTU        int
}

// CreateIPCRequest serialize the config into an IPC request and DeviceSetting
func CreateIPCRequest(conf *DeviceConfig) (*DeviceSetting, error) {
	var request bytes.Buffer

	request.WriteString(fmt.Sprintf("private_key=%s\n", conf.SecretKey))

	if conf.ListenPort != nil {
		request.WriteString(fmt.Sprintf("listen_port=%d\n", *conf.ListenPort))
	}

	if conf.ASecConfig != nil {
		aSecConfig := conf.ASecConfig

		var aSecBuilder strings.Builder

		aSecBuilder.WriteString(fmt.Sprintf("jc=%d\n", aSecConfig.junkPacketCount))
		aSecBuilder.WriteString(fmt.Sprintf("jmin=%d\n", aSecConfig.junkPacketMinSize))
		aSecBuilder.WriteString(fmt.Sprintf("jmax=%d\n", aSecConfig.junkPacketMaxSize))
		aSecBuilder.WriteString(fmt.Sprintf("s1=%d\n", aSecConfig.initPacketJunkSize))
		aSecBuilder.WriteString(fmt.Sprintf("s2=%d\n", aSecConfig.responsePacketJunkSize))
		aSecBuilder.WriteString(fmt.Sprintf("h1=%d\n", aSecConfig.initPacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h2=%d\n", aSecConfig.responsePacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h3=%d\n", aSecConfig.underloadPacketMagicHeader))
		aSecBuilder.WriteString(fmt.Sprintf("h4=%d\n", aSecConfig.transportPacketMagicHeader))

		if aSecConfig.i1 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i1=%s\n", *aSecConfig.i1))
		}
		if aSecConfig.i2 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i2=%s\n", *aSecConfig.i2))
		}
		if aSecConfig.i3 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i3=%s\n", *aSecConfig.i3))
		}
		if aSecConfig.i4 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i4=%s\n", *aSecConfig.i4))
		}
		if aSecConfig.i5 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("i5=%s\n", *aSecConfig.i5))
		}
		if aSecConfig.j1 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("j1=%s\n", *aSecConfig.j1))
		}
		if aSecConfig.j2 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("j2=%s\n", *aSecConfig.j2))
		}
		if aSecConfig.j3 != nil {
			aSecBuilder.WriteString(fmt.Sprintf("j3=%s\n", *aSecConfig.j3))
		}
		if aSecConfig.itime != nil {
			aSecBuilder.WriteString(fmt.Sprintf("itime=%d\n", *aSecConfig.itime))
		}

		request.WriteString(aSecBuilder.String())
	}

	for _, peer := range conf.Peers {
		request.WriteString(fmt.Sprintf(heredoc.Doc(`
				public_key=%s
				persistent_keepalive_interval=%d
				preshared_key=%s
			`),
			peer.PublicKey, peer.KeepAlive, peer.PreSharedKey,
		))
		if peer.Endpoint != nil {
			request.WriteString(fmt.Sprintf("endpoint=%s\n", *peer.Endpoint))
		}

		if len(peer.AllowedIPs) > 0 {
			for _, ip := range peer.AllowedIPs {
				request.WriteString(fmt.Sprintf("allowed_ip=%s\n", ip.String()))
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
		Tnet:       tnet,
		Dev:        dev,
		Conf:       conf,
		SystemDNS:  len(setting.DNS) == 0,
		PingRecord: make(map[string]uint64),
	}, nil
}
