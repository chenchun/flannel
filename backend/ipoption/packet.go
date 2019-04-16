package ipoption

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/coreos/flannel/backend/ipoption/option"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/context"
)

func (n *network) readEgress(ctx context.Context) {
	buf := make([]byte, 1500) // short be 1500
	glog.Infof("begin reading egress")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		num, err := n.TunFd.Read(buf)
		if err != nil {
			if err != io.EOF {
				glog.Fatal(err)
			}
		}
		err = n.mangleEgress(buf[:num])
		if err != nil {
			glog.Warning(err)
		}
	}
}

func (n *network) mangleEgress(buf []byte) error {
	packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Lazy)
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return nil
	}
	ipPacket, _ := ip4Layer.(*layers.IPv4)
	// ignore traffic between containers on this host
	if n.subnetIPNet.Contains(ipPacket.DstIP) {
		return nil
	}
	//glog.V(4).Infof("From src %s to dst %s", ipPacket.SrcIP.String(), ipPacket.DstIP.String())
	// encoding original container ips

	opt := layers.IPv4Option{OptionType: option.IPOptionType, OptionData: []byte{ipPacket.SrcIP.To4()[3], ipPacket.DstIP.To4()[3]}}
	opt.OptionLength = 4
	ipPacket.Options = append(ipPacket.Options, opt)
	// change src and dst ip
	ipPacket.SrcIP = n.publicIP
	cached := n.getDstNode(ipPacket.DstIP.Mask(n.subnetMask))
	if cached == nil {
		return fmt.Errorf("can't find routes to dst ip %s, subnet %s", ipPacket.DstIP.String(), ipPacket.DstIP.Mask(n.subnetMask))
	}
	ipPacket.DstIP = cached.dstIP
	//glog.V(4).Infof("Changed as src %s to dst %s, options: %s", ipPacket.SrcIP.String(), ipPacket.DstIP.String(), hex.EncodeToString(ipPacket.Options[0].OptionData))
	sBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(sBuf, gopacket.SerializeOptions{
		//ComputeChecksums: true,
		FixLengths: true,
	}, ipPacket, gopacket.Payload(ipPacket.Payload)); err != nil {
		return err
	}
	if err := n.send(sBuf.Bytes(), cached.dstAddr, ipPacket.Protocol); err != nil {
		return fmt.Errorf("failed to send mangled egress packets len %d: %v", len(sBuf.Bytes()), err)
	}
	return nil
}

func (n *network) initSocket() (err error) {
	for proto, socketPtr := range map[int]*int{
		syscall.IPPROTO_TCP: &n.tcpSocket,
		syscall.IPPROTO_UDP: &n.udpSocket,
		syscall.IPPROTO_RAW: &n.icmpSocket,
	} {
		*socketPtr, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto)
		if err != nil {
			return
		}
		if err = syscall.SetsockoptInt(*socketPtr, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
			return
		}
	}
	return
}

func (n *network) send(data []byte, addr *syscall.SockaddrInet4, proto layers.IPProtocol) error {
	var socket int
	switch proto {
	case layers.IPProtocolTCP:
		socket = n.tcpSocket
	case layers.IPProtocolUDP:
		socket = n.udpSocket
	case layers.IPProtocolICMPv4:
		socket = n.icmpSocket
	default:
		return fmt.Errorf("unknow packet protocol %v", proto)
	}
	return syscall.Sendto(socket, data, 0, addr)
}

func (n *network) readIngress(ctx context.Context, proto int) {
	// https://www.darkcoding.net/software/raw-sockets-in-go-link-layer/
	// The third parameter filters packets so we only receive ICMP. You need a protocol here. As man 7 raw says “Receiving of all IP protocols via IPPROTO_RAW is not possible using raw sockets”. We’ll do that in the next post in this series, at the physical / device driver layer.
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, proto) //syscall.IPPROTO_ICMP
	if err != nil {
		glog.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), fmt.Sprintf("fd %d", fd))

	glog.Infof("begin reading ingress")
	buf := make([]byte, 1500)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		num, err := f.Read(buf)
		if err != nil {
			fmt.Println(err)
		}
		err = n.mangleIngress(buf[:num])
		if err != nil {
			glog.Warning(err)
		}
	}
}

func (n *network) mangleIngress(buf []byte) error {
	packet := gopacket.NewPacket(buf, layers.LayerTypeIPv4, gopacket.Lazy)
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)
	if ip4Layer == nil {
		return nil
	}
	ipPacket, _ := ip4Layer.(*layers.IPv4)
	if len(ipPacket.Options) == 0 || ipPacket.Options[0].OptionType != option.IPOptionType {
		// TODO Pod may send packets with options?
		// TODO Did we steel the packet from kernel ? do we need to send it ?
		return nil
	}
	optData := ipPacket.Options[0].OptionData
	//glog.V(4).Infof("From src ip %s to dst ip %s, options %v", ipPacket.SrcIP.String(), ipPacket.DstIP.String(), ipPacket.Options)
	ipPacket.Options = nil
	dstIP := n.tempIP
	dstIP[3] = optData[1]
	cachedSubnetIP := n.getDstSubnet(ipPacket.SrcIP)
	if cachedSubnetIP == nil {
		return fmt.Errorf("can't find routes to src ip %s", ipPacket.SrcIP.String())
	}
	srcIP := make([]byte, 4)
	copy(srcIP, cachedSubnetIP)
	srcIP[3] = optData[0]
	ipPacket.DstIP = dstIP
	ipPacket.SrcIP = srcIP
	//glog.V(4).Infof("Decoded to src ip %s to dst ip %s", ipPacket.SrcIP.String(), ipPacket.DstIP.String())
	sBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(sBuf, gopacket.SerializeOptions{
		//ComputeChecksums: true,
		FixLengths: true,
	}, ipPacket, gopacket.Payload(ipPacket.Payload)); err != nil {
		return err
	}
	if err := n.send(sBuf.Bytes(), &syscall.SockaddrInet4{Addr: [4]byte{ipPacket.DstIP[0], ipPacket.DstIP[1], ipPacket.DstIP[2], ipPacket.DstIP[3]}}, ipPacket.Protocol); err != nil {
		return fmt.Errorf("failed to send mangled ingress packets len %d: %v", len(sBuf.Bytes()), err)
	}
	return nil
}
