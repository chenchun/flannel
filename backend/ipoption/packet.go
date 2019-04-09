package ipoption

import (
	"fmt"
	"io"
	"net"
	"os"
	"syscall"

	"github.com/coreos/flannel/backend/ipoption/option"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"golang.org/x/net/context"
)

func (n *network) readEgress(ctx context.Context) {
	buf := make([]byte, 1600)
	glog.Infof("begin reading egress")
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		_, err := n.TunFd.Read(buf)
		if err != nil {
			if err != io.EOF {
				glog.Fatal(err)
			}
		}
		err = n.mangleEgress(buf)
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
	// ignore none overlay packets
	if !n.Network.Contains(ipPacket.SrcIP) || !n.Network.Contains(ipPacket.DstIP) {
		return nil
	}
	// ignore traffic between containers on this host
	if n.SubnetLease.Subnet.ToIPNet().Contains(ipPacket.DstIP) {
		return nil
	}
	//glog.V(4).Infof("From src %s to dst %s", ipPacket.SrcIP.String(), ipPacket.DstIP.String())
	// encoding original container ips
	optData := option.EncodeOptionData(option.NewOption(n.networkMask, ipPacket.SrcIP, ipPacket.DstIP))
	opt := layers.IPv4Option{OptionType: option.IPOptionType, OptionData: optData}
	opt.OptionLength = uint8(len(opt.OptionData)) + 2
	ipPacket.Options = append(ipPacket.Options, opt)
	// change src and dst ip
	ipPacket.SrcIP = n.publicIP
	ipPacket.DstIP = n.getDstNode(ipPacket.DstIP.Mask(n.subnetMask))
	//glog.V(4).Infof("Changed as src %s to dst %s", ipPacket.SrcIP.String(), ipPacket.DstIP.String())
	if ipPacket.DstIP == nil {
		return fmt.Errorf("can't find routes to dst ip %s", ipPacket.DstIP.String())
	}
	dstIP := ipPacket.DstIP
	sBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(sBuf, gopacket.SerializeOptions{
		//ComputeChecksums: true,
		FixLengths: true,
	}, ipPacket, gopacket.Payload(ipPacket.Payload)); err != nil {
		return err
	}
	if err := send(sBuf.Bytes(), dstIP, ipPacket.Protocol); err != nil {
		return fmt.Errorf("failed to send mangled egress packets: %v", err)
	}
	return nil
}

func send(data []byte, dstIP net.IP, proto layers.IPProtocol) error {
	var protocol int
	switch proto {
	case layers.IPProtocolTCP:
		protocol = syscall.IPPROTO_TCP
	case layers.IPProtocolUDP:
		protocol = syscall.IPPROTO_UDP
	case layers.IPProtocolICMPv4:
		protocol = syscall.IPPROTO_RAW
	default:
		return fmt.Errorf("unknow packet protocol %v", proto)
	}
	sock, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, protocol)
	if err != nil {
		return err
	}
	defer syscall.Close(sock)
	if err := syscall.SetsockoptInt(sock, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return err
	}
	var addr syscall.SockaddrInet4
	ip := dstIP.To4()
	addr.Addr = [4]byte{ip[0], ip[1], ip[2], ip[3]}
	return syscall.Sendto(sock, data, 0, &addr)
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
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		buf := make([]byte, 1600)
		_, err := f.Read(buf)
		if err != nil {
			fmt.Println(err)
		}
		err = n.mangleIngress(buf)
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
	opt, err := option.DecodeOptionData(ipPacket.Options[0].OptionData, n.prefixBits)
	if err != nil {
		return err
	}
	glog.V(4).Infof("From src ip %s to dst ip %s, options %v, decoded to %v", ipPacket.SrcIP.String(), ipPacket.DstIP.String(), ipPacket.Options, opt)
	ipPacket.Options = nil
	ipPacket.DstIP = opt.DstIP
	ipPacket.SrcIP = opt.SrcIP
	sBuf := gopacket.NewSerializeBuffer()
	if err := gopacket.SerializeLayers(sBuf, gopacket.SerializeOptions{
		//ComputeChecksums: true,
		FixLengths: true,
	}, ipPacket, gopacket.Payload(ipPacket.Payload)); err != nil {
		return err
	}
	if err := send(sBuf.Bytes(), opt.DstIP, ipPacket.Protocol); err != nil {
		return err
	}
	return nil
}
