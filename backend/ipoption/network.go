package ipoption

import (
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	log "github.com/golang/glog"
	"golang.org/x/net/context"
)

type network struct {
	backend.SimpleNetwork
	SM         subnet.Manager
	subnetsMap *sync.Map // subnet ip as key
	publicIPMap *sync.Map // public ip as key


	subnetMask  net.IPMask
	subnetIPNet *net.IPNet
	publicIP    net.IP
	Network     *net.IPNet
	TunFd       *os.File
	tempIP      []byte

	tcpSocket, udpSocket, icmpSocket int
}

func newNetwork(subnetLease *subnet.Lease, extIface *backend.ExternalInterface, sm subnet.Manager, n ip.IP4Net) *network {
	net := &network{
		SimpleNetwork: backend.SimpleNetwork{
			SubnetLease: subnetLease,
			ExtIface:    extIface,
		},
		SM:          sm,
		publicIP:    subnetLease.Attrs.PublicIP.ToIP(),
		subnetMask:  subnetLease.Subnet.ToIPNet().Mask,
		subnetIPNet: subnetLease.Subnet.ToIPNet(),
		subnetsMap:  &sync.Map{},
		publicIPMap: &sync.Map{},
		Network:     n.ToIPNet(),
		tempIP:      make([]byte, 4),
	}
	copy(net.tempIP, subnetLease.Subnet.IP.ToIP().To4())
	return net
}

func (n *network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.Info("Watching for new subnet leases")
	evts := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, n.SM, n.SubnetLease, evts)
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		n.readEgress(ctx)
		wg.Done()
	}()

	//TODO Fix synchronized read
	//wg.Add(1)
	go func() {
		n.readIngress(ctx, syscall.IPPROTO_TCP)
		wg.Done()
	}()

	//wg.Add(1)
	go func() {
		n.readIngress(ctx, syscall.IPPROTO_UDP)
		wg.Done()
	}()

	//wg.Add(1)
	go func() {
		n.readIngress(ctx, syscall.IPPROTO_ICMP)
		wg.Done()
	}()

	defer wg.Wait()

	for {
		select {
		case evtBatch := <-evts:
			n.handleSubnetEvents(evtBatch)

		case <-ctx.Done():
			return
		}
	}
}

type cachedObj struct {
	dstAddr *syscall.SockaddrInet4
	dstIP   net.IP
}

func (n *network) addLease(lease *subnet.Lease) {
	obj := cachedObj{dstIP: lease.Attrs.PublicIP.ToIP().To4()}
	obj.dstAddr = &syscall.SockaddrInet4{Addr: [4]byte{obj.dstIP[0], obj.dstIP[1], obj.dstIP[2], obj.dstIP[3]}}
	n.subnetsMap.Store(lease.Subnet.IP, &obj)
	n.publicIPMap.Store(lease.Attrs.PublicIP, lease.Subnet.IP.ToIP().To4())
}

func (n *network) delLease(lease *subnet.Lease) {
	n.subnetsMap.Delete(lease.Subnet.IP)
	n.publicIPMap.Delete(lease.Attrs.PublicIP)
}

func (n *network) getDstNode(subnetIP net.IP) *cachedObj {
	if subnetIP == nil {
		return nil
	}
	l, ok := n.subnetsMap.Load(ip.FromIP(subnetIP))
	if ok {
		return l.(*cachedObj)
	}
	return nil
}

func (n *network) getDstSubnet(publicIP net.IP) net.IP {
	if publicIP == nil {
		return nil
	}
	l, ok := n.publicIPMap.Load(ip.FromIP(publicIP))
	if ok {
		return l.(net.IP)
	}
	return nil
}

func (n *network) MTU() int {
	return n.ExtIface.Iface.MTU - 4
}

func (n *network) handleSubnetEvents(batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Infof("Subnet added: %v via %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

			if evt.Lease.Attrs.BackendType != n.Lease().Attrs.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.Lease().Attrs.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}
			n.addLease(&evt.Lease)

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != n.Lease().Attrs.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.Lease().Attrs.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}

			n.delLease(&evt.Lease)

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}
