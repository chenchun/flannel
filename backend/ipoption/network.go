package ipoption

import (
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/backend/ipoption/option"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	log "github.com/golang/glog"
	"golang.org/x/net/context"
)

type network struct {
	backend.SimpleNetwork
	SM         subnet.Manager
	subnetsMap *sync.Map

	subnetMask  net.IPMask
	subnetIPNet *net.IPNet
	publicIP    net.IP
	opt         *option.Option
	Network     *net.IPNet
	TunFd       *os.File
	tempIP      []byte
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
		Network:     n.ToIPNet(),
		tempIP:      make([]byte, 4),
	}
	net.opt = option.New(n.ToIPNet())
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

func (n *network) addLease(lease *subnet.Lease) {
	n.subnetsMap.Store(lease.Subnet.IP, lease.Attrs.PublicIP.ToIP())
}

func (n *network) delLease(lease *subnet.Lease) {
	n.subnetsMap.Delete(lease.Subnet.IP)
}

func (n *network) getDstNode(subnetIP net.IP) net.IP {
	if subnetIP == nil {
		return nil
	}
	l, ok := n.subnetsMap.Load(ip.FromIP(subnetIP))
	if ok {
		return l.(net.IP)
	}
	return nil
}

func (n *network) MTU() int {
	return n.ExtIface.Iface.MTU
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
