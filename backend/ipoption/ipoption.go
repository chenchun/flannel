// +build !windows

// Copyright 2017 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ipoption

import (
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

const (
	backendType = "ipoption"
)

func init() {
	backend.Register(backendType, New)
}

type IPOptionBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	be := &IPOptionBackend{
		sm:       sm,
		extIface: extIface,
	}
	return be, nil
}

func (be *IPOptionBackend) RegisterNetwork(ctx context.Context, wg sync.WaitGroup, config *subnet.Config) (backend.Network, error) {
	var n *network
	l, err := be.sm.AcquireLease(ctx, &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: backendType,
	})
	switch err {
	case nil:
		n = newNetwork(l, be.extIface, be.sm, config.Network)
	case context.Canceled, context.DeadlineExceeded:
		return nil, err
	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	if err := n.initTun(n.SubnetLease, n.Network); err != nil {
		return nil, err
	}
	if err := n.initSocket(); err != nil {
		return nil, err
	}
	return n, nil
}

func (n *network) initTun(lease *subnet.Lease, network *net.IPNet) error {
	var tunName string
	var err error

	n.TunFd, tunName, err = ip.OpenTun("flannel.opt.%d")
	if err != nil {
		return fmt.Errorf("failed to open TUN device: %v", err)
	}

	err = n.configureIface(tunName)
	return err
}

func (n *network) configureIface(ifname string) error {
	iface, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to lookup interface %v", ifname)
	}

	// Ensure that the device has a /32 address so that no broadcast routes are created.
	// This IP is just used as a source address for host to workload traffic (so
	// the return path for the traffic has an address on the flannel network to use as the destination)
	ipNet := &net.IPNet{IP: n.SubnetLease.Subnet.IP.ToIP(), Mask: net.CIDRMask(32, 32)}
	err = netlink.AddrAdd(iface, &netlink.Addr{IPNet: ipNet, Label: ""})
	if err != nil {
		return fmt.Errorf("failed to add IP address %v to %v: %v", ipNet.String(), ifname, err)
	}

	err = netlink.LinkSetMTU(iface, n.MTU())
	if err != nil {
		return fmt.Errorf("failed to set MTU for %v: %v", ifname, err)
	}

	err = netlink.LinkSetUp(iface)
	if err != nil {
		return fmt.Errorf("failed to set interface %v to UP state: %v", ifname, err)
	}

	// explicitly add a route since there might be a route for a subnet already
	// installed by Docker and then it won't get auto added
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: iface.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       n.Network,
	})
	if err != nil && err != syscall.EEXIST {
		return fmt.Errorf("failed to add route (%v -> %v): %v", n.Network, ifname, err)
	}

	return nil
}
