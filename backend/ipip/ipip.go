// Copyright 2015 flannel authors
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

package ipip

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/backend/l3backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

const (
	backendType  = "ipip"
	tunnelName   = "tunl0"
	tunnelMaxMTU = 1480
)

func init() {
	backend.Register(backendType, New)
}

type IPIPBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	if !extIface.ExtAddr.Equal(extIface.IfaceAddr) {
		return nil, fmt.Errorf("your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by ipip backend")
	}

	be := &IPIPBackend{
		sm:       sm,
		extIface: extIface,
	}

	return be, nil
}

func (be *IPIPBackend) RegisterNetwork(ctx context.Context, config *subnet.Config) (backend.Network, error) {
	n := &l3backend.L3Network{
		Sm:          be.sm,
		BackendType: backendType,
	}

	attrs, err := newSubnetAttrs(be.extIface.ExtAddr, be.extIface.Mask)
	if err != nil {
		return nil, err
	}

	l, err := be.sm.AcquireLease(ctx, attrs)
	switch err {
	case nil:
		n.OwnerLease = l

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}
	dev, err := configureIPIPDevice(n.OwnerLease)
	if err != nil {
		return nil, err
	}
	n.DevInfo = dev
	cfg := struct {
		Hybrid bool
	}{}
	if len(config.Backend) > 0 {
		if err := json.Unmarshal(config.Backend, &cfg); err != nil {
			return nil, fmt.Errorf("error decoding IPIP backend config: %v", err)
		}
	}

	n.GetRoute = func(lease *subnet.Lease) *netlink.Route {
		route := netlink.Route{
			Dst:       lease.Subnet.ToIPNet(),
			Gw:        lease.Attrs.PublicIP.ToIP(),
			LinkIndex: dev.link.Attrs().Index,
			Flags:     int(netlink.FLAG_ONLINK),
		}
		if cfg.Hybrid && leaseInSameSubnet(lease, n.Lease()) {
			glog.Infof("configure route to %v direct!", lease.Attrs.PublicIP.String())
			route.LinkIndex = be.extIface.Iface.Index
		}
		return &route
	}

	/* NB: docker will create the local route to `sn` */

	return n, nil
}

func configureIPIPDevice(lease *subnet.Lease) (*tunnelDev, error) {
	link, err := netlink.LinkByName(tunnelName)
	if err != nil {
		if err := netlink.LinkAdd(&netlink.Iptun{LinkAttrs: netlink.LinkAttrs{Name: tunnelName}}); err != nil {
			return nil, fmt.Errorf("failed to create tunnel %v: %v", tunnelName, err)
		}
		if link, err = netlink.LinkByName(tunnelName); err != nil {
			return nil, fmt.Errorf("failed to find tunnel dev %v: %v", tunnelName, err)
		}
	} else {
		if link.Type() != "ipip" {
			return nil, fmt.Errorf("%v not in ipip mode", tunnelName)
		}
		ipip := link.(*netlink.Iptun)
		if ipip.Local != nil || ipip.Remote != nil {
			return nil, fmt.Errorf("local %v or remote %v of tunnel %s is not expected", ipip.Local, ipip.Remote, tunnelName)
		}
		oldMTU := link.Attrs().MTU
		if oldMTU > tunnelMaxMTU {
			glog.Warningf("%s MTU(%d) greater than %d, setting it to %d", tunnelName, oldMTU, tunnelMaxMTU, tunnelMaxMTU)
			err := netlink.LinkSetMTU(link, tunnelMaxMTU)
			if err != nil {
				return nil, fmt.Errorf("failed to set %v MTU to %v: %v", tunnelName, tunnelMaxMTU, err)
			}
		} else if oldMTU == 0 {
			glog.Warningf("%v MTU is 0, setting it to %v", tunnelName, tunnelMaxMTU)
			err := netlink.LinkSetMTU(link, tunnelMaxMTU)
			if err != nil {
				return nil, fmt.Errorf("failed to set %v MTU to %v: %v", tunnelName, tunnelMaxMTU, err)
			}
		}
	}
	if link.Attrs().Flags&net.FlagUp == 0 {
		err := netlink.LinkSetUp(link)
		if err != nil {
			return nil, fmt.Errorf("failed to set %v UP: %v", tunnelName, err)
		}
	}
	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("failed to list addr for dev %v: %v", tunnelName, err)
	}
	newAddr := lease.Subnet.Network().IP.ToIP()
	found := false
	for _, oldAddr := range addrs {
		if oldAddr.IP.Equal(newAddr) {
			found = true
			continue
		}
		glog.Infof("deleting old addr %s from %s", oldAddr.IP.String(), tunnelName)
		if err := netlink.AddrDel(link, &oldAddr); err != nil {
			return nil, fmt.Errorf("failed to remove old addr %s from %s: %v", oldAddr.IP.String(), tunnelName, err)
		}
	}
	if !found {
		mask := net.CIDRMask(32, 32)
		ipNet := net.IPNet{
			IP:   newAddr.Mask(mask),
			Mask: mask,
		}
		addr := &netlink.Addr{
			IPNet: &ipNet,
		}
		if err := netlink.AddrAdd(link, addr); err != nil {
			return nil, fmt.Errorf("failed to add addr %s to %s: %v", addr.IP.String(), tunnelName, err)
		}
	}
	return &tunnelDev{link: link}, nil
}

type tunnelDev struct {
	link netlink.Link
}

func (t *tunnelDev) MTU() int {
	return t.link.Attrs().MTU
}

type maskAttrs struct {
	Mask int
}

func newSubnetAttrs(publicIP net.IP, mask int) (*subnet.LeaseAttrs, error) {
	data, err := json.Marshal(maskAttrs{mask})
	if err != nil {
		return nil, err
	}

	return &subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(publicIP),
		BackendType: backendType,
		BackendData: json.RawMessage(data),
	}, nil
}

type routeFunc func(*subnet.Lease) *netlink.Route

func leaseInSameSubnet(a, b *subnet.Lease) bool {
	if len(a.Attrs.BackendData) == 0 || len(b.Attrs.BackendData) == 0 {
		return false
	}
	maskA := maskAttrs{}
	maskB := maskAttrs{}
	if err := json.Unmarshal(a.Attrs.BackendData, &maskA); err != nil {
		return false
	}
	if err := json.Unmarshal(b.Attrs.BackendData, &maskB); err != nil {
		return false
	}
	if maskA.Mask != maskB.Mask {
		return false
	}
	mask := net.CIDRMask(maskA.Mask, 32)
	ipA := a.Attrs.PublicIP.ToIP().Mask(mask)
	ipB := b.Attrs.PublicIP.ToIP().Mask(mask)
	return ipA.Equal(ipB)
}
