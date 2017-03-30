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
	"os/exec"
	"strings"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/backend/l3backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

const (
	backendType      = "ipip"
	tunnelName       = "tunl0"
	tunnelMaxMTU     = 1480
	tunnelDefaultMTU = 1480
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
		glog.Infof("will try to create %v", tunnelName)
		// run below command will create tunl0 dev. could also use `ip tunnel add tunl0 mode ipip` command
		cmd := exec.Command("ip", "tunnel", "add", tunnelName, "mode", "ipip")
		err := cmd.Run()
		if err != nil {
			glog.Errorf("failed to create tunnel %v: %v", tunnelName, err)
			return nil, err
		}
		link, err = netlink.LinkByName(tunnelName)
		if err != nil {
			glog.Errorf("failed to find tunnel dev %v: %v", tunnelName, err)
			return nil, err
		}
		glog.Infof("create %v success", tunnelName)
	}
	if link.Type() != "ipip" {
		glog.Errorf("%v not in ipip mode, current type is %v", tunnelName, link.Type())
		return nil, fmt.Errorf("%v not in ipip mode", tunnelName)
	}
	err = checkTunnelUsable()
	if err != nil {
		glog.Errorf("check tunnel dev error: ", err)
		return nil, err
	}
	oldMTU := link.Attrs().MTU
	if oldMTU > tunnelMaxMTU {
		glog.Warningf("%v MTU(%v) greater than %v, will reset to 1480", tunnelName, oldMTU, tunnelMaxMTU)
		err := netlink.LinkSetMTU(link, tunnelMaxMTU)
		if err != nil {
			glog.Errorf("failed to set %v MTU to %v: %v", tunnelName, tunnelMaxMTU, err)
			return nil, err
		}
	} else if oldMTU == 0 {
		glog.Warningf("%v MTU is 0, reset to default MTU %v", tunnelName, tunnelDefaultMTU)
		err := netlink.LinkSetMTU(link, tunnelDefaultMTU)
		if err != nil {
			glog.Errorf("failed to set %v MTU to %v: %v", tunnelName, tunnelDefaultMTU, err)
			return nil, err
		}
	}

	if link.Attrs().Flags&net.FlagUp == 0 {
		glog.Warningf("%v is not UP, will up it", tunnelName)
		err := netlink.LinkSetUp(link)
		if err != nil {
			glog.Errorf("failed to set %v UP: %v", tunnelName, err)
			return nil, err
		}
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_V4)
	if err != nil {
		glog.Errorf("failed to list addr for dev %v: %v", tunnelName, err)
		return nil, err
	}

	// first IP. if subnet is 172.17.100.1/24, ip will be 172.17.100.0
	newAddr := lease.Subnet.Network().IP.ToIP()
	found := false
	for _, oldAddr := range addrs {
		if oldAddr.IP.Equal(newAddr) {
			found = true
			continue
		}
		glog.Infof("will delete old %v addr %v", tunnelName, oldAddr.IP.String())
		err = netlink.AddrDel(link, &oldAddr)
		if err != nil {
			glog.Errorf("failed to remove old %v addr(%v): %v", tunnelName, oldAddr.IP.String(), err)
			return nil, err
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
		err = netlink.AddrAdd(link, addr)
		if err != nil {
			glog.Errorf("failed to add %v addr(%v): %v", tunnelName, addr.IP, err)
			return nil, err
		}
	}
	glog.Infof("tunnel info dump: %+v", link)
	return &tunnelDev{link: link}, nil
}

func checkTunnelUsable() error {
	cmd := exec.Command("ip", "tunnel", "show", tunnelName)
	bytes, err := cmd.CombinedOutput()
	if err != nil {
		return err
	}
	output := string(bytes)
	glog.V(4).Infof("get tunnel %v info: %v", tunnelName, output)
	if strings.Contains(output, "local any") && strings.Contains(output, "remote any") {
		return nil
	}
	return fmt.Errorf("tunnel %v not in remote any local any state", tunnelName)
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
