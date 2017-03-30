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

package hostgw

import (
	"fmt"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/backend/l3backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
)

func init() {
	backend.Register(backendType, New)
}

const (
	backendType = "host-gw"
)

type HostgwBackend struct {
	sm       subnet.Manager
	extIface *backend.ExternalInterface
	networks map[string]*l3backend.L3Network
}

func New(sm subnet.Manager, extIface *backend.ExternalInterface) (backend.Backend, error) {
	if !extIface.ExtAddr.Equal(extIface.IfaceAddr) {
		return nil, fmt.Errorf("your PublicIP differs from interface IP, meaning that probably you're on a NAT, which is not supported by host-gw backend")
	}

	be := &HostgwBackend{
		sm:       sm,
		extIface: extIface,
		networks: make(map[string]*l3backend.L3Network),
	}

	return be, nil
}

func (be *HostgwBackend) RegisterNetwork(ctx context.Context, config *subnet.Config) (backend.Network, error) {
	n := &l3backend.L3Network{
		Sm:          be.sm,
		BackendType: backendType,
	}

	attrs := subnet.LeaseAttrs{
		PublicIP:    ip.FromIP(be.extIface.ExtAddr),
		BackendType: backendType,
	}

	l, err := be.sm.AcquireLease(ctx, &attrs)
	switch err {
	case nil:
		n.OwnerLease = l

	case context.Canceled, context.DeadlineExceeded:
		return nil, err

	default:
		return nil, fmt.Errorf("failed to acquire lease: %v", err)
	}

	n.GetRoute = func(lease *subnet.Lease) *netlink.Route {
		route := netlink.Route{
			Dst:       lease.Subnet.ToIPNet(),
			Gw:        lease.Attrs.PublicIP.ToIP(),
			LinkIndex: be.extIface.Iface.Index,
		}
		return &route
	}
	n.DevInfo = devInfo{mtu: be.extIface.Iface.MTU}

	/* NB: docker will create the local route to `sn` */

	return n, nil
}

type devInfo struct {
	mtu int
}

func (di devInfo) MTU() int {
	return di.mtu
}
