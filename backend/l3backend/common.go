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

package l3backend

import (
	"bytes"
	"net"
	"sync"
	"time"

	log "github.com/golang/glog"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"

	"github.com/coreos/flannel/subnet"
)

const (
	routeCheckRetries = 10
)

type RouteInfo interface {
	LinkIndex() int
	Flags() int
}

type DevInfo interface {
	MTU() int
}

type L3Network struct {
	Name        string
	BackendType string
	Rl          []netlink.Route
	OwnerLease  *subnet.Lease
	Sm          subnet.Manager

	RouteInfo
	DevInfo
}

func (n *L3Network) Lease() *subnet.Lease {
	return n.OwnerLease
}

func (n *L3Network) MTU() int {
	return n.DevInfo.MTU()
}

func (n *L3Network) Run(ctx context.Context) {
	wg := sync.WaitGroup{}

	log.Info("Watching for new subnet leases")
	evts := make(chan []subnet.Event)
	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, n.Sm, n.OwnerLease, evts)
		wg.Done()
	}()

	n.Rl = make([]netlink.Route, 0, 10)
	wg.Add(1)
	go func() {
		n.routeCheck(ctx)
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

func (n *L3Network) handleSubnetEvents(batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Infof("Subnet added: %v via %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)

			if evt.Lease.Attrs.BackendType != n.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}

			route := netlink.Route{
				Dst:       evt.Lease.Subnet.ToIPNet(),
				Gw:        evt.Lease.Attrs.PublicIP.ToIP(),
				LinkIndex: n.RouteInfo.LinkIndex(),
				Flags:     n.RouteInfo.Flags(),
			}

			// Check if route exists before attempting to add it
			routeList, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{
				Dst: route.Dst,
			}, netlink.RT_FILTER_DST)
			if err != nil {
				log.Warningf("Unable to list routes: %v", err)
			}
			//   Check match on Dst for match on Gw
			if len(routeList) > 0 && !routeList[0].Gw.Equal(route.Gw) {
				// Same Dst different Gw. Remove it, correct route will be added below.
				log.Warningf("Replacing existing route to %v via %v with %v via %v.", evt.Lease.Subnet, routeList[0].Gw, evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)
				if err := netlink.RouteDel(&route); err != nil {
					log.Errorf("Error deleting route to %v: %v", evt.Lease.Subnet, err)
					continue
				}
			}
			if len(routeList) > 0 && routeList[0].Gw.Equal(route.Gw) {
				// Same Dst and same Gw, keep it and do not attempt to add it.
				log.Infof("Route to %v via %v already exists, skipping.", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP)
			} else if err := netlink.RouteAdd(&route); err != nil {
				log.Errorf("Error adding route to %v via %v: %v", evt.Lease.Subnet, evt.Lease.Attrs.PublicIP, err)
				continue
			}
			n.addToRouteList(route)

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			if evt.Lease.Attrs.BackendType != n.BackendType {
				log.Warningf("Ignoring non-%v subnet: type=%v", n.BackendType, evt.Lease.Attrs.BackendType)
				continue
			}

			route := netlink.Route{
				Dst:       evt.Lease.Subnet.ToIPNet(),
				Gw:        evt.Lease.Attrs.PublicIP.ToIP(),
				LinkIndex: n.RouteInfo.LinkIndex(),
				Flags:     n.RouteInfo.Flags(),
			}
			if err := netlink.RouteDel(&route); err != nil {
				log.Errorf("Error deleting route to %v: %v", evt.Lease.Subnet, err)
				continue
			}
			n.removeFromRouteList(route)

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}

func (n *L3Network) addToRouteList(route netlink.Route) {
	for _, r := range n.Rl {
		if routeEqual(r, route) {
			return
		}
	}
	n.Rl = append(n.Rl, route)
}

func (n *L3Network) removeFromRouteList(route netlink.Route) {
	for index, r := range n.Rl {
		if routeEqual(r, route) {
			n.Rl = append(n.Rl[:index], n.Rl[index+1:]...)
			return
		}
	}
}

func (n *L3Network) routeCheck(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(routeCheckRetries * time.Second):
			n.checkSubnetExistInRoutes()
		}
	}
}

func (n *L3Network) checkSubnetExistInRoutes() {
	routeList, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err == nil {
		for _, route := range n.Rl {
			exist := false
			for _, r := range routeList {
				if r.Dst == nil {
					continue
				}
				if routeEqual(r, route) {
					exist = true
					break
				}
			}
			if !exist {
				if err := netlink.RouteAdd(&route); err != nil {
					if nerr, ok := err.(net.Error); !ok {
						log.Errorf("Error recovering route to %v: %v, %v", route.Dst, route.Gw, nerr)
					}
					continue
				} else {
					log.Infof("Route recovered %v : %v", route.Dst, route.Gw)
				}
			}
		}
	}
}

func routeEqual(x, y netlink.Route) bool {
	if x.Dst.IP.Equal(y.Dst.IP) && x.Gw.Equal(y.Gw) && bytes.Equal(x.Dst.Mask, y.Dst.Mask) && x.LinkIndex == y.LinkIndex {
		return true
	}
	return false
}
