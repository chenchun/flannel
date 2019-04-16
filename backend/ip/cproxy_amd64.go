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
// +build !windows

package ip

//#cgo CFLAGS: -I ../udp/
//#include "ip_proxy_amd64.h"
import "C"

import (
	"os"
	"reflect"
	"unsafe"

	log "github.com/golang/glog"

	"github.com/coreos/flannel/pkg/ip"
)

func runCProxy(tun *os.File, tcpSock, udpSock, icmpSock, icmpRecv int, ctl *os.File, tunIP, localIP ip.IP4, mtu, overhead int) {
	var log_errors int
	if log.V(1) {
		log_errors = 1
	}
	C.run_ip_proxy(
		C.int(tun.Fd()),
		C.int(tcpSock),
		C.int(udpSock),
		C.int(icmpSock),
		C.int(icmpRecv),
		C.int(ctl.Fd()),
		C.in_addr_t(tunIP.NetworkOrder()),
		C.in_addr_t(localIP.NetworkOrder()),
		C.size_t(mtu),
		C.size_t(overhead),
		C.int(log_errors),
	)
}

func writeCommand(f *os.File, cmd *C.command) {
	hdr := reflect.SliceHeader{
		Data: uintptr(unsafe.Pointer(cmd)),
		Len:  int(unsafe.Sizeof(*cmd)),
		Cap:  int(unsafe.Sizeof(*cmd)),
	}
	buf := *(*[]byte)(unsafe.Pointer(&hdr))

	f.Write(buf)
}

func setRoute(ctl *os.File, dst ip.IP4Net, nextHopIP ip.IP4) {
	cmd := C.command{
		cmd:           C.IP_CMD_SET_ROUTE,
		dest_net:      C.in_addr_t(dst.IP.NetworkOrder()),
		dest_net_len:  C.int(dst.PrefixLen),
		next_hop_ip:   C.in_addr_t(nextHopIP.NetworkOrder()),
	}

	writeCommand(ctl, &cmd)
}

func removeRoute(ctl *os.File, dst ip.IP4Net) {
	cmd := C.command{
		cmd:          C.IP_CMD_DEL_ROUTE,
		dest_net:     C.in_addr_t(dst.IP.NetworkOrder()),
		dest_net_len: C.int(dst.PrefixLen),
	}

	writeCommand(ctl, &cmd)
}

func stopProxy(ctl *os.File) {
	cmd := C.command{
		cmd: C.IP_CMD_STOP,
	}

	writeCommand(ctl, &cmd)
}
