// Copyright 2015 CoreOS, Inc.
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

#ifndef IP_PROXY_H
#define IP_PROXY_H

#include <netinet/in.h>
#include "proxy_amd64.h"

#ifdef IP_CMD_DEFINE
#	define ipcmdexport
#else
#	define ipcmdexport static
#endif

ipcmdexport int IP_CMD_SET_ROUTE = 1;
ipcmdexport int IP_CMD_DEL_ROUTE = 2;
ipcmdexport int IP_CMD_STOP      = 3;

void run_ip_proxy(int tun, int tcp_sock, int udp_sock, int icmp_sock, int icmp_recv, int ctl, in_addr_t tun_ip, in_addr_t local_ip, size_t mtu, size_t overhead, int log_errors);

#endif
