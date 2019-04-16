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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <memory.h>
#include <assert.h>

#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <fcntl.h>
#include <pthread.h>

#define IP_CMD_DEFINE
#include "ip_proxy_amd64.h"

struct ip_net {
	in_addr_t ip;
	in_addr_t mask;
};

struct route_entry {
	struct ip_net      dst;
	struct sockaddr_in next_hop;
};

typedef struct icmp_pkt {
	struct iphdr   iph;
	struct icmphdr icmph;
	/* dest unreachable must include IP hdr 8 bytes of upper layer proto
	 * of the original packet. */
	char    data[sizeof(struct iphdr) + MAX_IPOPTLEN + 8];
} __attribute__ ((aligned (4))) icmp_pkt;

/* we calc hdr checksums using 32bit uints that can alias other types */
typedef uint32_t __attribute__((__may_alias__)) aliasing_uint32_t;

struct route_entry *routes;
size_t routes_alloc;
size_t routes_cnt;

in_addr_t tun_addr;
in_addr_t local_addr;

int log_enabled;
int exit_flag;

static inline in_addr_t netmask(int prefix_len) {
	return htonl(~((uint32_t)0) << (32 - prefix_len));
}

static inline int contains(struct ip_net net, in_addr_t ip) {
	return net.ip == (ip & net.mask);
}

static void log_error(const char *fmt, ...) {
	va_list ap;

	if( log_enabled ) {
		va_start(ap, fmt);
		vfprintf(stderr, fmt, ap);
		va_end(ap);
	}
}

/* fast version -- only works with mults of 4 bytes */
static uint16_t cksum(aliasing_uint32_t *buf, int len) {
	uint32_t sum = 0;
	uint16_t t1, t2;

	for( ; len > 0; len-- ) {
		uint32_t s = *buf++;
		sum += s;
		if( sum < s )
			sum++;
	}

	/* Fold down to 16 bits */
	t1 = sum;
	t2 = sum >> 16;
	t1 += t2;
	if( t1 < t2 )
		t1++;

	return ~t1;
}

static void send_net_unreachable(int tun, char *offender) {
	icmp_pkt pkt;
	int off_iph_len;
	struct iphdr *off_iph = (struct iphdr *)offender;
	size_t pktlen, nsent;

	off_iph_len = off_iph->ihl * 4;
	if( off_iph_len >= sizeof(struct iphdr) + MAX_IPOPTLEN ) {
		log_error("not sending net unreachable: mulformed ip pkt: iph=%d\n", (int)off_iph_len);
		return; /* ip pkt mulformed */
	}

	if( off_iph->protocol == IPPROTO_ICMP ) {
		/* To avoid infinite loops, RFC 792 instructs not to send ICMPs
		 * about ICMPs */
		return;
	}

	/* Lower 3 bits (in network order) of frag_off is actually flags */
	if( (off_iph->frag_off & htons(0x1FFF)) != 0 ) {
		/* ICMP messages are only sent for first fragment */
		return;
	}

	pktlen = sizeof(struct iphdr) + sizeof(struct icmphdr) + off_iph_len + 8;

	memset(&pkt, 0, sizeof(pkt));

	/* Fill in the IP header */
	pkt.iph.ihl = sizeof(struct iphdr) / 4;
	pkt.iph.version = IPVERSION;
	pkt.iph.tot_len = htons(pktlen);
	pkt.iph.ttl = 8;
	pkt.iph.protocol = IPPROTO_ICMP;
	pkt.iph.saddr = tun_addr;
	pkt.iph.daddr = off_iph->saddr;
	pkt.iph.check = cksum((aliasing_uint32_t*) &pkt.iph, sizeof(struct iphdr) / sizeof(aliasing_uint32_t));

	/* Fill in the ICMP header */
	pkt.icmph.type = ICMP_DEST_UNREACH;
	pkt.icmph.code = ICMP_NET_UNREACH;

	/* Copy the offenders IP hdr + first 8 bytes of IP payload */
	memcpy(pkt.data, offender, off_iph_len + 8);

	/* Compute the checksum over the ICMP header and data */
	pkt.icmph.checksum = cksum((aliasing_uint32_t*) &pkt.icmph,
			(sizeof(struct icmphdr) + off_iph_len + 8) / sizeof(aliasing_uint32_t));

	/* Kick it back */
	nsent = write(tun, &pkt, pktlen);

	if( nsent < 0 ) {
		log_error("failed to send ICMP net unreachable: %s\n", strerror(errno));
	} else if( nsent != pktlen ) {
		log_error("failed to send ICMP net unreachable: only %d out of %d byte sent\n", (int)nsent, (int)pktlen);
	}
}

static int set_route(struct ip_net dst, struct sockaddr_in *next_hop) {
	size_t i;

	for( i = 0; i < routes_cnt; i++ ) {
		if( dst.ip == routes[i].dst.ip && dst.mask == routes[i].dst.mask ) {
			routes[i].next_hop = *next_hop;
			return 0;
		}
	}

	if( routes_alloc == routes_cnt ) {
		int new_alloc = (routes_alloc ? 2*routes_alloc : 8);
		struct route_entry *new_routes = (struct route_entry *) realloc(routes, new_alloc*sizeof(struct route_entry));
		if( !new_routes )
			return ENOMEM;

		routes = new_routes;
		routes_alloc = new_alloc;
	}

	routes[routes_cnt].dst = dst;
	routes[routes_cnt].next_hop = *next_hop;
	routes_cnt++;

	return 0;
}

static int del_route(struct ip_net dst) {
	size_t i;

	for( i = 0; i < routes_cnt; i++ ) {
		if( dst.ip == routes[i].dst.ip && dst.mask == routes[i].dst.mask ) {
			routes[i] = routes[routes_cnt-1];
			routes_cnt--;
			return 0;
		}
	}

	return ENOENT;
}

static struct sockaddr_in *find_route(in_addr_t dst) {
	size_t i;

	for( i = 0; i < routes_cnt; i++ ) {
		if( contains(routes[i].dst, dst) ) {
			// packets for same dest tend to come in bursts. swap to front make it faster for subsequent ones
			if( i != 0 ) {
				struct route_entry tmp = routes[i];
				routes[i] = routes[0];
				routes[0] = tmp;
			}

			return &routes[0].next_hop;
		}
	}

	return NULL;
}

static in_addr_t *find_subnet(in_addr_t public_ip) {
	size_t i;

	for( i = 0; i < routes_cnt; i++ ) {
		if(routes[i].next_hop.sin_addr.s_addr == public_ip) {
			// packets for same dest tend to come in bursts. swap to front make it faster for subsequent ones
			if( i != 0 ) {
				struct route_entry tmp = routes[i];
				routes[i] = routes[0];
				routes[0] = tmp;
			}

			return &routes[0].dst.ip;
		}
	}

	return NULL;
}

static char *inaddr_str(in_addr_t a, char *buf, size_t len) {
	struct in_addr addr;
	addr.s_addr = a;

	strncpy(buf, inet_ntoa(addr), len);
	buf[len-1] = '\0';

	return buf;
}

static ssize_t tun_recv_packet(int tun, char *buf, size_t buflen) {
	ssize_t nread = read(tun, buf, buflen);

	if( nread < sizeof(struct iphdr) ) {
		if( nread < 0 ) {
			if( errno != EAGAIN && errno != EWOULDBLOCK )
				log_error("TUN recv failed: %s\n", strerror(errno));
		} else {
			log_error("TUN recv packet too small: %d bytes\n", (int)nread);
		}
		return -1;
	}

	return nread;
}

static ssize_t
sock_recv_packet(int sock, char *buf, size_t buflen) {
	ssize_t nread = recv(sock, buf, buflen, 0);

	if( nread < sizeof(struct iphdr) ) {
		if( nread < 0 ) {
			if( errno != EAGAIN && errno != EWOULDBLOCK )
				log_error("recv failed: %s\n", strerror(errno));
		} else {
			log_error("recv packet too small: %d bytes\n", (int)nread);
		}
		return -1;
	}

	return nread;
}

static void sock_send_packet(int sock, char *pkt, size_t pktlen, struct sockaddr_in *dst) {
	ssize_t nsent = sendto(sock, pkt, pktlen, 0, (struct sockaddr *)dst, sizeof(struct sockaddr_in));

	if( nsent != pktlen ) {
		if( nsent < 0 ) {
			log_error("send to %s failed: %s\n",
					inet_ntoa(dst->sin_addr), strerror(errno));
		} else {
			log_error("Was only able to send %d out of %d bytes to %s\n",
					(int)nsent, (int)pktlen, inet_ntoa(dst->sin_addr));
		}
	}
}

static void tun_send_packet(int tun, char *pkt, size_t pktlen) {
	ssize_t nsent;
_retry:
	nsent = write(tun, pkt, pktlen);

	if( nsent != pktlen ) {
		if( nsent < 0 ) {
			if( errno == EAGAIN || errno == EWOULDBLOCK)
				goto _retry;

			log_error("TUN send failed: %s\n", strerror(errno));
		} else {
			log_error("Was only able to send %d out of %d bytes to TUN\n", (int)nsent, (int)pktlen);
		}
	}
}

inline static int decrement_ttl(struct iphdr *iph) {
	if( --(iph->ttl) == 0 ) {
//		char saddr[32], daddr[32];
//		log_error("Discarding IP fragment %s -> %s due to zero TTL\n",
//				inaddr_str(iph->saddr, saddr, sizeof(saddr)),
//				inaddr_str(iph->daddr, daddr, sizeof(daddr)));
		return 0;
	}

	/* patch up IP checksum (see RFC 1624) */
	if( iph->check >= htons(0xFFFFu - 0x100) ) {
		iph->check += htons(0x100) + 1;
	} else {
		iph->check += htons(0x100);
	}

	return 1;
}

static void process_cmd(int ctl) {
	struct command cmd;
	struct ip_net ipn;
	struct sockaddr_in sa = {
		.sin_family = AF_INET
	};

	ssize_t nrecv = recv(ctl, (char *) &cmd, sizeof(cmd), 0);
	if( nrecv < 0 ) {
		log_error("CTL recv failed: %s\n", strerror(errno));
		return;
	}

	if( cmd.cmd == IP_CMD_SET_ROUTE ) {
		ipn.mask = netmask(cmd.dest_net_len);
		ipn.ip = cmd.dest_net & ipn.mask;

		sa.sin_addr.s_addr = cmd.next_hop_ip;
		set_route(ipn, &sa);

	} else if( cmd.cmd == IP_CMD_DEL_ROUTE ) {
		ipn.mask = netmask(cmd.dest_net_len);
		ipn.ip = cmd.dest_net & ipn.mask;

		del_route(ipn);

	} else if( cmd.cmd == IP_CMD_STOP ) {
		exit_flag = 1;
	}
}


size_t MTU;
size_t Overhead;
const uint8_t option_type = 40;

struct proxy {
	int tun;
	int tcp_sock;
	int udp_sock;
	int icmp_sock;
	int icmp_recv;
	int ctl;
};

// ip option header
struct opthdr {
	uint8_t type;
	uint8_t len;
};

struct optdata {
	char src;
	char dst;
};

#define iphdrlen sizeof(struct iphdr)
#define opthdrlen sizeof(struct opthdr)

void printc(const char *fmt, char* p, ssize_t pktlen) {
	log_error(fmt);
	for (ssize_t i = 0; i < pktlen; i++) {
		if (i == 12 || i == 20) {
			log_error("  ");
		}
		log_error("%02hhx ", *p);
		p++;
	}
	log_error("\n");
}

#define LOG(format, ...) ({\
	printf(format, ##__VA_ARGS__);\
	printf("\n");\
})

static ssize_t mangle_egress(char *buf, struct sockaddr_in *next_hop, ssize_t pktlen) {
	char *head = buf + Overhead;
	char* ptr = buf;
	for (; head < buf + Overhead + iphdrlen; ptr++, head++) {
		*ptr = *head;
	}
	struct iphdr *iph = (struct iphdr *)buf;
	struct opthdr *opthdr = (struct opthdr*)ptr;
	opthdr->type = option_type;
	opthdr->len = (uint8_t)Overhead;

	struct optdata *data = (struct optdata*)(ptr+opthdrlen);
	data->src = buf[15];
	data->dst = buf[19];
	iph->saddr = local_addr;
	iph->daddr = next_hop->sin_addr.s_addr;

	// fix length
	pktlen += Overhead;
	iph->ihl += Overhead/4;
	iph->tot_len = htons(pktlen);
	// leave checksum to kernel
	iph->check = 0;
//	iph->check = cksum((aliasing_uint32_t*) &iph, (iphdrlen + Overhead) / sizeof(aliasing_uint32_t));
	return pktlen;
}

static int read_egress(int tun, int tcp_sock, int udp_sock, int icmp_sock, char *buf) {
	struct iphdr *iph;
	struct sockaddr_in *next_hop;

	// read packets starting at the `Overhead` position, so when adding IP options, we only need to move
	// IP Header instead of payload ahead which is more efficiency for packets larger than 40 bytes.
	char *head = buf + Overhead;
	ssize_t pktlen = tun_recv_packet(tun, head, MTU - Overhead);
	if( pktlen < 0 )
		return 0;

	iph = (struct iphdr *)head;

	next_hop = find_route((in_addr_t) iph->daddr);
	if( !next_hop ) {
//		send_net_unreachable(tun, head);
		goto _active;
	}

	int sock;
	switch(iph->protocol) {
		case IPPROTO_TCP:
			sock = tcp_sock;
			break;
		case IPPROTO_UDP:
			sock = udp_sock;
			break;
		case IPPROTO_ICMP:
			sock = icmp_sock;
			break;
		default:
			log_error("Unable to handle proto: %d\n", iph->protocol);
			goto _active;
	}
//	printc("egress unencode:", head, pktlen);
	pktlen = mangle_egress(buf, next_hop, pktlen);
//	printc("egress  encoded:", buf, pktlen);
	sock_send_packet(sock, buf, pktlen, next_hop);
_active:
	return 1;
}

static void mangle_ingress(char *buf, in_addr_t saddr) {
	struct iphdr *iph = (struct iphdr *)buf;
	struct optdata *data = (struct optdata*)(buf+iphdrlen+opthdrlen);
	iph->saddr = saddr;
	buf[15] = data->src;
	iph->daddr = tun_addr;
	buf[19] = data->dst;
}

static int read_ingress(int sock, char *buf) {
	ssize_t pktlen = sock_recv_packet(sock, buf, MTU);
	if( pktlen < 0 )
		return 0;

	struct iphdr *iph = (struct iphdr *)buf;
	if (iph->ihl == 5) {
		// no ip options
		goto _active;
	}
	struct opthdr *opthdr = (struct opthdr*)(buf+iphdrlen);
	if (opthdr->type != option_type) {
		goto _active;
	}
	in_addr_t *saddr = find_subnet((in_addr_t) iph->saddr);
	if (!saddr) {
		goto _active;
	}
	mangle_ingress(buf, *saddr);
//	printc("ingress encoded: ", buf, pktlen);
	struct sockaddr_in sa = {
		.sin_family = AF_INET,
		.sin_addr.s_addr = (in_addr_t)iph->daddr,
	};
//	printc("ingress decoded: ", buf, pktlen);
	sock_send_packet(sock, buf, pktlen, &sa);
_active:
	return 1;
}

void *_process_cmd(void * ptr) {
	struct proxy *p = (struct proxy *) ptr;
	while(1) {
		if (exit_flag) {
			return 0;
		}
		process_cmd(p->ctl);
	}
}

void *_read_egress(void *ptr) {
	struct proxy *p = (struct proxy *) ptr;
	char * buf = (char *) malloc(MTU);
	while(1) {
		if (exit_flag) {
			return 0;
		}
		read_egress(p->tun, p->tcp_sock, p->udp_sock, p->icmp_sock, buf);
	}
}

struct ingress_args {
	struct proxy *p;
	int proto;
};

void *_read_ingress(void *ptr) {
	struct ingress_args *p = (struct ingress_args *) ptr;
	int rcv;
	switch (p->proto) {
		case IPPROTO_TCP:
			rcv = p->p->tcp_sock;
			break;
		case IPPROTO_UDP:
			rcv = p->p->udp_sock;
			break;
		case IPPROTO_ICMP:
			rcv = p->p->icmp_recv;
			break;
	}
	char * buf = (char *) malloc(MTU);
	while(1) {
		if (exit_flag) {
			return 0;
		}
		read_ingress(rcv, buf);
	}
}

void run_ip_proxy(int tun, int tcp_sock, int udp_sock, int icmp_sock, int icmp_recv, int ctl,
				  in_addr_t tun_ip, in_addr_t local_ip, size_t mtu, size_t overhead, int log_errors) {
	exit_flag = 0;
	tun_addr = tun_ip;
	local_addr = local_ip;
	MTU = mtu;
	Overhead = overhead;
	log_enabled = log_errors;
	struct proxy p = {.ctl = ctl, .tun = tun, .tcp_sock = tcp_sock, .udp_sock = udp_sock, .icmp_sock = icmp_sock, .icmp_recv = icmp_recv};
	LOG("tcp %d udp %d icmp %d, ctl %d", p.tcp_sock, p.udp_sock, p.icmp_sock, ctl);

	pthread_t *threads = malloc(sizeof(pthread_t)*5);
	if(pthread_create( &threads[0], NULL, &_process_cmd, &p)) {
		fprintf(stderr,"Error - pthread_create() failed\n");
		exit(EXIT_FAILURE);
	}
	if(pthread_create( &threads[1], NULL, &_read_egress, &p)) {
		fprintf(stderr,"Error - pthread_create() failed\n");
		exit(EXIT_FAILURE);
	}
	struct ingress_args args1 = {.p = &p, .proto = IPPROTO_TCP};
	struct ingress_args args2 = {.p = &p, .proto = IPPROTO_UDP};
	struct ingress_args args3 = {.p = &p, .proto = IPPROTO_ICMP};
	if(pthread_create( &threads[2], NULL, &_read_ingress, &args1)) {
		fprintf(stderr,"Error - pthread_create() failed\n");
		exit(EXIT_FAILURE);
	}
	if(pthread_create( &threads[3], NULL, &_read_ingress, &args2)) {
		fprintf(stderr,"Error - pthread_create() failed\n");
		exit(EXIT_FAILURE);
	}
	if(pthread_create( &threads[4], NULL, &_read_ingress, &args3)) {
		fprintf(stderr,"Error - pthread_create() failed\n");
		exit(EXIT_FAILURE);
	}

	for (int i = 0; i < 5; i++) {
		pthread_join(threads[i], NULL);
	}
}