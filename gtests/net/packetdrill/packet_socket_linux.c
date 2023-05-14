/*
 * Copyright 2013 Google Inc.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */
/*
 * Author: ncardwell@google.com (Neal Cardwell)
 *
 * API to read and write raw packets implemented using Linux packet socket.
 */

#include "packet_socket.h"

#include <errno.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <unistd.h>
#include <sys/socket.h>

#ifdef linux

#include <netpacket/packet.h>
#include <linux/filter.h>
#include <linux/sockios.h>

#include "assert.h"
#include "ethernet.h"
#include "logging.h"

/* Number of bytes to buffer in the packet socket we use for sniffing. */
static const int PACKET_SOCKET_RCVBUF_BYTES = 2*1024*1024;

struct packet_socket {
	int packet_fd;	/* socket for sending, sniffing timestamped packets */
	char *name;	/* malloc-allocated copy of interface name */
	int index;	/* interface index from if_nametoindex */
};

/* Set the receive buffer for a socket to the given size in bytes. */
static void set_receive_buffer_size(int fd, int bytes)
{
	if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bytes, sizeof(bytes)) < 0)
		die_perror("setsockopt SOL_SOCKET SO_RCVBUF");
}

/* Bind the packet socket with the given fd to the given interface. */
static void bind_to_interface(int fd, int interface_index)
{
	struct sockaddr_ll sll;
	memset(&sll, 0, sizeof(sll));
	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= interface_index;
	sll.sll_protocol	= htons(ETH_P_ALL);

	if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0)
		die_perror("bind packet socket");
}

/* Allocate and configure a packet socket just like the one tcpdump
 * uses. We do this so we can get timestamps on the outbound packets
 * the kernel sends, to verify the correct timing (tun devices do not
 * take timestamps). To reduce CPU load and filtering complexity, we
 * bind the socket to a single device so we only receive packets for
 * that device.
 */
static void packet_socket_setup(struct packet_socket *psock)
{
	struct timeval tv;

	psock->packet_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (psock->packet_fd < 0)
		die_perror("socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))");

	psock->index = if_nametoindex(psock->name);
	if (psock->index == 0)
		die_perror("if_nametoindex");
	DEBUGP("device index: %s -> %d\n", psock->name, psock->index);

	bind_to_interface(psock->packet_fd, psock->index);

	set_receive_buffer_size(psock->packet_fd, PACKET_SOCKET_RCVBUF_BYTES);

	/* Pay the non-trivial latency cost to enable timestamps now, before
	 * the test starts, to avoid significant delays in the middle of tests.
	 */
	ioctl(psock->packet_fd, SIOCGSTAMP, &tv);
}

/* Add a filter so we only sniff packets we want. */
void packet_socket_set_filter(struct packet_socket *psock,
			      const struct ip_address *client_live_ip,
			      u16 src_port,
			      u16 dst_port)
{
	struct sock_fprog bpfcode;
	struct sock_filter bpf_ipv4_src[] = {
		/* This filter is constructed to try to allow packetdrill
		 * wire_server processes to only capture traffic under test.
		 * It works for ethernet interfaces. The hex array dump is
		 * copied verbatim from the output of the following tcpdump
		 * command line on a Linux machine:
		 *
		 * tcpdump -p -n -s 0 -i lo -dd
		 * "ip src 1.2.3.4 and "
		 * "(src port 0xaabb or dst port 0xccdd or icmp)"
		 */
		{ 0x28, 0,  0, 0x0000000c },
		{ 0x15, 0, 15, 0x00000800 },	/* ETHERTYPE_IP */
		{ 0x20, 0,  0, 0x0000001a },
		{ 0x15, 0, 13, 0x01020304 },	/* IPv4: 1.2.3.4 */
		{ 0x30, 0,  0, 0x00000017 },
		{ 0x15, 2,  0, 0x00000084 },
		{ 0x15, 1,  0, 0x00000006 },
		{ 0x15, 0,  7, 0x00000011 },
		{ 0x28, 0,  0, 0x00000014 },
		{ 0x45, 7,  0, 0x00001fff },
		{ 0xb1, 0,  0, 0x0000000e },
		{ 0x48, 0,  0, 0x0000000e },
		{ 0x15, 3,  0, 0x0000aabb },	/* src port 0xaabb */
		{ 0x48, 0,  0, 0x00000010 },
		{ 0x15, 1,  2, 0x0000ccdd },	/* dst port 0xccdd */
		{ 0x15, 0,  1, 0x00000001 },
		{ 0x06, 0,  0, 0x00040000 },
		{ 0x06, 0,  0, 0x00000000 },

	};
	struct sock_filter bpf_ipv6_src[] = {
		/* This filter is constructed to try to allow packetdrill
		 * wire_server processes to only capture traffic under test.
		 * It works for ethernet interfaces. The hex array dump is
		 * copied verbatim from the output of the following tcpdump
		 * command line on a Linux machine:
		 *
		 * tcpdump -p -n -s 0 -i lo -dd
		 * "ip6 src 1:2:3:4:5:6:7:8 and "
		 * "(src port 0xaabb or dst port 0xccdd or icmp6)
		 */
		{ 0x28, 0,  0, 0x0000000c },
		{ 0x15, 0, 21, 0x000086dd },	/* ETHERTYPE_IPV6 */
		{ 0x20, 0,  0, 0x00000016 },
		{ 0x15, 0, 19, 0x00010002 },	/* IPv6: 1:2 */
		{ 0x20, 0,  0, 0x0000001a },
		{ 0x15, 0, 17, 0x00030004 },	/* IPv6: 3:4 */
		{ 0x20, 0,  0, 0x0000001e },
		{ 0x15, 0, 15, 0x00050006 },	/* IPv6: 5:6 */
		{ 0x20, 0,  0, 0x00000022 },
		{ 0x15, 0, 13, 0x00070008 },	/* IPv6: 7:8 */
		{ 0x30, 0,  0, 0x00000014 },
		{ 0x15, 2,  0, 0x00000084 },
		{ 0x15, 1,  0, 0x00000006 },
		{ 0x15, 0,  4, 0x00000011 },
		{ 0x28, 0,  0, 0x00000036 },
		{ 0x15, 6,  0, 0x0000aabb },	/* src port 0xaabb */
		{ 0x28, 0,  0, 0x00000038 },
		{ 0x15, 4,  5, 0x0000ccdd },	/* dst port 0xccdd */
		{ 0x15, 3,  0, 0x0000003a },
		{ 0x15, 0,  3, 0x0000002c },
		{ 0x30, 0,  0, 0x00000036 },
		{ 0x15, 0,  1, 0x0000003a },
		{ 0x06, 0,  0, 0x00040000 },
		{ 0x06, 0,  0, 0x00000000 },
	};
	char ip_string[ADDR_STR_LEN];

	DEBUGP("packet_socket_set_filter: ip: %s src: %u dst: %u\n",
	       ip_to_string(client_live_ip, ip_string), src_port, dst_port);

	if (client_live_ip->address_family == AF_INET) {
		/* Fill in the client-side IPv4 address to look for. */
		bpf_ipv4_src[3].k = ntohl(client_live_ip->ip.v4.s_addr);
		/* Fill in the src port to look for. */
		bpf_ipv4_src[12].k = src_port;
		/* Fill in the dst port to look for. */
		bpf_ipv4_src[14].k = dst_port;

		bpfcode.len	= ARRAY_SIZE(bpf_ipv4_src);
		bpfcode.filter	= bpf_ipv4_src;
	} else if (client_live_ip->address_family == AF_INET6) {
		/* Fill in the client-side IPv6 address to look for. */
		bpf_ipv6_src[3].k = ntohl(client_live_ip->ip.v6.s6_addr32[0]);
		bpf_ipv6_src[5].k = ntohl(client_live_ip->ip.v6.s6_addr32[1]);
		bpf_ipv6_src[7].k = ntohl(client_live_ip->ip.v6.s6_addr32[2]);
		bpf_ipv6_src[9].k = ntohl(client_live_ip->ip.v6.s6_addr32[3]);
		/* Fill in the src port to look for. */
		bpf_ipv6_src[15].k = src_port;
		/* Fill in the dst port to look for. */
		bpf_ipv6_src[17].k = dst_port;

		bpfcode.len	= ARRAY_SIZE(bpf_ipv6_src);
		bpfcode.filter	= bpf_ipv6_src;
	} else {
		assert(!"bad address family");
	}

	if (DEBUG_LOGGING) {
		int i;
		DEBUGP("filter constants:\n");
		for (i = 0; i < bpfcode.len; ++i)
			DEBUGP("{ 0x%02x, %3d, %3d, 0x%08x },\n",
			       bpfcode.filter[i].code,
			       bpfcode.filter[i].jt,
			       bpfcode.filter[i].jf,
			       bpfcode.filter[i].k);
	}

	/* Attach the filter. */
	if (setsockopt(psock->packet_fd, SOL_SOCKET, SO_ATTACH_FILTER,
		       &bpfcode, sizeof(bpfcode)) < 0) {
		die_perror("setsockopt SOL_SOCKET, SO_ATTACH_FILTER");
	}
}

struct packet_socket *packet_socket_new(const char *device_name)
{
	struct packet_socket *psock = calloc(1, sizeof(struct packet_socket));

	psock->name = strdup(device_name);
	psock->packet_fd = -1;

	packet_socket_setup(psock);

	return psock;
}

void packet_socket_free(struct packet_socket *psock)
{
	if (psock->packet_fd >= 0)
		close(psock->packet_fd);

	if (psock->name != NULL)
		free(psock->name);

	memset(psock, 0, sizeof(*psock));	/* paranoia to catch bugs*/
	free(psock);
}

int packet_socket_writev(struct packet_socket *psock,
			 const struct iovec *iov, int iovcnt)
{
	if (writev(psock->packet_fd, iov, iovcnt) < 0) {
		perror("writev");
		return STATUS_ERR;
	}
	return STATUS_OK;
}

int packet_socket_receive(struct packet_socket *psock,
			  enum direction_t direction, s32 timeout_secs,
			  struct packet *packet, int *in_bytes)
{
	struct sockaddr_ll from;
	memset(&from, 0, sizeof(from));
	socklen_t from_len = sizeof(from);

	/* Change the socket to timeout after a certain period.
	 * We set the timeout to be the maximum of the expected_usecs
	 * and expected_usecs_end computed in verify_time so we wait long
	 * enough regardless of the packet time type.
	 */

	struct timeval sock_timeout = {.tv_sec = timeout_secs, .tv_usec = 0};

	if (timeout_secs == TIMEOUT_NONE)
		sock_timeout.tv_sec = 0;

	setsockopt(psock->packet_fd, SOL_SOCKET, SO_RCVTIMEO,
	   &sock_timeout, sizeof(sock_timeout));

	/* Read the packet out of our kernel packet socket buffer. */
	*in_bytes = recvfrom(psock->packet_fd,
			     packet->buffer, packet->buffer_bytes, 0,
			     (struct sockaddr *)&from, &from_len);
	/* Set the socket back to its blocking state. */
	sock_timeout.tv_sec = 0;
	setsockopt(psock->packet_fd, SOL_SOCKET, SO_RCVTIMEO,
		   &sock_timeout, sizeof(sock_timeout));
	/* Return an error if we timed out */
	if (*in_bytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK))
		return STATUS_TIMEOUT;

	assert(*in_bytes <= packet->buffer_bytes);
	if (*in_bytes < 0) {
		if (errno == EINTR) {
			DEBUGP("EINTR\n");
			return STATUS_ERR;
		} else {
			die_perror("packet socket recvfrom()");
		}
	}

	/* We only want packets our kernel is sending out. */
	if (direction == DIRECTION_OUTBOUND &&
	    from.sll_pkttype != PACKET_OUTGOING) {
		DEBUGP("not outbound\n");
		return STATUS_ERR;
	}
	if (direction == DIRECTION_INBOUND &&
	    from.sll_pkttype != PACKET_HOST) {
		DEBUGP("not inbound\n");
		return STATUS_ERR;
	}

	/* We only want packets on our tun device. The kernel
	 * can put packets for other devices in our receive
	 * buffer before we bind the packet socket to the tun
	 * device.
	 */
	if (from.sll_ifindex != psock->index) {
		DEBUGP("not correct index\n");
		return STATUS_ERR;
	}

	/* Get the time at which the kernel sniffed the packet. */
	struct timeval tv;
	if (ioctl(psock->packet_fd, SIOCGSTAMP, &tv) < 0)
		die_perror("SIOCGSTAMP");
	packet->time_usecs = timeval_to_usecs(&tv);
	DEBUGP("sniffed packet sent at %u.%u = %lld\n",
	       (u32)tv.tv_sec, (u32)tv.tv_usec,
	       packet->time_usecs);

	return STATUS_OK;
}

#endif  /* linux */
