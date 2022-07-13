/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * Socket based service load-balancing notification via perf event ring buffer.
 *
 * API:
 * void send_trace_sock_notify(ctx, obs_point, src_ip, dst_ip, src_port,
 * 			       dst_port, sock_cookie, xlate_point, l4_proto)
 *
 * @ctx:	 socket address buffer
 * @obs_point:	 observation point (TRACE_*)
 * @src_ip:	 source ip address
 * @dst_ip:	 destination ip address
 * @src_port:	 source port
 * @dst_port:	 destination port
 * @sock_cookie: socket cookie
 * @xlate_point: service translation point for load-balancing
 * @l4_proto:    layer 4 protocol
 *
 * If TRACE_SOCK_NOTIFY is not defined, the API will be compiled in as a NOP.
 */
#ifndef __LIB_TRACE_SOCK__
#define __LIB_TRACE_SOCK__

#include <bpf/ctx/sock.h>

#include "common.h"
#include "events.h"

/* L4 protocol for the trace event */
enum l4_protocol {
	L4_PROTOCOL_UNKNOWN = 0,
	L4_PROTOCOL_TCP = 1,
  	L4_PROTOCOL_UDP = 2,
} __packed;

/* Direction for translation between service and backend IP */
enum xlate_point {
	XLATE_UNKNOWN = 0, 
	XLATE_PRE_DIRECTION_FWD = 1,  /* Pre service translation */
	XLATE_POST_DIRECTION_FWD = 2, /* Post service translation */
	XLATE_PRE_DIRECTION_REV = 3,  /* Pre reverse service translation */
	XLATE_POST_DIRECTION_REV = 4, /* Post reverse service translation */
} __packed;

struct ip {
	union {
		struct {
			__be32 ip4;
			__u32 pad1;
			__u32 pad2;
			__u32 pad3;
		};
		union v6addr ip6;
	};
};

#ifdef TRACE_SOCK_NOTIFY
struct trace_sock_notify {
	__u8 type;
	__u8 xlate_point;
	__u8 l4_proto;
	struct ip src_ip;
	struct ip dst_ip;
	__u16 src_port;
	__u16 dst_port;
	__u64 sock_cookie;
	__u8 ipv6 : 1;
	__u8 pad : 7;
} __packed;

static __always_inline l4_protocol
parse_protocol(__u32 l4_proto) {
	switchi (l4_proto) {
		case IPPROTO_TCP:
			return L4_PROTOCOL_TCP;
		case IPPROTO_UDP:
			return L4_PROTOCOL_UDP;
		default:
			return L4_PROTOCOL_UNKNOWN;
	}
}

static __always_inline void
send_trace_sock_notify4(struct __ctx_sock *ctx __maybe_unused,
    			enum xlate_point point __maybe_unused, __u32 src_ip __maybe_unused,
			__u32 dst_ip __maybe_unused, __u16 src_port __maybe_unused,
			__u16 dst_port __maybe_unused, __u64 sock_cookie __maybe_unused,
			__u32 l4_proto __maybe_unused)
{
	struct trace_sock_notify msg __align_stack_8;
	long err = 0;

	msg = (typeof(msg)){
		.type = CILIUM_NOTIFY_TRACE_SOCK,
		.sub_type = obs_point,
		.l4_proto = parse_protocol(l4_proto),
		.src_ip.ip4 = src_ip,
		.dst_ip.ip4 = dst_ip,
		.src_port = src_port,
		.dst_port = dst_port,
		.sock_cookie = sock_cookie,
		.xlate_point = xlate_point,
		.ipv6 = 0,
	};
	if (xlate_dir) {
		printk("bpf_sock-trace_fwd: sock_cookie dst_ip dst_port %llu %u %d\n",
			sock_cookie, dst_ip, dst_port);
	} else {
		printk("bpf_sock-trace_rev: sock_cookie dst_ip dst_port %llu %u %d\n",
			sock_cookie, dst_ip, dst_port);
	}

	err = ctx_event_output(ctx, &EVENTS_MAP, BPF_F_CURRENT_CPU, &msg, sizeof(msg));
	printk("bpf_sock-aditi: err %ld\n", err);
}
#else
static __always_inline void
send_trace_sock_notify4(struct __ctx_sock *ctx __maybe_unused,
			enum xlate_point point __maybe_unused, __u32 src_ip __maybe_unused,
			__u32 dst_ip __maybe_unused, __u16 src_port __maybe_unused,
			__u16 dst_port __maybe_unused, __u64 sock_cookie __maybe_unused,
			__u32 l4_proto __maybe_unused)
{

}

#endif /* TRACE_SOCK_NOTIFY */
#endif /* __LIB_TRACE_SOCK__ */
