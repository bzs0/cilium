/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/* Simple NAT engine in BPF. */
#ifndef __LIB_NAT__
#define __LIB_NAT__

#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/icmpv6.h>
#include <linux/ipv6.h>

#include "common.h"
#include "drop.h"
#include "signal.h"
#include "conntrack.h"
#include "conntrack_map.h"
#include "egress_policies.h"
#include "icmp6.h"
#include "nat_46x64.h"
#include "stubs.h"

enum  nat_dir {
	NAT_DIR_EGRESS  = TUPLE_F_OUT,
	NAT_DIR_INGRESS = TUPLE_F_IN,
} __packed;

struct nat_entry {
	__u64 created;
	__u64 host_local;	/* Only single bit used. */
	__u64 pad1;		/* Future use. */
	__u64 pad2;		/* Future use. */
};

#define NAT_CONTINUE_XLATE	0

#ifdef HAVE_LRU_HASH_MAP_TYPE
# define NAT_MAP_TYPE BPF_MAP_TYPE_LRU_HASH
#else
# define NAT_MAP_TYPE BPF_MAP_TYPE_HASH
#endif

#ifdef HAVE_LARGE_INSN_LIMIT
# define SNAT_COLLISION_RETRIES		128
# define SNAT_SIGNAL_THRES		64
#else
# define SNAT_COLLISION_RETRIES		32
# define SNAT_SIGNAL_THRES		16
#endif

static __always_inline bool nodeport_uses_dsr(__u8 nexthdr __maybe_unused);

static __always_inline __be16 __snat_clamp_port_range(__u16 start, __u16 end,
						      __u16 val)
{
	return (val % (__u16)(end - start)) + start;
}

static __always_inline __maybe_unused __be16
__snat_try_keep_port(__u16 start, __u16 end, __u16 val)
{
	return val >= start && val <= end ? val :
	       __snat_clamp_port_range(start, end, (__u16)get_prandom_u32());
}

static __always_inline __maybe_unused void *
__snat_lookup(const void *map, const void *tuple)
{
	return map_lookup_elem(map, tuple);
}

static __always_inline __maybe_unused int
__snat_update(const void *map, const void *otuple, const void *ostate,
	      const void *rtuple, const void *rstate)
{
	int ret;

	ret = map_update_elem(map, rtuple, rstate, BPF_NOEXIST);
	if (!ret) {
		ret = map_update_elem(map, otuple, ostate, BPF_NOEXIST);
		if (ret)
			map_delete_elem(map, rtuple);
	}
	return ret;
}

static __always_inline __maybe_unused void
__snat_delete(const void *map, const void *otuple, const void *rtuple)
{
	map_delete_elem(map, otuple);
	map_delete_elem(map, rtuple);
}

struct ipv4_nat_entry {
	struct nat_entry common;
	union {
		struct {
			__be32 to_saddr;
			__be16 to_sport;
		};
		struct {
			__be32 to_daddr;
			__be16 to_dport;
		};
	};
};

struct ipv4_nat_target {
	__be32 addr;
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool src_from_world;
	bool from_local_endpoint;
	bool egress_gateway; /* NAT is needed because of an egress gateway policy */
};

#if defined(ENABLE_IPV4) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, NAT_MAP_TYPE);
	__type(key, struct ipv4_ct_tuple);
	__type(value, struct ipv4_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV4_SIZE);
#ifndef HAVE_LRU_HASH_MAP_TYPE
	__uint(map_flags, CONDITIONAL_PREALLOC);
#endif
} SNAT_MAPPING_IPV4 __section_maps_btf;

#ifdef ENABLE_IP_MASQ_AGENT
struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct lpm_v4_key);
	__type(value, struct lpm_val);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, 16384);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} IP_MASQ_AGENT_IPV4 __section_maps_btf;
#endif

static __always_inline
struct ipv4_nat_entry *snat_v4_lookup(const struct ipv4_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV4, tuple);
}

static __always_inline int snat_v4_update(const struct ipv4_ct_tuple *otuple,
					  const struct ipv4_nat_entry *ostate,
					  const struct ipv4_ct_tuple *rtuple,
					  const struct ipv4_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV4, otuple, ostate,
			     rtuple, rstate);
}

static __always_inline void snat_v4_delete(const struct ipv4_ct_tuple *otuple,
					   const struct ipv4_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV4, otuple, rtuple);
}

static __always_inline void snat_v4_swap_tuple(const struct ipv4_ct_tuple *otuple,
					       struct ipv4_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v4_reverse_tuple(const struct ipv4_ct_tuple *otuple,
						 struct ipv4_ct_tuple *rtuple)
{
	struct ipv4_nat_entry *ostate;

	ostate = snat_v4_lookup(otuple);
	if (ostate) {
		snat_v4_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

static __always_inline void snat_v4_ct_canonicalize(struct ipv4_ct_tuple *otuple)
{
	__be32 addr = otuple->saddr;

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	otuple->saddr = otuple->daddr;
	otuple->daddr = addr;
}

static __always_inline void snat_v4_delete_tuples(struct ipv4_ct_tuple *otuple)
{
	struct ipv4_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v4_ct_canonicalize(otuple);
	if (!snat_v4_reverse_tuple(otuple, &rtuple))
		snat_v4_delete(otuple, &rtuple);
}

static __always_inline int snat_v4_new_mapping(struct __ctx_buff *ctx,
					       struct ipv4_ct_tuple *otuple,
					       struct ipv4_nat_entry *ostate,
					       const struct ipv4_nat_target *target)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv4_nat_entry rstate;
	struct ipv4_ct_tuple rtuple;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	snat_v4_swap_tuple(otuple, &rtuple);
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	if (otuple->saddr == target->addr) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!snat_v4_lookup(&rtuple)) {
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			ret = snat_v4_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V4);
	return !ret ? 0 : DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v4_track_connection(struct __ctx_buff *ctx,
						    const struct ipv4_ct_tuple *tuple,
						    const struct ipv4_nat_entry *state,
						    enum nat_dir dir, __u32 off,
						    const struct ipv4_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv4_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	enum ct_dir where;
	int ret;

	if (state && state->common.host_local) {
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
		if (tuple->saddr == target->addr)
			needs_ct = true;
#if defined(ENABLE_EGRESS_GATEWAY)
		/* Track egress gateway connections, but only if they are
		 * related to a remote endpoint (if the endpoint is local then
		 * the connection is already tracked).
		 */
		else if (target->egress_gateway && !target->from_local_endpoint)
			needs_ct = true;
#endif
	}
	if (!needs_ct)
		return 0;

	memset(&ct_state, 0, sizeof(ct_state));
	memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup4(get_ct_map4(&tmp), &tmp, ctx, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create4(get_ct_map4(&tmp), NULL, &tmp, ctx,
				 where, &ct_state, false, false, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

static __always_inline int
snat_v4_nat_handle_mapping(struct __ctx_buff *ctx,
			   struct ipv4_ct_tuple *tuple,
			   struct ipv4_nat_entry **state,
			   struct ipv4_nat_entry *tmp,
			   __u32 off,
			   const struct ipv4_nat_target *target)
{
	int ret;

	*state = snat_v4_lookup(tuple);
	ret = snat_v4_track_connection(ctx, tuple, *state, NAT_DIR_EGRESS, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else
		return snat_v4_new_mapping(ctx, tuple, (*state = tmp), target);
}

static __always_inline int
snat_v4_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv4_ct_tuple *tuple,
			       struct ipv4_nat_entry **state,
			       __u32 off,
			       const struct ipv4_nat_target *target)
{
	int ret;

	*state = snat_v4_lookup(tuple);
	ret = snat_v4_track_connection(ctx, tuple, *state, NAT_DIR_INGRESS, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else
		return tuple->nexthdr != IPPROTO_ICMP &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v4_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv4_ct_tuple *tuple,
						  struct ipv4_nat_entry *state,
						  __u32 off, bool has_l4_header)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;

	if (state->to_saddr == tuple->saddr &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 4, &state->to_saddr, 4, 0);
	if (has_l4_header) {
		csum_l4_offset_and_flags(tuple->nexthdr, &csum);

		if (state->to_sport != tuple->sport) {
			switch (tuple->nexthdr) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				ret = l4_modify_port(ctx, off,
						     offsetof(struct tcphdr, source),
						     &csum, state->to_sport,
						     tuple->sport);
				if (ret < 0)
					return ret;
				break;
#ifdef ENABLE_SCTP
			case IPPROTO_SCTP:
				return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
			case IPPROTO_ICMP: {
				__be32 from, to;

				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmphdr, un.echo.id),
						    &state->to_sport,
						    sizeof(state->to_sport), 0) < 0)
					return DROP_WRITE_ERROR;
				from = tuple->sport;
				to = state->to_sport;
				flags = 0; /* ICMPv4 has no pseudo-header */
				sum_l4 = csum_diff(&from, 4, &to, 4, 0);
				csum.offset = offsetof(struct icmphdr, checksum);
				break;
			}}
		}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, saddr),
			    &state->to_saddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline int snat_v4_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv4_ct_tuple *tuple,
						   struct ipv4_nat_entry *state,
						   __u32 off)
{
	int ret, flags = BPF_F_PSEUDO_HDR;
	struct csum_offset csum = {};
	__be32 sum_l4 = 0, sum;

	if (state->to_daddr == tuple->daddr &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 4, &state->to_daddr, 4, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMP: {
			__u8 type = 0;
			__be32 from, to;

			if (ctx_load_bytes(ctx, off +
					   offsetof(struct icmphdr, type),
					   &type, 1) < 0)
				return DROP_INVALID;
			if (type == ICMP_ECHO || type == ICMP_ECHOREPLY) {
				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmphdr, un.echo.id),
						    &state->to_dport,
						    sizeof(state->to_dport), 0) < 0)
					return DROP_WRITE_ERROR;
				from = tuple->dport;
				to = state->to_dport;
				flags = 0; /* ICMPv4 has no pseudo-header */
				sum_l4 = csum_diff(&from, 4, &to, 4, 0);
				csum.offset = offsetof(struct icmphdr, checksum);
			}
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct iphdr, daddr),
			    &state->to_daddr, 4, 0) < 0)
		return DROP_WRITE_ERROR;
	if (l3_csum_replace(ctx, ETH_HLEN + offsetof(struct iphdr, check),
			    0, sum, 0) < 0)
		return DROP_CSUM_L3;
	if (tuple->nexthdr == IPPROTO_ICMP)
		sum = sum_l4;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, flags) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool
snat_v4_nat_can_skip(const struct ipv4_nat_target *target, const struct ipv4_ct_tuple *tuple,
		     bool icmp_echoreply)
{
	__u16 sport = bpf_ntohs(tuple->sport);

#if defined(ENABLE_EGRESS_GATEWAY)
	if (target->egress_gateway)
		return false;
#endif

	return (!target->from_local_endpoint && !target->src_from_world &&
		sport < NAT_MIN_EGRESS) ||
		icmp_echoreply;
}

static __always_inline bool
snat_v4_rev_nat_can_skip(const struct ipv4_nat_target *target, const struct ipv4_ct_tuple *tuple)
{
	__u16 dport = bpf_ntohs(tuple->dport);

	return dport < target->min_port || dport > target->max_port;
}

static __always_inline __maybe_unused int snat_v4_create_dsr(struct __ctx_buff *ctx,
							     __be32 to_saddr,
							     __be16 to_sport)
{
	void *data, *data_end;
	struct ipv4_ct_tuple tuple = {};
	struct ipv4_nat_entry state = {};
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	tuple.nexthdr = ip4->protocol;
	tuple.daddr = ip4->saddr;
	tuple.saddr = ip4->daddr;
	tuple.flags = NAT_DIR_EGRESS;

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);

	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.sport;
		tuple.sport = l4hdr.dport;
		break;
	default:
		/* NodePort svc can be reached only via TCP or UDP, so
		 * drop the rest.
		 */
		return DROP_NAT_UNSUPP_PROTO;
	}

	state.common.created = bpf_mono_now();
	state.to_saddr = to_saddr;
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV4, &tuple, &state, 0);
	if (ret)
		return ret;

	return CTX_ACT_OK;
}

static __always_inline void snat_v4_init_tuple(const struct iphdr *ip4,
					       enum nat_dir dir,
					       struct ipv4_ct_tuple *tuple)
{
	tuple->nexthdr = ip4->protocol;
	tuple->daddr = ip4->daddr;
	tuple->saddr = ip4->saddr;
	tuple->flags = dir;
}

/* The function contains a core logic for deciding whether an egressing packet
 * has to be SNAT-ed, filling the relevant state in the target parameter if
 * that's the case.
 *
 * The function will set:
 * - target->addr to the SNAT IP address
 * - target->from_local_endpoint to true if the packet is sent from a local endpoint
 * - target->egress_gateway to true if the packet should be SNAT-ed because of
 *   an egress gateway policy
 *
 * The function will return true if the packet should be SNAT-ed, false
 * otherwise.
 */
static __always_inline bool snat_v4_prepare_state(struct __ctx_buff *ctx,
						  struct ipv4_nat_target *target)
{
	void *data, *data_end;
	struct iphdr *ip4;
	struct endpoint_info *local_ep __maybe_unused;
	struct remote_endpoint_info *remote_ep __maybe_unused;
	struct egress_gw_policy_entry *egress_gw_policy __maybe_unused;
	bool is_reply = false;

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return false;

	/* Basic minimum is to only NAT when there is a potential of
	 * overlapping tuples, e.g. applications in hostns reusing
	 * source IPs we SNAT in NodePort and BPF-masq.
	 */
#if defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY)
	if (ip4->saddr == IPV4_GATEWAY) {
		target->addr = IPV4_GATEWAY;
		return true;
	}
#else
    /* NATIVE_DEV_IFINDEX == DIRECT_ROUTING_DEV_IFINDEX cannot be moved into
     * preprocessor, as the former is known only during load time (templating).
     * This checks whether bpf_host is running on the direct routing device.
     */
	if (DIRECT_ROUTING_DEV_IFINDEX == NATIVE_DEV_IFINDEX &&
	    ip4->saddr == IPV4_DIRECT_ROUTING) {
		target->addr = IPV4_DIRECT_ROUTING;
		return true;
	}
# ifdef ENABLE_MASQUERADE
	if (ip4->saddr == IPV4_MASQUERADE) {
		target->addr = IPV4_MASQUERADE;
		return true;
	}
# endif
#endif /* defined(TUNNEL_MODE) && defined(IS_BPF_OVERLAY) */

	local_ep = __lookup_ip4_endpoint(ip4->saddr);
	remote_ep = lookup_ip4_remote_endpoint(ip4->daddr);

	/* Check if this packet belongs to reply traffic coming from a
	 * local endpoint.
	 *
	 * If local_ep is NULL, it means there's no endpoint running on the
	 * node which matches the packet source IP, which means we can
	 * skip the CT lookup since this cannot be reply traffic.
	 */
	if (local_ep) {
		struct ipv4_ct_tuple tuple = {
			.nexthdr = ip4->protocol,
			.daddr = ip4->daddr,
			.saddr = ip4->saddr
		};

		target->from_local_endpoint = true;

		ct_is_reply4(get_ct_map4(&tuple), ctx, ETH_HLEN +
			     ipv4_hdrlen(ip4), &tuple, &is_reply);
	}

#ifdef ENABLE_MASQUERADE /* SNAT local pod to world packets */
# ifdef IS_BPF_OVERLAY
	/* Do not MASQ when this function is executed from bpf_overlay
	 * (IS_BPF_OVERLAY denotes this fact). Otherwise, a packet will
	 * be SNAT'd to cilium_host IP addr.
	 */
	return false;
# endif

/* Check if the packet matches an egress NAT policy and so needs to be SNAT'ed.
 *
 * This check must happen before the IPV4_SNAT_EXCLUSION_DST_CIDR check below as
 * the destination may be in the SNAT exclusion CIDR but regardless of that we
 * always want to SNAT a packet if it's matched by an egress NAT policy.
 */
#if defined(ENABLE_EGRESS_GATEWAY)
	/* If the packet is destined to an entity inside the cluster, either EP
	 * or node, skip SNAT since only traffic leaving the cluster is supposed
	 * to be masqueraded with an egress IP.
	 */
	if (remote_ep &&
	    identity_is_cluster(remote_ep->sec_label))
		goto skip_egress_gateway;

	/* If the packet is a reply it means that outside has initiated the
	 * connection, so no need to SNAT the reply.
	 */
	if (is_reply)
		goto skip_egress_gateway;

	if (egress_gw_snat_needed(ip4, &target->addr)) {
		target->egress_gateway = true;

		return true;
	}
skip_egress_gateway:
#endif

#ifdef IPV4_SNAT_EXCLUSION_DST_CIDR
	/* Do not MASQ if a dst IP belongs to a pods CIDR
	 * (ipv4-native-routing-cidr if specified, otherwise local pod CIDR).
	 * The check is performed before we determine that a packet is
	 * sent from a local pod, as this check is cheaper than
	 * the map lookup done in the latter check.
	 */
	if (ipv4_is_in_subnet(ip4->daddr, IPV4_SNAT_EXCLUSION_DST_CIDR,
			      IPV4_SNAT_EXCLUSION_DST_CIDR_LEN))
		return false;
#endif

	/* if this is a localhost endpoint, no SNAT is needed */
	if (local_ep && (local_ep->flags & ENDPOINT_F_HOST))
		return false;

	if (remote_ep) {
#ifdef ENABLE_IP_MASQ_AGENT
		/* Do not SNAT if dst belongs to any ip-masq-agent
		 * subnet.
		 */
		struct lpm_v4_key pfx;

		pfx.lpm.prefixlen = 32;
		memcpy(pfx.lpm.data, &ip4->daddr, sizeof(pfx.addr));
		if (map_lookup_elem(&IP_MASQ_AGENT_IPV4, &pfx))
			return false;
#endif
#ifndef TUNNEL_MODE
		/* In the tunnel mode, a packet from a local ep
		 * to a remote node is not encap'd, and is sent
		 * via a native dev. Therefore, such packet has
		 * to be MASQ'd. Otherwise, it might be dropped
		 * either by underlying network (e.g. AWS drops
		 * packets by default from unknown subnets) or
		 * by the remote node if its native dev's
		 * rp_filter=1.
		 */
		if (identity_is_remote_node(remote_ep->sec_label))
			return false;
#endif

		/* If the packet is a reply it means that outside has
		 * initiated the connection, so no need to SNAT the
		 * reply.
		 */
		if (!is_reply && local_ep) {
			target->addr = IPV4_MASQUERADE;
			return true;
		}
	}
#endif /*ENABLE_MASQUERADE */

	return false;
}

static __always_inline __maybe_unused int
snat_v4_nat(struct __ctx_buff *ctx, const struct ipv4_nat_target *target)
{
	struct icmphdr icmphdr __align_stack_8;
	struct ipv4_nat_entry *state, tmp;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	bool icmp_echoreply = false;
	__u64 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	snat_v4_init_tuple(ip4, NAT_DIR_EGRESS, &tuple);

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;
		if (icmphdr.type != ICMP_ECHO &&
		    icmphdr.type != ICMP_ECHOREPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (icmphdr.type == ICMP_ECHO) {
			tuple.dport = 0;
			tuple.sport = icmphdr.un.echo.id;
		} else {
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			icmp_echoreply = true;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v4_nat_can_skip(target, &tuple, icmp_echoreply))
		return NAT_PUNT_TO_STACK;
	ret = snat_v4_nat_handle_mapping(ctx, &tuple, &state, &tmp, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return snat_v4_rewrite_egress(ctx, &tuple, state, off, ipv4_has_l4_header(ip4));
}

static __always_inline __maybe_unused int
snat_v4_rev_nat(struct __ctx_buff *ctx, const struct ipv4_nat_target *target)
{
	struct icmphdr icmphdr __align_stack_8;
	struct ipv4_nat_entry *state;
	struct ipv4_ct_tuple tuple = {};
	void *data, *data_end;
	struct iphdr *ip4;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u64 off;
	int ret;

	build_bug_on(sizeof(struct ipv4_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip4))
		return DROP_INVALID;

	snat_v4_init_tuple(ip4, NAT_DIR_INGRESS, &tuple);

	off = ((void *)ip4 - data) + ipv4_hdrlen(ip4);
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMP:
		if (ctx_load_bytes(ctx, off, &icmphdr, sizeof(icmphdr)) < 0)
			return DROP_INVALID;
		switch (icmphdr.type) {
		case ICMP_ECHO:
			tuple.dport = 0;
			tuple.sport = icmphdr.un.echo.id;
			break;
		case ICMP_ECHOREPLY:
			tuple.dport = icmphdr.un.echo.id;
			tuple.sport = 0;
			break;
		default:
			return DROP_NAT_UNSUPP_PROTO;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v4_rev_nat_can_skip(target, &tuple))
		return NAT_PUNT_TO_STACK;
	ret = snat_v4_rev_nat_handle_mapping(ctx, &tuple, &state, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return snat_v4_rewrite_ingress(ctx, &tuple, state, off);
}
#else
static __always_inline __maybe_unused
int snat_v4_nat(struct __ctx_buff *ctx __maybe_unused,
		const struct ipv4_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
int snat_v4_rev_nat(struct __ctx_buff *ctx __maybe_unused,
		    const struct ipv4_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
void snat_v4_delete_tuples(struct ipv4_ct_tuple *tuple __maybe_unused)
{
}
#endif

struct ipv6_nat_entry {
	struct nat_entry common;
	union {
		struct {
			union v6addr to_saddr;
			__be16       to_sport;
		};
		struct {
			union v6addr to_daddr;
			__be16       to_dport;
		};
	};
};

struct ipv6_nat_target {
	union v6addr addr;
	const __u16 min_port; /* host endianness */
	const __u16 max_port; /* host endianness */
	bool src_from_world;
};

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
struct {
	__uint(type, NAT_MAP_TYPE);
	__type(key, struct ipv6_ct_tuple);
	__type(value, struct ipv6_nat_entry);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, SNAT_MAPPING_IPV6_SIZE);
#ifndef HAVE_LRU_HASH_MAP_TYPE
	__uint(map_flags, CONDITIONAL_PREALLOC);
#endif
} SNAT_MAPPING_IPV6 __section_maps_btf;

static __always_inline
struct ipv6_nat_entry *snat_v6_lookup(struct ipv6_ct_tuple *tuple)
{
	return __snat_lookup(&SNAT_MAPPING_IPV6, tuple);
}

static __always_inline int snat_v6_update(struct ipv6_ct_tuple *otuple,
					  struct ipv6_nat_entry *ostate,
					  struct ipv6_ct_tuple *rtuple,
					  struct ipv6_nat_entry *rstate)
{
	return __snat_update(&SNAT_MAPPING_IPV6, otuple, ostate,
			     rtuple, rstate);
}

static __always_inline void snat_v6_delete(const struct ipv6_ct_tuple *otuple,
					   const struct ipv6_ct_tuple *rtuple)
{
	__snat_delete(&SNAT_MAPPING_IPV6, otuple, rtuple);
}

static __always_inline void snat_v6_swap_tuple(const struct ipv6_ct_tuple *otuple,
					       struct ipv6_ct_tuple *rtuple)
{
	memset(rtuple, 0, sizeof(*rtuple));
	rtuple->nexthdr = otuple->nexthdr;
	rtuple->daddr = otuple->saddr;
	rtuple->saddr = otuple->daddr;
	rtuple->dport = otuple->sport;
	rtuple->sport = otuple->dport;
	rtuple->flags = otuple->flags == NAT_DIR_EGRESS ?
			NAT_DIR_INGRESS : NAT_DIR_EGRESS;
}

static __always_inline int snat_v6_reverse_tuple(struct ipv6_ct_tuple *otuple,
						 struct ipv6_ct_tuple *rtuple)
{
	struct ipv6_nat_entry *ostate;

	ostate = snat_v6_lookup(otuple);
	if (ostate) {
		snat_v6_swap_tuple(otuple, rtuple);
		rtuple->daddr = ostate->to_saddr;
		rtuple->dport = ostate->to_sport;
	}

	return ostate ? 0 : -1;
}

static __always_inline void snat_v6_ct_canonicalize(struct ipv6_ct_tuple *otuple)
{
	union v6addr addr = {};

	otuple->flags = NAT_DIR_EGRESS;
	/* Workaround #5848. */
	ipv6_addr_copy(&addr, &otuple->saddr);
	ipv6_addr_copy(&otuple->saddr, &otuple->daddr);
	ipv6_addr_copy(&otuple->daddr, &addr);
}

static __always_inline void snat_v6_delete_tuples(struct ipv6_ct_tuple *otuple)
{
	struct ipv6_ct_tuple rtuple;

	if (otuple->flags & TUPLE_F_IN)
		return;
	snat_v6_ct_canonicalize(otuple);
	if (!snat_v6_reverse_tuple(otuple, &rtuple))
		snat_v6_delete(otuple, &rtuple);
}

static __always_inline int snat_v6_new_mapping(struct __ctx_buff *ctx,
					       struct ipv6_ct_tuple *otuple,
					       struct ipv6_nat_entry *ostate,
					       const struct ipv6_nat_target *target)
{
	int ret = DROP_NAT_NO_MAPPING, retries;
	struct ipv6_nat_entry rstate;
	struct ipv6_ct_tuple rtuple;
	__u16 port;

	memset(&rstate, 0, sizeof(rstate));
	memset(ostate, 0, sizeof(*ostate));

	rstate.to_daddr = otuple->saddr;
	rstate.to_dport = otuple->sport;

	ostate->to_saddr = target->addr;

	snat_v6_swap_tuple(otuple, &rtuple);
	port = __snat_try_keep_port(target->min_port,
				    target->max_port,
				    bpf_ntohs(otuple->sport));

	rtuple.dport = ostate->to_sport = bpf_htons(port);
	rtuple.daddr = target->addr;

	if (!ipv6_addrcmp(&otuple->saddr, &rtuple.daddr)) {
		ostate->common.host_local = 1;
		rstate.common.host_local = ostate->common.host_local;
	}

#pragma unroll
	for (retries = 0; retries < SNAT_COLLISION_RETRIES; retries++) {
		if (!snat_v6_lookup(&rtuple)) {
			ostate->common.created = bpf_mono_now();
			rstate.common.created = ostate->common.created;

			ret = snat_v6_update(otuple, ostate, &rtuple, &rstate);
			if (!ret)
				break;
		}

		port = __snat_clamp_port_range(target->min_port,
					       target->max_port,
					       retries ? port + 1 :
					       (__u16)get_prandom_u32());
		rtuple.dport = ostate->to_sport = bpf_htons(port);
	}

	if (retries > SNAT_SIGNAL_THRES)
		send_signal_nat_fill_up(ctx, SIGNAL_PROTO_V6);
	return !ret ? 0 : DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v6_track_connection(struct __ctx_buff *ctx,
						    struct ipv6_ct_tuple *tuple,
						    const struct ipv6_nat_entry *state,
						    enum nat_dir dir, __u32 off,
						    const struct ipv6_nat_target *target)
{
	struct ct_state ct_state;
	struct ipv6_ct_tuple tmp;
	bool needs_ct = false;
	__u32 monitor = 0;
	int ret, where;

	if (state && state->common.host_local) {
		needs_ct = true;
	} else if (!state && dir == NAT_DIR_EGRESS) {
		if (!ipv6_addrcmp(&tuple->saddr, (void *)&target->addr))
			needs_ct = true;
	}
	if (!needs_ct)
		return 0;

	memset(&ct_state, 0, sizeof(ct_state));
	memcpy(&tmp, tuple, sizeof(tmp));

	where = dir == NAT_DIR_INGRESS ? CT_INGRESS : CT_EGRESS;

	ret = ct_lookup6(get_ct_map6(&tmp), &tmp, ctx, off, where,
			 &ct_state, &monitor);
	if (ret < 0) {
		return ret;
	} else if (ret == CT_NEW) {
		ret = ct_create6(get_ct_map6(&tmp), NULL, &tmp, ctx, where,
				 &ct_state, false, false, false);
		if (IS_ERR(ret))
			return ret;
	}

	return 0;
}

static __always_inline int
snat_v6_nat_handle_mapping(struct __ctx_buff *ctx,
			   struct ipv6_ct_tuple *tuple,
			   struct ipv6_nat_entry **state,
			   struct ipv6_nat_entry *tmp,
			   __u32 off,
			   const struct ipv6_nat_target *target)
{
	int ret;

	*state = snat_v6_lookup(tuple);
	ret = snat_v6_track_connection(ctx, tuple, *state, NAT_DIR_EGRESS, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else
		return snat_v6_new_mapping(ctx, tuple, (*state = tmp), target);
}

static __always_inline int
snat_v6_rev_nat_handle_mapping(struct __ctx_buff *ctx,
			       struct ipv6_ct_tuple *tuple,
			       struct ipv6_nat_entry **state,
			       __u32 off,
			       const struct ipv6_nat_target *target)
{
	int ret;

	*state = snat_v6_lookup(tuple);
	ret = snat_v6_track_connection(ctx, tuple, *state, NAT_DIR_INGRESS, off, target);
	if (ret < 0)
		return ret;
	else if (*state)
		return NAT_CONTINUE_XLATE;
	else
		return tuple->nexthdr != IPPROTO_ICMPV6 &&
		       bpf_ntohs(tuple->dport) < target->min_port ?
		       NAT_PUNT_TO_STACK : DROP_NAT_NO_MAPPING;
}

static __always_inline int snat_v6_rewrite_egress(struct __ctx_buff *ctx,
						  struct ipv6_ct_tuple *tuple,
						  struct ipv6_nat_entry *state,
						  __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_saddr, &tuple->saddr) &&
	    state->to_sport == tuple->sport)
		return 0;
	sum = csum_diff(&tuple->saddr, 16, &state->to_saddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_sport != tuple->sport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off, offsetof(struct tcphdr, source),
					     &csum, state->to_sport, tuple->sport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMPV6: {
			__be32 from, to;

			if (ctx_store_bytes(ctx, off +
					    offsetof(struct icmp6hdr,
						     icmp6_dataun.u_echo.identifier),
					    &state->to_sport,
					    sizeof(state->to_sport), 0) < 0)
				return DROP_WRITE_ERROR;
			from = tuple->sport;
			to = state->to_sport;
			sum = csum_diff(&from, 4, &to, 4, sum);
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, saddr),
			    &state->to_saddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline int snat_v6_rewrite_ingress(struct __ctx_buff *ctx,
						   struct ipv6_ct_tuple *tuple,
						   struct ipv6_nat_entry *state,
						   __u32 off)
{
	struct csum_offset csum = {};
	__be32 sum;
	int ret;

	if (!ipv6_addrcmp(&state->to_daddr, &tuple->daddr) &&
	    state->to_dport == tuple->dport)
		return 0;
	sum = csum_diff(&tuple->daddr, 16, &state->to_daddr, 16, 0);
	csum_l4_offset_and_flags(tuple->nexthdr, &csum);
	if (state->to_dport != tuple->dport) {
		switch (tuple->nexthdr) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			ret = l4_modify_port(ctx, off,
					     offsetof(struct tcphdr, dest),
					     &csum, state->to_dport,
					     tuple->dport);
			if (ret < 0)
				return ret;
			break;
#ifdef ENABLE_SCTP
		case IPPROTO_SCTP:
			return DROP_CSUM_L4;
#endif  /* ENABLE_SCTP */
		case IPPROTO_ICMPV6: {
			__u8 type = 0;
			__be32 from, to;

			if (ctx_load_bytes(ctx, off, &type, 1) < 0)
				return DROP_INVALID;
			if (type == ICMP_ECHO || type == ICMP_ECHOREPLY) {
				if (ctx_store_bytes(ctx, off +
						    offsetof(struct icmp6hdr,
							     icmp6_dataun.u_echo.identifier),
						    &state->to_dport,
						    sizeof(state->to_dport), 0) < 0)
					return DROP_WRITE_ERROR;
				from = tuple->dport;
				to = state->to_dport;
				sum = csum_diff(&from, 4, &to, 4, sum);
			}
			break;
		}}
	}
	if (ctx_store_bytes(ctx, ETH_HLEN + offsetof(struct ipv6hdr, daddr),
			    &state->to_daddr, 16, 0) < 0)
		return DROP_WRITE_ERROR;
	if (csum.offset &&
	    csum_l4_replace(ctx, off, &csum, 0, sum, BPF_F_PSEUDO_HDR) < 0)
		return DROP_CSUM_L4;
	return 0;
}

static __always_inline bool
snat_v6_nat_can_skip(const struct ipv6_nat_target *target, const struct ipv6_ct_tuple *tuple,
		     bool icmp_echoreply)
{
	__u16 sport = bpf_ntohs(tuple->sport);

	return (!target->src_from_world && sport < NAT_MIN_EGRESS) || icmp_echoreply;
}

static __always_inline bool
snat_v6_rev_nat_can_skip(const struct ipv6_nat_target *target, const struct ipv6_ct_tuple *tuple)
{
	__u16 dport = bpf_ntohs(tuple->dport);

	return dport < target->min_port || dport > target->max_port;
}

static __always_inline __maybe_unused int snat_v6_create_dsr(struct __ctx_buff *ctx,
							     const union v6addr *to_saddr,
							     __be16 to_sport)
{
	void *data, *data_end;
	struct ipv6_ct_tuple tuple = {};
	struct ipv6_nat_entry state = {};
	struct ipv6hdr *ip6;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	int ret, hdrlen;
	__u32 off;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	ipv6_addr_copy(&tuple.daddr, (union v6addr *)&ip6->saddr);
	ipv6_addr_copy(&tuple.saddr, (union v6addr *)&ip6->daddr);
	tuple.flags = NAT_DIR_EGRESS;

	off = ((void *)ip6 - data) + hdrlen;

	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.sport;
		tuple.sport = l4hdr.dport;
		break;
	default:
		/* NodePort svc can be reached only via TCP or UDP, so
		 * drop the rest.
		 */
		return DROP_NAT_UNSUPP_PROTO;
	}

	state.common.created = bpf_mono_now();
	ipv6_addr_copy(&state.to_saddr, to_saddr);
	state.to_sport = to_sport;

	ret = map_update_elem(&SNAT_MAPPING_IPV6, &tuple, &state, 0);
	if (ret)
		return ret;

	return CTX_ACT_OK;
}

static __always_inline void snat_v6_init_tuple(const struct ipv6hdr *ip6,
					       enum nat_dir dir,
					       struct ipv6_ct_tuple *tuple)
{
	ipv6_addr_copy(&tuple->daddr, (union v6addr *)&ip6->daddr);
	ipv6_addr_copy(&tuple->saddr, (union v6addr *)&ip6->saddr);
	tuple->flags = dir;
}

static __always_inline bool snat_v6_needed(struct __ctx_buff *ctx,
					   const union v6addr *addr)
{
	void *data, *data_end;
	struct ipv6hdr *ip6;

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return false;
#ifdef ENABLE_DSR_HYBRID
	{
		__u8 nexthdr = ip6->nexthdr;
		int ret;

		ret = ipv6_hdrlen(ctx, &nexthdr);
		if (ret > 0) {
			if (nodeport_uses_dsr(nexthdr))
				return false;
		}
	}
#endif /* ENABLE_DSR_HYBRID */
	/* See snat_v4_prepare_state(). */
	return !ipv6_addrcmp((union v6addr *)&ip6->saddr, addr);
}

static __always_inline __maybe_unused int
snat_v6_nat(struct __ctx_buff *ctx, const struct ipv6_nat_target *target)
{
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct ipv6_nat_entry *state, tmp;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;
	bool icmp_echoreply = false;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	snat_v6_init_tuple(ip6, NAT_DIR_EGRESS, &tuple);

	off = ((void *)ip6 - data) + hdrlen;
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		/* Letting neighbor solicitation / advertisement pass through. */
		if (icmp6hdr.icmp6_type == ICMP6_NS_MSG_TYPE ||
		    icmp6hdr.icmp6_type == ICMP6_NA_MSG_TYPE)
			return CTX_ACT_OK;
		if (icmp6hdr.icmp6_type != ICMPV6_ECHO_REQUEST &&
		    icmp6hdr.icmp6_type != ICMPV6_ECHO_REPLY)
			return DROP_NAT_UNSUPP_PROTO;
		if (icmp6hdr.icmp6_type == ICMPV6_ECHO_REQUEST) {
			tuple.dport = 0;
			tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
		} else {
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			icmp_echoreply = true;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_nat_can_skip(target, &tuple, icmp_echoreply))
		return NAT_PUNT_TO_STACK;
	ret = snat_v6_nat_handle_mapping(ctx, &tuple, &state, &tmp, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return snat_v6_rewrite_egress(ctx, &tuple, state, off);
}

static __always_inline __maybe_unused int
snat_v6_rev_nat(struct __ctx_buff *ctx, const struct ipv6_nat_target *target)
{
	struct icmp6hdr icmp6hdr __align_stack_8;
	struct ipv6_nat_entry *state;
	struct ipv6_ct_tuple tuple = {};
	void *data, *data_end;
	struct ipv6hdr *ip6;
	int ret, hdrlen;
	struct {
		__be16 sport;
		__be16 dport;
	} l4hdr;
	__u32 off;

	build_bug_on(sizeof(struct ipv6_nat_entry) > 64);

	if (!revalidate_data(ctx, &data, &data_end, &ip6))
		return DROP_INVALID;

	tuple.nexthdr = ip6->nexthdr;
	hdrlen = ipv6_hdrlen(ctx, &tuple.nexthdr);
	if (hdrlen < 0)
		return hdrlen;

	snat_v6_init_tuple(ip6, NAT_DIR_INGRESS, &tuple);

	off = ((void *)ip6 - data) + hdrlen;
	switch (tuple.nexthdr) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
#ifdef ENABLE_SCTP
	case IPPROTO_SCTP:
#endif  /* ENABLE_SCTP */
		if (ctx_load_bytes(ctx, off, &l4hdr, sizeof(l4hdr)) < 0)
			return DROP_INVALID;
		tuple.dport = l4hdr.dport;
		tuple.sport = l4hdr.sport;
		break;
	case IPPROTO_ICMPV6:
		if (ctx_load_bytes(ctx, off, &icmp6hdr, sizeof(icmp6hdr)) < 0)
			return DROP_INVALID;
		switch (icmp6hdr.icmp6_type) {
			/* Letting neighbor solicitation / advertisement pass through. */
		case ICMP6_NS_MSG_TYPE:
		case ICMP6_NA_MSG_TYPE:
			return CTX_ACT_OK;
		case ICMPV6_ECHO_REQUEST:
			tuple.dport = 0;
			tuple.sport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			break;
		case ICMPV6_ECHO_REPLY:
			tuple.dport = icmp6hdr.icmp6_dataun.u_echo.identifier;
			tuple.sport = 0;
			break;
		default:
			return DROP_NAT_UNSUPP_PROTO;
		}
		break;
	default:
		return NAT_PUNT_TO_STACK;
	};

	if (snat_v6_rev_nat_can_skip(target, &tuple))
		return NAT_PUNT_TO_STACK;
	ret = snat_v6_rev_nat_handle_mapping(ctx, &tuple, &state, off, target);
	if (ret > 0)
		return CTX_ACT_OK;
	if (ret < 0)
		return ret;

	return snat_v6_rewrite_ingress(ctx, &tuple, state, off);
}
#else
static __always_inline __maybe_unused
int snat_v6_nat(struct __ctx_buff *ctx __maybe_unused,
		const struct ipv6_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
int snat_v6_rev_nat(struct __ctx_buff *ctx __maybe_unused,
		    const struct ipv6_nat_target *target __maybe_unused)
{
	return CTX_ACT_OK;
}

static __always_inline __maybe_unused
void snat_v6_delete_tuples(struct ipv6_ct_tuple *tuple __maybe_unused)
{
}
#endif

#if defined(ENABLE_IPV6) && defined(ENABLE_NODEPORT)
static __always_inline int
snat_remap_rfc8215(struct __ctx_buff *ctx, const struct iphdr *ip4, int l3_off)
{
	union v6addr src6, dst6;

	build_v4_in_v6_rfc8215(&src6, ip4->saddr);
	build_v4_in_v6(&dst6, ip4->daddr);
	return ipv4_to_ipv6(ctx, l3_off, &src6, &dst6);
}

static __always_inline bool
__snat_v6_has_v4_complete(struct ipv6_ct_tuple *tuple6,
			  const struct ipv4_ct_tuple *tuple4)
{
	build_v4_in_v6(&tuple6->daddr, tuple4->daddr);
	tuple6->nexthdr = tuple4->nexthdr;
	tuple6->sport = tuple4->sport;
	tuple6->dport = tuple4->dport;
	tuple6->flags = NAT_DIR_INGRESS;
	return snat_v6_lookup(tuple6);
}

static __always_inline bool
snat_v6_has_v4_match_rfc8215(const struct ipv4_ct_tuple *tuple4)
{
	struct ipv6_ct_tuple tuple6;

	memset(&tuple6, 0, sizeof(tuple6));
	build_v4_in_v6_rfc8215(&tuple6.saddr, tuple4->saddr);
	return __snat_v6_has_v4_complete(&tuple6, tuple4);
}

static __always_inline bool
snat_v6_has_v4_match(const struct ipv4_ct_tuple *tuple4)
{
	struct ipv6_ct_tuple tuple6;

	memset(&tuple6, 0, sizeof(tuple6));
	build_v4_in_v6(&tuple6.saddr, tuple4->saddr);
	return __snat_v6_has_v4_complete(&tuple6, tuple4);
}
#else
static __always_inline bool
snat_v6_has_v4_match(const struct ipv4_ct_tuple *tuple4 __maybe_unused)
{
	return false;
}
#endif /* ENABLE_IPV6 && ENABLE_NODEPORT */

static __always_inline __maybe_unused void
ct_delete4(const void *map, struct ipv4_ct_tuple *tuple, struct __ctx_buff *ctx)
{
	int err;

	err = map_delete_elem(map, tuple);
	if (err < 0)
		cilium_dbg(ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v4_delete_tuples(tuple);
}

static __always_inline __maybe_unused void
ct_delete6(const void *map, struct ipv6_ct_tuple *tuple, struct __ctx_buff *ctx)
{
	int err;

	err = map_delete_elem(map, tuple);
	if (err < 0)
		cilium_dbg(ctx, DBG_ERROR_RET, BPF_FUNC_map_delete_elem, err);
	else
		snat_v6_delete_tuples(tuple);
}

#endif /* __LIB_NAT__ */
