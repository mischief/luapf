/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netdb.h>
#include <netinet/in.h>

/* TCPSTATES defines tcpstates[], the same names pfctl prints. */
#define TCPSTATES
#include <netinet/tcp_fsm.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "property.h"
#include "banned.h"

/***
@module pf
*/

enum { maxprotos = 256, maxprotosize = 16 };

static const char *
cacheprotoent(uint8_t proto)
{
	static char protocache[maxprotos][maxprotosize];
	struct protoent *p;

	if (protocache[proto][0] != '\0')
		return protocache[proto];

	p = getprotobynumber(proto);
	if (p == NULL)
		return NULL;

	/* A name longer than the cache slot is truncated, not rejected. */
	strlcpy(protocache[proto], p->p_name, maxprotosize);

	return protocache[proto];
}

static int
state_id(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)betoh64(s->id));

	return 1;
}

static int
state_creatorid(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)betoh32(s->creatorid));

	return 1;
}

static int
state_ifname(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	/*
	 * The kernel need not NUL terminate a fixed-size character array, so
	 * bound the read by the size of the array itself. sizeof on a
	 * pointer would measure the pointer.
	 */
	lua_pushlstring(L, s->ifname, strnlen(s->ifname, sizeof(s->ifname)));

	return 1;
}

static int
state_proto(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushstring(L, cacheprotoent(s->proto));

	return 1;
}

static int
state_direction(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushstring(L, s->direction == PF_IN ? "in" : "out");

	return 1;
}

static int
state_rule(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint32_t rule = betoh32(s->rule);

	if (rule == (uint32_t)-1)
		lua_pushinteger(L, -1);
	else
		lua_pushinteger(L, (lua_Integer)rule);

	return 1;
}

static int
state_creation(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)betoh32(s->creation));

	return 1;
}

static int
state_expire(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)betoh32(s->expire));

	return 1;
}

/*
 * Two swaps are stacked in key[] indexing. Which key first: WIRE holds the
 * packet as it goes over the wire and STACK as the local stack sees it, so
 * the translated view is WIRE outbound and STACK inbound. This picks the
 * translated view either way; the other key holds the untranslated one.
 */

/*
 * Which index second: addr[1] is always the near end, the side of PF this
 * host and the hosts behind it are on, and addr[0] the far end. Neither
 * moves with direction. source does move, because source is the near end
 * outbound and the far end inbound.
 */

/*
 * Two ends by two views is four addresses, and an end is translated when
 * its two views differ. Three of the four describe a flow completely only
 * while one end is translated: nat-to with rdr-to gives WIRE
 * 10.99.0.9:53640 -> 10.99.0.3:7777 over STACK 10.99.0.1:3105 ->
 * 10.99.0.2:9999.
 */
static void
gimmekey(lua_State *L, const struct pfsync_state *s, int idx,
         const struct pf_addr **raddr, uint16_t *rport, sa_family_t *raf)
{
	const struct pfsync_state_key *key;

	/*
	 * The two keys of an af-to state carry different families, which is
	 * fine: the family travels with the key, so each address is rendered
	 * as whatever it actually is.
	 */
	switch (s->direction) {
	case PF_IN:
		key = &s->key[PF_SK_STACK];
		break;
	case PF_OUT:
		key = &s->key[PF_SK_WIRE];
		break;
	default:
		luaL_error(L, "unhandled direction %d", s->direction);
		return;
	}

	*raddr = &key->addr[idx];
	*rport = be16toh(key->port[idx]);
	*raf = key->af;
}

static int
pushhostport(lua_State *L, sa_family_t af, const struct pf_addr *a,
             uint16_t port)
{
	char addr[INET6_ADDRSTRLEN];

	if (inet_ntop(af, &a->pfa, addr, sizeof(addr)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	switch (af) {
	case AF_INET:
		lua_pushfstring(L, "%s:%d", addr, port);
		break;
	case AF_INET6:
		lua_pushfstring(L, "[%s]:%d", addr, port);
		break;
	default:
		luaL_error(L, "unhandled address family %d", af);
	}

	return 1;
}

/*
 * The key source and destination read, and with other set the one gateway
 * reads. Two states in different routing domains may carry the same
 * addresses and ports, so a key is only unique together with its rdomain.
 */
/*
 * An af-to state translates between families, and the kernel mirrors the
 * two keys when it does: the end that is addr[1] in one key is addr[0] in
 * the other. pfctl inverts the same index and prints an inbound af-to
 * state with the outbound arrow, which is the same statement -- for
 * indexing, an inbound af-to state reads as an outbound one.
 */
static int
stateafto(const struct pfsync_state *s)
{
	return s->key[PF_SK_STACK].af != s->key[PF_SK_WIRE].af;
}

/* True when the state indexes its keys the way an outbound state does. */
static int
stateoutward(const struct pfsync_state *s)
{
	return (int)s->direction == PF_OUT || stateafto(s);
}

static const struct pfsync_state_key *
directionkey(const struct pfsync_state *s, int other)
{
	int wire = ((int)s->direction == PF_OUT) != (other != 0);

	return &s->key[wire ? PF_SK_WIRE : PF_SK_STACK];
}

static int
state_rdomain(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)be16toh(directionkey(s, 0)->rdomain));

	return 1;
}

static int
state_gateway_rdomain(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)be16toh(directionkey(s, 1)->rdomain));

	return 1;
}

/*
 * The four addresses on their own axes: which end, and which view of it.
 * source, destination and gateway are the direction-relative reading of
 * the same four, and can name only one translated end between them.
 */
static int
pushkeyhost(lua_State *L, const struct pfsync_state *s, int wire, int nearend)
{
	const struct pfsync_state_key *key =
	    &s->key[wire ? PF_SK_WIRE : PF_SK_STACK];
	int i = nearend ? 1 : 0;

	/* The other key holds this end at the opposite index when the
	 * families differ, so pairing by index alone would name the far
	 * end here and the near end there. */
	if (stateafto(s) && key != directionkey(s, 0))
		i = !i;

	return pushhostport(L, key->af, &key->addr[i], be16toh(key->port[i]));
}

static int
state_near_wire(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	return pushkeyhost(L, s, 1, 1);
}

static int
state_far_wire(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	return pushkeyhost(L, s, 1, 0);
}

static int
state_near_stack(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	return pushkeyhost(L, s, 0, 1);
}

static int
state_far_stack(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	return pushkeyhost(L, s, 0, 0);
}

static int
state_source(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	const struct pf_addr *a;
	uint16_t p;
	sa_family_t af;

	gimmekey(L, s, stateoutward(s) ? 1 : 0, &a, &p, &af);

	return pushhostport(L, af, a, p);
}

static int
state_destination(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	const struct pf_addr *a;
	uint16_t p;
	sa_family_t af;

	gimmekey(L, s, stateoutward(s) ? 0 : 1, &a, &p, &af);

	return pushhostport(L, af, a, p);
}

/*
 * The same endpoint as the other side of translation sees it: whichever
 * key gimmekey() did not use. Outbound that is the source the stack asked
 * for before nat-to rewrote it; inbound, the destination the packet
 * carried before rdr-to redirected it. pfctl prints it in parentheses.
 * An untranslated state reports the address it already had.
 */

/*
 * Translation acts on index 1, the local end: nat-to rewrites the source
 * outbound, rdr-to the destination inbound. Index 1 of the other key is
 * therefore enough, and is also all this can report: a binat translates
 * both ends, and gateway has no room for the second.
 */
static int
state_gateway(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	const struct pfsync_state_key *other = directionkey(s, 1);
	int i = stateafto(s) ? 0 : 1;

	return pushhostport(L, other->af, &other->addr[i],
	                    be16toh(other->port[i]));
}

/*
 * Every per-direction counter puts the state's own direction at index 0 and
 * the reverse at index 1, so the inbound half of an outbound state is index
 * 1. Elsewhere in this binding in and out mean the direction PF saw the
 * packet in, and these read the same way.
 */
static int
dirindex(const struct pfsync_state *s, int dir)
{
	return (int)s->direction == dir ? 0 : 1;
}

static int
state_packets_in(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->packets[dirindex(s, PF_IN)], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static int
state_packets_out(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->packets[dirindex(s, PF_OUT)], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static int
state_bytes_in(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->bytes[dirindex(s, PF_IN)], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static int
state_bytes_out(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->bytes[dirindex(s, PF_OUT)], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static int
state_anchor(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint32_t anchor = betoh32(s->anchor);

	/* Same convention as rule: -1 means the main ruleset. */
	if (anchor == (uint32_t)-1)
		lua_pushinteger(L, -1);
	else
		lua_pushinteger(L, (lua_Integer)anchor);

	return 1;
}

static const struct pfsync_state_peer *
statepeer(lua_State *L, int idx, int dst)
{
	const struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	return dst ? &s->dst : &s->src;
}

/*
 * The three-way dispatch pfctl uses on the connection state levels: TCP
 * against the tcpstates names, UDP and everything else against their own
 * short tables, ICMP against nothing at all because it has no levels. A
 * level with no name renders as its number, so the pair always reads.
 */
static const char *
peerstatename(uint8_t proto, uint8_t level, char *buf, size_t bufsz)
{
	static const char *const udpnames[] = PFUDPS_NAMES;
	static const char *const othernames[] = PFOTHERS_NAMES;

	switch (proto) {
	case IPPROTO_TCP:
		if (level <= TCPS_TIME_WAIT)
			return tcpstates[level];
		if (level == PF_TCPS_PROXY_SRC)
			return "PROXY_SRC";
		if (level == PF_TCPS_PROXY_DST)
			return "PROXY_DST";
		break;
	case IPPROTO_UDP:
		if (level < PFUDPS_NSTATES)
			return udpnames[level];
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		break;
	default:
		if (level < PFOTHERS_NSTATES)
			return othernames[level];
		break;
	}

	snprintf(buf, bufsz, "%u", level);

	return buf;
}

enum { maxlevelname = 16 };

static int
pushpeerstate(lua_State *L, int idx, int dst)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	const struct pfsync_state_peer *p = statepeer(L, idx, dst);
	char buf[maxlevelname];

	lua_pushstring(L, peerstatename(s->proto, p->state, buf, sizeof(buf)));

	return 1;
}

static int
state_src_state(lua_State *L, int idx)
{
	return pushpeerstate(L, idx, 0);
}

static int
state_dst_state(lua_State *L, int idx)
{
	return pushpeerstate(L, idx, 1);
}

static int
state_connection_state(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	char src[maxlevelname], dst[maxlevelname];

	lua_pushfstring(
	    L, "%s:%s", peerstatename(s->proto, s->src.state, src, sizeof(src)),
	    peerstatename(s->proto, s->dst.state, dst, sizeof(dst)));

	return 1;
}

static const struct {
	uint16_t bit;
	const char *name;
} stateflagnames[] = {
    {PFSTATE_ALLOWOPTS,    "allowopts"   },
    {PFSTATE_SLOPPY,       "sloppy"      },
    {PFSTATE_PFLOW,        "pflow"       },
    {PFSTATE_NOSYNC,       "nosync"      },
    {PFSTATE_ACK,          "ack"         },
    {PFSTATE_NODF,         "nodf"        },
    {PFSTATE_SETTOS,       "settos"      },
    {PFSTATE_RANDOMID,     "randomid"    },
    {PFSTATE_SCRUB_TCP,    "scrub-tcp"   },
    {PFSTATE_SETPRIO,      "setprio"     },
    {PFSTATE_INP_UNLINKED, "inp-unlinked"},
    {0,                    NULL          },
};

static int
state_state_flags(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)be16toh(s->state_flags));

	return 1;
}

static int
state_state_flag_names(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint16_t flags = be16toh(s->state_flags);
	char buf[128];

	buf[0] = '\0';
	for (size_t i = 0; stateflagnames[i].name != NULL; i++) {
		if ((flags & stateflagnames[i].bit) == 0)
			continue;
		if (buf[0] != '\0')
			strlcat(buf, ",", sizeof(buf));
		strlcat(buf, stateflagnames[i].name, sizeof(buf));
	}

	lua_pushstring(L, buf);

	return 1;
}

/*
 * Which timeout bucket the state sits in, under the names pf:timeouts()
 * uses. This is what explains expire: the bucket names the number the
 * ruleset configured for it.
 */
static const char *const timeoutnames[] = {
    [PFTM_TCP_FIRST_PACKET] = "tcp.first",
    [PFTM_TCP_OPENING] = "tcp.opening",
    [PFTM_TCP_ESTABLISHED] = "tcp.established",
    [PFTM_TCP_CLOSING] = "tcp.closing",
    [PFTM_TCP_FIN_WAIT] = "tcp.finwait",
    [PFTM_TCP_CLOSED] = "tcp.closed",
    [PFTM_UDP_FIRST_PACKET] = "udp.first",
    [PFTM_UDP_SINGLE] = "udp.single",
    [PFTM_UDP_MULTIPLE] = "udp.multiple",
    [PFTM_ICMP_FIRST_PACKET] = "icmp.first",
    [PFTM_ICMP_ERROR_REPLY] = "icmp.error",
    [PFTM_OTHER_FIRST_PACKET] = "other.first",
    [PFTM_OTHER_SINGLE] = "other.single",
    [PFTM_OTHER_MULTIPLE] = "other.multiple",
    [PFTM_FRAG] = "frag",
    [PFTM_INTERVAL] = "interval",
    [PFTM_ADAPTIVE_START] = "adaptive.start",
    [PFTM_ADAPTIVE_END] = "adaptive.end",
    [PFTM_SRC_NODE] = "src.track",
    [PFTM_TS_DIFF] = "tcp.tsdiff",
    [PFTM_PURGE] = "purge",
    [PFTM_UNLINKED] = "unlinked",
};

static int
state_timeout(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	lua_pushinteger(L, (lua_Integer)s->timeout);

	return 1;
}

static int
state_timeout_name(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	size_t t = s->timeout;

	if (t < sizeof(timeoutnames) / sizeof(timeoutnames[0]))
		lua_pushstring(L, timeoutnames[t]);
	else
		lua_pushnil(L);

	return 1;
}

/* rt names the route-to family of options; rt_addr is their target. */
static int
state_route(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);

	switch (s->rt) {
	case PF_ROUTETO:
		lua_pushstring(L, "route-to");
		break;
	case PF_DUPTO:
		lua_pushstring(L, "dup-to");
		break;
	case PF_REPLYTO:
		lua_pushstring(L, "reply-to");
		break;
	default:
		lua_pushnil(L);
		break;
	}

	return 1;
}

static int
state_route_addr(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	sa_family_t af = s->key[PF_SK_WIRE].af;
	char addr[INET6_ADDRSTRLEN];

	/* The target is only meaningful once a rule set one. */
	if (s->rt == PF_NOPFROUTE || PF_AZERO(&s->rt_addr, af)) {
		lua_pushnil(L);
		return 1;
	}

	if (inet_ntop(af, &s->rt_addr.pfa, addr, sizeof(addr)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	lua_pushstring(L, addr);

	return 1;
}

/*
 * TCP window and sequence tracking, one set per peer. The window PF allows
 * is seqhi - seqlo, not seqhi on its own, and wscale carries a flag bit
 * above the shift, so mask it the way pfctl does. Other protocols leave
 * every one of these at zero.
 */
static int
state_src_seqlo(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 0);

	lua_pushinteger(L, (lua_Integer)betoh32(p->seqlo));

	return 1;
}

static int
state_src_seqhi(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 0);

	lua_pushinteger(L, (lua_Integer)betoh32(p->seqhi));

	return 1;
}

static int
state_src_seqdiff(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 0);

	lua_pushinteger(L, (lua_Integer)betoh32(p->seqdiff));

	return 1;
}

static int
state_src_max_win(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 0);

	lua_pushinteger(L, (lua_Integer)be16toh(p->max_win));

	return 1;
}

static int
state_src_mss(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 0);

	lua_pushinteger(L, (lua_Integer)be16toh(p->mss));

	return 1;
}

static int
state_src_wscale(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 0);

	lua_pushinteger(L, (lua_Integer)(p->wscale & PF_WSCALE_MASK));

	return 1;
}

static int
state_dst_seqlo(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 1);

	lua_pushinteger(L, (lua_Integer)betoh32(p->seqlo));

	return 1;
}

static int
state_dst_seqhi(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 1);

	lua_pushinteger(L, (lua_Integer)betoh32(p->seqhi));

	return 1;
}

static int
state_dst_seqdiff(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 1);

	lua_pushinteger(L, (lua_Integer)betoh32(p->seqdiff));

	return 1;
}

static int
state_dst_max_win(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 1);

	lua_pushinteger(L, (lua_Integer)be16toh(p->max_win));

	return 1;
}

static int
state_dst_mss(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 1);

	lua_pushinteger(L, (lua_Integer)be16toh(p->mss));

	return 1;
}

static int
state_dst_wscale(lua_State *L, int idx)
{
	const struct pfsync_state_peer *p = statepeer(L, idx, 1);

	lua_pushinteger(L, (lua_Integer)(p->wscale & PF_WSCALE_MASK));

	return 1;
}

static const struct ro_property state_properties[] = {
    {"id",               state_id              },
    {"creatorid",        state_creatorid       },
    {"ifname",           state_ifname          },
    {"proto",            state_proto           },
    {"direction",        state_direction       },
    {"rule",             state_rule            },
    {"anchor",           state_anchor          },
    {"creation",         state_creation        },
    {"expire",           state_expire          },
    {"timeout",          state_timeout         },
    {"timeout_name",     state_timeout_name    },
    {"source",           state_source          },
    {"destination",      state_destination     },
    {"gateway",          state_gateway         },
    {"near_wire",        state_near_wire       },
    {"far_wire",         state_far_wire        },
    {"near_stack",       state_near_stack      },
    {"far_stack",        state_far_stack       },
    {"rdomain",          state_rdomain         },
    {"gateway_rdomain",  state_gateway_rdomain },
    {"route",            state_route           },
    {"route_addr",       state_route_addr      },
    {"src_state",        state_src_state       },
    {"dst_state",        state_dst_state       },
    {"connection_state", state_connection_state},
    {"state_flags",      state_state_flags     },
    {"state_flag_names", state_state_flag_names},
    {"packets_in",       state_packets_in      },
    {"packets_out",      state_packets_out     },
    {"bytes_in",         state_bytes_in        },
    {"bytes_out",        state_bytes_out       },
    {"src_seqlo",        state_src_seqlo       },
    {"src_seqhi",        state_src_seqhi       },
    {"src_seqdiff",      state_src_seqdiff     },
    {"src_max_win",      state_src_max_win     },
    {"src_mss",          state_src_mss         },
    {"src_wscale",       state_src_wscale      },
    {"dst_seqlo",        state_dst_seqlo       },
    {"dst_seqhi",        state_dst_seqhi       },
    {"dst_seqdiff",      state_dst_seqdiff     },
    {"dst_max_win",      state_dst_max_win     },
    {"dst_mss",          state_dst_mss         },
    {"dst_wscale",       state_dst_wscale      },
    {NULL,               NULL                  },
};

static int
pfstateindex(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFSTATE_MT);

	return ro_property_lookup(L, state_properties, 1, 2);
}

static int
pfstateaux(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFSTATE_MT);

	return ro_property_next(L, state_properties, 1, 2);
}

static int
pfstatepairs(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFSTATE_MT);

	lua_pushcfunction(L, pfstateaux);
	lua_pushvalue(L, 1);
	lua_pushnil(L);

	return 3;
}

static void
addbounded(luaL_Buffer *b, const char *s, size_t size)
{
	luaL_addlstring(b, s, strnlen(s, size));
}

/*
 * pfctl's print_host: the routing domain first and only when it is set,
 * then the address, then the port. A zero port is no port at all, which is
 * how a protocol PF gives no ports to prints as a bare address.
 */
static void
addhost(lua_State *L, luaL_Buffer *b, const struct pf_addr *a, uint16_t port,
        sa_family_t af, uint16_t rdomain)
{
	char s[INET6_ADDRSTRLEN];
	char num[16];

	if (rdomain != 0) {
		snprintf(num, sizeof(num), "(%u) ", be16toh(rdomain));
		luaL_addstring(b, num);
	}

	if (inet_ntop(af, &a->pfa, s, sizeof(s)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	luaL_addstring(b, s);

	if (port == 0)
		return;

	if (af == AF_INET)
		snprintf(num, sizeof(num), ":%u", be16toh(port));
	else
		snprintf(num, sizeof(num), "[%u]", be16toh(port));

	luaL_addstring(b, num);
}

/* The route-to target, which pfctl prints in braces beside its own end. */
static void
addroutetarget(lua_State *L, luaL_Buffer *b, const struct pf_addr *a,
               sa_family_t af)
{
	char s[INET6_ADDRSTRLEN];

	if (inet_ntop(af, &a->pfa, s, sizeof(s)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	luaL_addstring(b, " {");
	luaL_addstring(b, s);
	luaL_addchar(b, '}');
}

/*
 * The connection levels as pfctl prints them, which is not src_state and
 * dst_state joined: pfctl names a proxy state from either peer, refuses a
 * TCP pair it cannot name outright, and falls back to the numbers.
 */
static void
addlevels(luaL_Buffer *b, const struct pfsync_state *s,
          const struct pfsync_state_peer *src,
          const struct pfsync_state_peer *dst)
{
	static const char *const udpnames[] = PFUDPS_NAMES;
	static const char *const othernames[] = PFOTHERS_NAMES;
	const char *const *names = NULL;
	char num[64];

	if (s->proto == IPPROTO_TCP) {
		if (src->state <= TCPS_TIME_WAIT &&
		    dst->state <= TCPS_TIME_WAIT) {
			names = tcpstates;
		} else if (src->state == PF_TCPS_PROXY_SRC ||
		           dst->state == PF_TCPS_PROXY_SRC) {
			luaL_addstring(b, "PROXY:SRC");
			return;
		} else if (src->state == PF_TCPS_PROXY_DST ||
		           dst->state == PF_TCPS_PROXY_DST) {
			luaL_addstring(b, "PROXY:DST");
			return;
		} else {
			snprintf(num, sizeof(num), "<BAD STATE LEVELS %u:%u>",
			         src->state, dst->state);
			luaL_addstring(b, num);
			return;
		}
	} else if (s->proto == IPPROTO_UDP && src->state < PFUDPS_NSTATES &&
	           dst->state < PFUDPS_NSTATES) {
		names = udpnames;
	} else if (s->proto != IPPROTO_ICMP && s->proto != IPPROTO_ICMPV6 &&
	           src->state < PFOTHERS_NSTATES &&
	           dst->state < PFOTHERS_NSTATES) {
		names = othernames;
	}

	if (names == NULL) {
		snprintf(num, sizeof(num), "%u:%u", src->state, dst->state);
		luaL_addstring(b, num);
		return;
	}

	luaL_addstring(b, names[src->state]);
	luaL_addchar(b, ':');
	luaL_addstring(b, names[dst->state]);
}

/***
Render a state exactly as a pfctl -s states line prints it.

The near end comes first, then the arrow, then the far end, with the other
key's reading of an end in parentheses where the two disagree. An af-to
state takes the outbound arrow whichever way it runs.
@function state:__tostring
@treturn string
@usage
print(tostring(s))
-- em0 tcp 10.0.0.1:22 &lt;- 10.0.0.2:51000       ESTABLISHED:ESTABLISHED
*/
static int
pfstatetostring(lua_State *L)
{
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	const struct pfsync_state_peer *src, *dst;
	struct pfsync_state_key sk, nk;
	const char *proto = cacheprotoent(s->proto);
	int afto = stateafto(s);
	int icmp = s->proto == IPPROTO_ICMP || s->proto == IPPROTO_ICMPV6;
	luaL_Buffer b;
	char num[16];

	/*
	 * The keys are copied because ICMP needs one port overwritten: the
	 * two keys carry different ICMP ids, and without this every ICMP
	 * state would report a translation it does not have.
	 */
	if ((int)s->direction == PF_OUT) {
		src = &s->src;
		dst = &s->dst;
		sk = s->key[PF_SK_STACK];
		nk = s->key[PF_SK_WIRE];
		if (icmp)
			sk.port[0] = nk.port[0];
	} else {
		src = &s->dst;
		dst = &s->src;
		sk = s->key[PF_SK_WIRE];
		nk = s->key[PF_SK_STACK];
		if (icmp)
			sk.port[1] = nk.port[1];
	}

	luaL_buffinit(L, &b);

	addbounded(&b, s->ifname, sizeof(s->ifname));
	luaL_addchar(&b, ' ');

	if (proto != NULL) {
		luaL_addstring(&b, proto);
	} else {
		snprintf(num, sizeof(num), "%u", s->proto);
		luaL_addstring(&b, num);
	}
	luaL_addchar(&b, ' ');

	addhost(L, &b, &nk.addr[1], nk.port[1], nk.af, nk.rdomain);
	if (nk.af != sk.af || PF_ANEQ(&nk.addr[1], &sk.addr[1], nk.af) ||
	    nk.port[1] != sk.port[1] || nk.rdomain != sk.rdomain) {
		int i = afto ? 0 : 1;

		luaL_addstring(&b, " (");
		addhost(L, &b, &sk.addr[i], sk.port[i], sk.af, sk.rdomain);
		luaL_addchar(&b, ')');
	}

	if ((int)s->direction == PF_IN && !PF_AZERO(&s->rt_addr, sk.af))
		addroutetarget(L, &b, &s->rt_addr, sk.af);

	luaL_addstring(&b, stateoutward(s) ? " -> " : " <- ");

	addhost(L, &b, &nk.addr[0], nk.port[0], nk.af, nk.rdomain);
	if (nk.af != sk.af || PF_ANEQ(&nk.addr[0], &sk.addr[0], nk.af) ||
	    nk.port[0] != sk.port[0] || nk.rdomain != sk.rdomain) {
		int i = afto ? 1 : 0;

		luaL_addstring(&b, " (");
		addhost(L, &b, &sk.addr[i], sk.port[i], sk.af, sk.rdomain);
		luaL_addchar(&b, ')');
	}

	if ((int)s->direction == PF_OUT && !PF_AZERO(&s->rt_addr, nk.af))
		addroutetarget(L, &b, &s->rt_addr, nk.af);

	luaL_addstring(&b, "       ");
	addlevels(&b, s, src, dst);

	luaL_pushresult(&b);

	return 1;
}

static const luaL_Reg pfstatemeta[] = {
    {"__index",    pfstateindex   },
    {"__pairs",    pfstatepairs   },
    {"__tostring", pfstatetostring},
    {NULL,         NULL           },
};

static int
pfstateslen(lua_State *L)
{
	struct pfioc_states *ps = luaL_checkudata(L, 1, PFSTATES_MT);

	lua_pushinteger(L,
	                (lua_Integer)(ps->ps_len / sizeof(ps->ps_states[0])));

	return 1;
}

static int
pfstatesindex(lua_State *L)
{
	struct pfioc_states *ps = luaL_checkudata(L, 1, PFSTATES_MT);
	const struct pfsync_state *p = ps->ps_states;
	struct pfsync_state *s;
	size_t n = ps->ps_len / sizeof(ps->ps_states[0]);
	int worked;
	lua_Integer idx = lua_tointegerx(L, 2, &worked);

	if (!worked || idx < 1 || (size_t)idx > n) {
		lua_pushnil(L);
		return 1;
	}

	s = lua_newuserdata(L, sizeof(*s));
	luaL_setmetatable(L, PFSTATE_MT);

	*s = p[idx - 1];

	return 1;
}

static int
pfstatesgc(lua_State *L)
{
	struct pfioc_states *ps = luaL_checkudata(L, 1, PFSTATES_MT);

	free(ps->ps_buf);
	ps->ps_buf = NULL;

	return 0;
}

static const luaL_Reg pfstatesmeta[] = {
    {"__len",   pfstateslen  },
    {"__index", pfstatesindex},
    {"__gc",    pfstatesgc   },
    {NULL,      NULL         },
};

/***
Read one state by id.
@function pf:getstate
@int id
@int[opt=0] creatorid
@treturn ?userdata state, or nil if no state has that id
@raise if the ioctl fails
@usage local s = h:states()[1]; h:getstate(s.id, s.creatorid)
*/
int
pfgetstate(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	lua_Integer id = luaL_checkinteger(L, 2);
	lua_Integer creatorid = luaL_optinteger(L, 3, 0);
	struct pfioc_state *ps;
	struct pfsync_state *s;

	ps = lua_newuserdata(L, sizeof(*ps));
	memset(ps, 0, sizeof(*ps));

	ps->state.id = htobe64((uint64_t)id);
	ps->state.creatorid = htobe32((uint32_t)creatorid);

	if (ioctl(pf->fd, DIOCGETSTATE, ps) < 0) {
		if (errno == ENOENT) {
			lua_pushnil(L);
			return 1;
		}
		luaL_error(L, "DIOCGETSTATE: %s", strerror(errno));
	}

	s = lua_newuserdata(L, sizeof(*s));
	luaL_setmetatable(L, PFSTATE_MT);
	*s = ps->state;

	return 1;
}

/***
Remove every state, or every state on one interface.
@function pf:clearstates
@string[opt] interface
@treturn int states removed
@raise if the ioctl fails
*/
int
pfclearstates(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *ifname = luaL_optstring(L, 2, "");
	struct pfioc_state_kill psk;

	memset(&psk, 0, sizeof(psk));

	if (strlcpy(psk.psk_ifname, ifname, sizeof(psk.psk_ifname)) >=
	    sizeof(psk.psk_ifname))
		luaL_error(L, "interface name too long");

	if (ioctl(pf->fd, DIOCCLRSTATES, &psk) < 0)
		luaL_error(L, "DIOCCLRSTATES: %s", strerror(errno));

	lua_pushinteger(L, (lua_Integer)psk.psk_killed);

	return 1;
}

void
luapf_states_register(lua_State *L)
{
	luaL_newmetatable(L, PFSTATES_MT);
	luaL_setfuncs(L, pfstatesmeta, 0);
	lua_pop(L, 1);

	luaL_newmetatable(L, PFSTATE_MT);
	luaL_setfuncs(L, pfstatemeta, 0);
	lua_pop(L, 1);
}

/***
A single state.

Read-only properties, all of them served by \_\_index and walked by pairs:

Identity and origin: id, creatorid, ifname, proto, direction, rule and
anchor. rule numbers the rule inside its anchor, so read the two together;
each is -1 when there is none.

Age: creation and expire in seconds, timeout as the number of the bucket
the state sits in, and timeout_name as that bucket under the names
pf:timeouts() uses. The bucket is what sets expire.

Endpoints: source, destination and gateway, each host:port, or
[host]:port for IPv6. source is the endpoint that opened the connection.
gateway is the same endpoint as the far side of translation sees it.
Those three are the direction-relative reading of four addresses:
near_wire, far_wire, near_stack and far_stack. The near end is the side of
PF this host and the hosts behind it are on, the far end the other side,
and neither moves with direction. An end is translated when its wire and
stack readings differ. gateway names one translated end, so a flow that
nat-to and rdr-to have both translated can only be read from these four.
A rule that translates between address families makes the two readings of
one end differ in family as well as address, and the near/far pairing is
what holds them together. A NAT64 flow reads:

    near_stack  10.64.0.1:65154     far_stack  10.64.0.2:9999
    near_wire   [fd00:64::2]:1179   far_wire   [64:ff9b::2]:9999

source and destination are the stack pair here and gateway the near wire,
so the seven names carry four values. far_wire is the one with no
direction-relative name, and it is exactly what gateway cannot reach.
Comparing against pfctl, note it prints an inbound af-to state with the
outbound arrow.

rdomain is the routing domain source and destination sit in, and
gateway_rdomain the one gateway sits in. Addresses carry no rdomain of
their own, so two states in different routing domains may report the same
source and destination; compare the rdomain as well.

Routing: route is "route-to", "dup-to" or "reply-to" when a rule set one,
otherwise nil, and route_addr is its target address without a port.

Connection state: src_state and dst_state are the two levels pfctl joins
with a colon, and connection_state is that pair, for example
"ESTABLISHED:ESTABLISHED". src_state belongs to source and dst_state to
destination. A protocol with no names for its levels, ICMP among them,
reports the numbers instead. pfctl orders the pair by the direction PF saw
the packets in, so for an inbound state it prints these two the other way
round.

Flags: state_flags as the raw bits and state_flag_names as their names
joined by commas, empty when no bit is set.

Counters: packets_in, packets_out, bytes_in and bytes_out, counting the
direction PF saw the packet in, the same as everywhere else in this
binding.

tostring renders the state as a pfctl -s states line. It is not built
out of the properties above: pfctl leaves a zero port off entirely, hides
the ICMP id difference the two keys carry, and names a TCP proxy pair from
either peer.

TCP windows: src_seqlo, src_seqhi, src_seqdiff, src_max_win, src_mss,
src_wscale and the same six for dst. The window PF allows a peer is
seqhi - seqlo. wscale is the shift with pfctl's mask already applied.
Every one of these is zero for a protocol PF does not window.
@table state
*/
