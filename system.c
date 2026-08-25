/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "banned.h"

/***
@module pf
*/

struct namedindex {
	const char *name;
	int index;
};

static const struct namedindex limits[] = {
    {"states",        PF_LIMIT_STATES       },
    {"src-nodes",     PF_LIMIT_SRC_NODES    },
    {"frags",         PF_LIMIT_FRAGS        },
    {"tables",        PF_LIMIT_TABLES       },
    {"table-entries", PF_LIMIT_TABLE_ENTRIES},
    {"pktdelay-pkts", PF_LIMIT_PKTDELAY_PKTS},
    {"anchors",       PF_LIMIT_ANCHORS      },
    {NULL,            0                     },
};

static const struct namedindex timeouts[] = {
    {"tcp.first",       PFTM_TCP_FIRST_PACKET  },
    {"tcp.opening",     PFTM_TCP_OPENING       },
    {"tcp.established", PFTM_TCP_ESTABLISHED   },
    {"tcp.closing",     PFTM_TCP_CLOSING       },
    {"tcp.finwait",     PFTM_TCP_FIN_WAIT      },
    {"tcp.closed",      PFTM_TCP_CLOSED        },
    {"tcp.tsdiff",      PFTM_TS_DIFF           },
    {"udp.first",       PFTM_UDP_FIRST_PACKET  },
    {"udp.single",      PFTM_UDP_SINGLE        },
    {"udp.multiple",    PFTM_UDP_MULTIPLE      },
    {"icmp.first",      PFTM_ICMP_FIRST_PACKET },
    {"icmp.error",      PFTM_ICMP_ERROR_REPLY  },
    {"other.first",     PFTM_OTHER_FIRST_PACKET},
    {"other.single",    PFTM_OTHER_SINGLE      },
    {"other.multiple",  PFTM_OTHER_MULTIPLE    },
    {"frag",            PFTM_FRAG              },
    {"interval",        PFTM_INTERVAL          },
    {"adaptive.start",  PFTM_ADAPTIVE_START    },
    {"adaptive.end",    PFTM_ADAPTIVE_END      },
    {"src.track",       PFTM_SRC_NODE          },
    {NULL,              0                      },
};

/***
Read the configured limits.

Keys are the names pfctl uses: states, src-nodes, frags, tables,
table-entries, pktdelay-pkts and anchors.
@function pf:limits
@treturn table limit name to value
@raise if the ioctl fails
*/
int
pflimits(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_limit pl;

	lua_newtable(L);

	for (const struct namedindex *n = limits; n->name != NULL; n++) {
		memset(&pl, 0, sizeof(pl));
		pl.index = n->index;

		if (ioctl(pf->fd, DIOCGETLIMIT, &pl) < 0)
			luaL_error(L, "DIOCGETLIMIT %s: %s", n->name,
			           strerror(errno));

		lua_pushinteger(L, (lua_Integer)pl.limit);
		lua_setfield(L, -2, n->name);
	}

	return 1;
}

/***
Read the configured timeouts in seconds.

Keys are the names pfctl uses, such as tcp.established and src.track.
@function pf:timeouts
@treturn table timeout name to seconds
@raise if the ioctl fails
*/
int
pftimeouts(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_tm pt;

	lua_newtable(L);

	for (const struct namedindex *n = timeouts; n->name != NULL; n++) {
		memset(&pt, 0, sizeof(pt));
		pt.timeout = n->index;

		if (ioctl(pf->fd, DIOCGETTIMEOUT, &pt) < 0)
			luaL_error(L, "DIOCGETTIMEOUT %s: %s", n->name,
			           strerror(errno));

		lua_pushinteger(L, (lua_Integer)pt.seconds);
		lua_setfield(L, -2, n->name);
	}

	return 1;
}

static void
pushifcounters(lua_State *L, const struct pfi_kif *k)
{
	static const char *const names[2][2][2] = {
	    {{"in4_pass", "in4_block"}, {"out4_pass", "out4_block"}},
	    {{"in6_pass", "in6_block"}, {"out6_pass", "out6_block"}},
	};
	char field[24];

	for (int af = 0; af < 2; af++) {
		for (int dir = 0; dir < 2; dir++) {
			for (int act = 0; act < 2; act++) {
				const char *name = names[af][dir][act];

				snprintf(field, sizeof(field), "%s_packets",
				         name);
				lua_pushinteger(
				    L,
				    (lua_Integer)k->pfik_packets[af][dir][act]);
				lua_setfield(L, -2, field);

				snprintf(field, sizeof(field), "%s_bytes",
				         name);
				lua_pushinteger(
				    L,
				    (lua_Integer)k->pfik_bytes[af][dir][act]);
				lua_setfield(L, -2, field);
			}
		}
	}
}

/***
Read the per-interface counters, the same numbers as pfctl -vvsI.

Each entry holds name, skip, any, states, rules, routes, srcnodes, cleared
and eight counter pairs named like in4_pass_packets and out6_block_bytes.
skip and any are the two flags pf keeps per interface: skip is set by
pfctl -F Interfaces or a set skip rule, any marks the group that matches
every non-loopback interface. The filter matches an interface or a group,
not a prefix.
@function pf:interfaces
@string[opt] filter interface or group name
@treturn table array of interface tables
@raise if the ioctl fails
*/
/*
 * These entries are lua tables rather than userdata, which is no barrier
 * to a metamethod: a table takes a metatable the same way. Each renders
 * what pfctl prints for it, so printing one is worth doing.
 */

/*
 * A metamethod is reachable through getmetatable, so it can be called
 * with anything at all. Accept only a table this module gave this
 * metatable, the way luaL_checkudata does for userdata.
 */
static void
checkentry(lua_State *L, const char *meta, const char *what)
{
	if (!lua_getmetatable(L, 1)) {
		luaL_error(L, "expected %s", what);
		return;
	}
	luaL_getmetatable(L, meta);
	if (!lua_rawequal(L, -1, -2))
		luaL_error(L, "expected %s", what);
	lua_pop(L, 2);
}

/* Its fields stay writable, so a required one is still checked. */
static const char *
entrystring(lua_State *L, const char *field)
{
	const char *str;

	lua_getfield(L, 1, field);
	str = lua_tostring(L, -1);
	if (str == NULL)
		luaL_error(L, "%s is not a string", field);

	return str;
}

static lua_Integer
entryint(lua_State *L, const char *field)
{
	lua_Integer v;

	lua_getfield(L, 1, field);
	if (!lua_isnumber(L, -1))
		luaL_error(L, "%s is not a number", field);
	v = lua_tointeger(L, -1);
	lua_pop(L, 1);

	return v;
}

static int
iface_tostring(lua_State *L)
{
	checkentry(L, "PFIFACEMT", "an interface");
	lua_pushstring(L, entrystring(L, "name"));

	return 1;
}

/* pfctl writes the rate as thousandths, printed as N.N over the period. */
static int
srcnode_tostring(lua_State *L)
{
	luaL_Buffer b;
	lua_Integer count, seconds, states, conns;
	const char *type;

	checkentry(L, "PFSRCNODEMT", "a source node");

	states = entryint(L, "states");
	conns = entryint(L, "connections");

	lua_getfield(L, 1, "conn_rate");
	if (!lua_istable(L, -1))
		luaL_error(L, "conn_rate is not a table");
	lua_getfield(L, -1, "count");
	count = lua_tointeger(L, -1);
	lua_getfield(L, -2, "seconds");
	seconds = lua_tointeger(L, -1);
	lua_pop(L, 3);

	luaL_buffinit(L, &b);
	luaL_addstring(&b, entrystring(L, "address"));

	lua_getfield(L, 1, "translation");
	if (!lua_isnil(L, -1)) {
		const char *raddr = lua_tostring(L, -1);

		if (raddr == NULL)
			luaL_error(L, "translation is not a string");
		type = entrystring(L, "type");
		if (strcmp(type, "none") == 0)
			luaL_addstring(&b, " ??? ");
		else {
			luaL_addchar(&b, ' ');
			luaL_addstring(&b, type);
			luaL_addstring(&b, "-to ");
		}
		luaL_addstring(&b, raddr);
	}

	lua_pushfstring(L, " ( states %I, connections %I, rate %I.%I/%Is )",
	    states, conns, (lua_Integer)(count / 1000),
	    (lua_Integer)((count % 1000) / 100), seconds);
	luaL_addvalue(&b);

	luaL_pushresult(&b);

	return 1;
}

static void
setentrymeta(lua_State *L, const char *name, lua_CFunction f)
{
	if (luaL_newmetatable(L, name)) {
		lua_pushcfunction(L, f);
		lua_setfield(L, -2, "__tostring");
	}
	lua_setmetatable(L, -2);
}

int
pfinterfaces(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *filter = luaL_optstring(L, 2, "");
	struct pfioc_iface io;
	const struct pfi_kif *kifs;
	int cap = 64;

	for (;;) {
		memset(&io, 0, sizeof(io));
		io.pfiio_esize = sizeof(struct pfi_kif);
		io.pfiio_size = cap;

		if (strlcpy(io.pfiio_name, filter, sizeof(io.pfiio_name)) >=
		    sizeof(io.pfiio_name))
			luaL_error(L, "interface name too long");

		io.pfiio_buffer =
		    lua_newuserdata(L, sizeof(struct pfi_kif) * (size_t)cap);
		memset(io.pfiio_buffer, 0,
		       sizeof(struct pfi_kif) * (size_t)cap);

		if (ioctl(pf->fd, DIOCIGETIFACES, &io) < 0)
			luaL_error(L, "DIOCIGETIFACES: %s", strerror(errno));

		if (io.pfiio_size < cap)
			break;

		lua_pop(L, 1);

		if (cap > 65536)
			luaL_error(L, "too many interfaces");

		cap *= 2;
	}

	kifs = io.pfiio_buffer;

	lua_newtable(L);

	for (int i = 0; i < io.pfiio_size; i++) {
		const struct pfi_kif *k = &kifs[i];

		lua_newtable(L);

		/*
		 * A kernel name field can fill its array with no NUL, so
		 * bound every such read to the size of the array itself.
		 */
		lua_pushlstring(L, k->pfik_name,
		                strnlen(k->pfik_name, sizeof(k->pfik_name)));
		lua_setfield(L, -2, "name");
		lua_pushboolean(L, (k->pfik_flags & PFI_IFLAG_SKIP) != 0);
		lua_setfield(L, -2, "skip");
		lua_pushboolean(L, (k->pfik_flags & PFI_IFLAG_ANY) != 0);
		lua_setfield(L, -2, "any");
		lua_pushinteger(L, (lua_Integer)k->pfik_states);
		lua_setfield(L, -2, "states");
		lua_pushinteger(L, (lua_Integer)k->pfik_rules);
		lua_setfield(L, -2, "rules");
		lua_pushinteger(L, (lua_Integer)k->pfik_routes);
		lua_setfield(L, -2, "routes");
		lua_pushinteger(L, (lua_Integer)k->pfik_srcnodes);
		lua_setfield(L, -2, "srcnodes");
		lua_pushinteger(L, (lua_Integer)k->pfik_tzero);
		lua_setfield(L, -2, "cleared");

		pushifcounters(L, k);

		setentrymeta(L, "PFIFACEMT", iface_tostring);
		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}

static void
pushaddress(lua_State *L, sa_family_t af, const struct pf_addr *a)
{
	char s[INET6_ADDRSTRLEN];

	if (inet_ntop(af, a, s, sizeof(s)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	lua_pushstring(L, s);
}

/*
 * PF_SN_NONE has no matching pfctl label because pfctl never prints an
 * untranslated node's type at all.
 */
static const char *const srcnodetypes[PF_SN_MAX] = {
    [PF_SN_NONE] = "none",
    [PF_SN_NAT] = "nat",
    [PF_SN_RDR] = "rdr",
    [PF_SN_ROUTE] = "route",
};

/***
Read the source tracking nodes.

Nodes exist only for rules that track them, such as an overload rule or a
sticky pool. Each entry holds address, type, states, connections,
packets_in, packets_out, bytes_in, bytes_out, creation, expire and
conn_rate, which holds the count and seconds of the connection rate pfctl
prints.

translation is set only where the node carries one, and rule only where
the node came from a numbered rule, so both read as nil where pfctl
prints nothing. type is none, nat, rdr or route, and unknown if the kernel
grows another; nat, rdr and route are what pfctl prints as nat-to, rdr-to
and route-to. There is no interface: the kernel clears the node's kif
pointer on its way out, and pfctl does not print one either.
@function pf:srcnodes
@treturn table array of node tables
@raise if the ioctl fails
*/
int
pfsrcnodes(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_src_nodes *psn;
	const struct pf_src_node *nodes = NULL;
	size_t len, count = 0;

	psn = lua_newuserdata(L, sizeof(*psn));
	memset(psn, 0, sizeof(*psn));

	if (ioctl(pf->fd, DIOCGETSRCNODES, psn) < 0)
		luaL_error(L, "DIOCGETSRCNODES: %s", strerror(errno));

	/*
	 * The kernel stops at psn_len and reports no truncation, so a node
	 * that appeared since the sizing call would be dropped without a
	 * word. A buffer the answer filled exactly may have been cut short,
	 * so double it and ask again until it is not.
	 */
	for (len = psn->psn_len; len > 0; len *= 2) {
		psn->psn_len = len;
		psn->psn_buf = lua_newuserdata(L, len);
		memset(psn->psn_buf, 0, len);

		if (ioctl(pf->fd, DIOCGETSRCNODES, psn) < 0)
			luaL_error(L, "DIOCGETSRCNODES: %s", strerror(errno));

		if (psn->psn_len < len) {
			nodes = psn->psn_src_nodes;
			count = psn->psn_len / sizeof(struct pf_src_node);
			break;
		}

		lua_pop(L, 1);
	}

	lua_newtable(L);

	for (size_t i = 0; i < count; i++) {
		const struct pf_src_node *n = &nodes[i];
		sa_family_t naf = n->naf != 0 ? n->naf : n->af;

		lua_newtable(L);

		pushaddress(L, n->af, &n->addr);
		lua_setfield(L, -2, "address");

		/* An all zero raddr is not the address 0.0.0.0, it is the
		 * absence of a translation, which is why pfctl prints
		 * nothing for it. */
		if (!PF_AZERO(&n->raddr, naf)) {
			pushaddress(L, naf, &n->raddr);
			lua_setfield(L, -2, "translation");
		}

		lua_pushstring(L, n->type < PF_SN_MAX ? srcnodetypes[n->type]
		                                      : "unknown");
		lua_setfield(L, -2, "type");

		lua_pushinteger(L, (lua_Integer)n->states);
		lua_setfield(L, -2, "states");
		lua_pushinteger(L, (lua_Integer)n->conn);
		lua_setfield(L, -2, "connections");
		lua_pushinteger(L, (lua_Integer)n->packets[0]);
		lua_setfield(L, -2, "packets_in");
		lua_pushinteger(L, (lua_Integer)n->packets[1]);
		lua_setfield(L, -2, "packets_out");
		lua_pushinteger(L, (lua_Integer)n->bytes[0]);
		lua_setfield(L, -2, "bytes_in");
		lua_pushinteger(L, (lua_Integer)n->bytes[1]);
		lua_setfield(L, -2, "bytes_out");
		lua_pushinteger(L, (lua_Integer)n->creation);
		lua_setfield(L, -2, "creation");
		lua_pushinteger(L, (lua_Integer)n->expire);
		lua_setfield(L, -2, "expire");

		lua_newtable(L);
		lua_pushinteger(L, (lua_Integer)n->conn_rate.count);
		lua_setfield(L, -2, "count");
		lua_pushinteger(L, (lua_Integer)n->conn_rate.seconds);
		lua_setfield(L, -2, "seconds");
		lua_setfield(L, -2, "conn_rate");

		/* The kernel hands "no rule" over as -1 in a u_int32_t, and
		 * a rule numbered four billion helps nobody. */
		if (n->rule.nr != (u_int32_t)-1) {
			lua_pushinteger(L, (lua_Integer)n->rule.nr);
			lua_setfield(L, -2, "rule");
		}

		setentrymeta(L, "PFSRCNODEMT", srcnode_tostring);
		lua_rawseti(L, -2, (lua_Integer)i + 1);
	}

	return 1;
}

/***
Kill the source nodes of one address, or of a range.
@function pf:killsrcnodes
@string address
@string[opt] to end of a range starting at address
@treturn int nodes killed
@raise if an address cannot be parsed
*/
int
pfkillsrcnodes(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *from = luaL_checkstring(L, 2);
	const char *to = luaL_optstring(L, 3, NULL);
	struct pfioc_src_node_kill psnk;
	sa_family_t af = AF_INET;

	memset(&psnk, 0, sizeof(psnk));

	if (inet_pton(AF_INET, from, &psnk.psnk_src.addr.v.a.addr) != 1) {
		if (inet_pton(AF_INET6, from, &psnk.psnk_src.addr.v.a.addr) !=
		    1)
			luaL_error(L, "bad address: %s", from);
		af = AF_INET6;
	}

	memset(&psnk.psnk_src.addr.v.a.mask, 0xff,
	       af == AF_INET ? 4 : sizeof(psnk.psnk_src.addr.v.a.mask));

	if (to != NULL) {
		if (inet_pton(af, to, &psnk.psnk_dst.addr.v.a.addr) != 1)
			luaL_error(L, "bad address: %s", to);
		memset(&psnk.psnk_dst.addr.v.a.mask, 0xff,
		       af == AF_INET ? 4 : sizeof(psnk.psnk_dst.addr.v.a.mask));
	}

	psnk.psnk_af = af;

	if (ioctl(pf->fd, DIOCKILLSRCNODES, &psnk) < 0)
		luaL_error(L, "DIOCKILLSRCNODES: %s", strerror(errno));

	lua_pushinteger(L, (lua_Integer)psnk.psnk_killed);

	return 1;
}

/***
Remove every source tracking node.
@function pf:clearsrcnodes
@raise if the ioctl fails
*/
int
pfclearsrcnodes(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	if (ioctl(pf->fd, DIOCCLRSRCNODES, NULL) < 0)
		luaL_error(L, "DIOCCLRSRCNODES: %s", strerror(errno));

	return 0;
}
