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

Each entry holds name, skip, states, rules, routes, srcnodes, cleared and
eight counter pairs named like in4_pass_packets and out6_block_bytes. The
filter matches an interface or a group, not a prefix.
@function pf:interfaces
@string[opt] filter interface or group name
@treturn table array of interface tables
@raise if the ioctl fails
*/
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

		lua_pushstring(L, k->pfik_name);
		lua_setfield(L, -2, "name");
		lua_pushboolean(L, (k->pfik_flags & PFI_IFLAG_SKIP) != 0);
		lua_setfield(L, -2, "skip");
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

/***
Read the source tracking nodes.

Nodes exist only for rules that track them, such as an overload rule or a
sticky pool. Each entry holds address, translation, states, connections,
packets_in, packets_out, bytes_in, bytes_out, creation, expire and rule.
@function pf:srcnodes
@treturn table array of node tables
@raise if the ioctl fails
*/
int
pfsrcnodes(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_src_nodes *psn;
	const struct pf_src_node *nodes;
	size_t count;

	psn = lua_newuserdata(L, sizeof(*psn));
	memset(psn, 0, sizeof(*psn));

	if (ioctl(pf->fd, DIOCGETSRCNODES, psn) < 0)
		luaL_error(L, "DIOCGETSRCNODES: %s", strerror(errno));

	psn->psn_buf = lua_newuserdata(L, psn->psn_len);
	memset(psn->psn_buf, 0, psn->psn_len);

	if (ioctl(pf->fd, DIOCGETSRCNODES, psn) < 0)
		luaL_error(L, "DIOCGETSRCNODES: %s", strerror(errno));

	nodes = psn->psn_src_nodes;
	count = psn->psn_len / sizeof(struct pf_src_node);

	lua_newtable(L);

	for (size_t i = 0; i < count; i++) {
		const struct pf_src_node *n = &nodes[i];

		lua_newtable(L);

		pushaddress(L, n->af, &n->addr);
		lua_setfield(L, -2, "address");
		pushaddress(L, n->naf != 0 ? n->naf : n->af, &n->raddr);
		lua_setfield(L, -2, "translation");
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
		lua_pushinteger(L, (lua_Integer)n->rule.nr);
		lua_setfield(L, -2, "rule");

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
