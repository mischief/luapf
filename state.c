/* SPDX-License-Identifier: ISC */
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netdb.h>

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

	assert(strlen(p->p_name) < maxprotosize);

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

	lua_pushstring(L, s->ifname);

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

/* Inbound states read from the stack key, outbound ones from the wire key. */
static void
gimmekey(lua_State *L, const struct pfsync_state *s, int idx,
         const struct pf_addr **raddr, uint16_t *rport, sa_family_t *raf)
{
	const struct pfsync_state_key *key;

	/* XXX: af-to states have two address families and are not handled. */
	if (s->key[PF_SK_STACK].af != s->key[PF_SK_WIRE].af)
		luaL_error(L, "what even is af-to");

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

/* TODO: maybe source/dest should be a table, or expose rdomain via another
 * property */
static int
state_source(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	const struct pf_addr *a;
	uint16_t p;
	sa_family_t af;

	gimmekey(L, s, s->direction == PF_OUT ? 1 : 0, &a, &p, &af);

	return pushhostport(L, af, a, p);
}

static int
state_destination(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	const struct pf_addr *a;
	uint16_t p;
	sa_family_t af;

	gimmekey(L, s, s->direction == PF_OUT ? 0 : 1, &a, &p, &af);

	return pushhostport(L, af, a, p);
}

static int
state_gateway(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	const struct pfsync_state_key *stk;

	if (s->direction != PF_OUT) {
		lua_pushnil(L);
		return 1;
	}

	stk = &s->key[PF_SK_STACK];

	return pushhostport(L, stk->af, &stk->addr[1], be16toh(stk->port[1]));
}

static int
state_packets_in(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->packets[0], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static int
state_packets_out(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->packets[1], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static int
state_bytes_in(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->bytes[0], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static int
state_bytes_out(lua_State *L, int idx)
{
	struct pfsync_state *s = luaL_checkudata(L, idx, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->bytes[1], d);
	lua_pushinteger(L, (lua_Integer)d);

	return 1;
}

static const struct ro_property state_properties[] = {
    {"id",          state_id         },
    {"creatorid",   state_creatorid  },
    {"ifname",      state_ifname     },
    {"proto",       state_proto      },
    {"direction",   state_direction  },
    {"rule",        state_rule       },
    {"creation",    state_creation   },
    {"expire",      state_expire     },
    {"source",      state_source     },
    {"destination", state_destination},
    {"gateway",     state_gateway    },
    {"packets_in",  state_packets_in },
    {"packets_out", state_packets_out},
    {"bytes_in",    state_bytes_in   },
    {"bytes_out",   state_bytes_out  },
    {NULL,          NULL             },
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

static const luaL_Reg pfstatemeta[] = {
    {"__index", pfstateindex},
    {"__pairs", pfstatepairs},
    {NULL,      NULL        },
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

Read-only properties: id, creatorid, ifname, proto, direction, rule,
creation, expire, source, destination, gateway, packets_in, packets_out,
bytes_in and bytes_out. Addresses read as host:port, or [host]:port for
IPv6. Iterating with pairs walks the same set.
@table state
*/
