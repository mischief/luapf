#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <assert.h>
#include <stdlib.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"

static const char*
cacheprotoent(int proto)
{
	enum { maxentries = 256, maxprotosize = 16 };
	static char protocache[maxentries][maxprotosize];
	struct protoent *p;

	if(protocache[proto][0])
		return protocache[proto];

	p = getprotobynumber(proto);
	if(!p)
		return NULL;

	assert(proto < maxentries);
	assert(strlen(p->p_name) < maxprotosize);

	strlcpy(protocache[proto], p->p_name, maxprotosize);

	return protocache[proto];
}

static int
pfstateindex(lua_State *L)
{
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	//struct pfsync_state_key *sk;
	struct pf_addr pfa;
	const char *key;
	char addr[INET6_ADDRSTRLEN];
	int af;
	
	if(!lua_isstring(L, 2)){
		lua_pushnil(L);
		return 1;
	}

	key = lua_tostring(L, 2);

	if(!strcmp(key, "id")){
		lua_pushinteger(L, betoh64(s->id));
		return 1;
	} else if(!strcmp(key, "ifname")){
		lua_pushstring(L, s->ifname);
		return 1;
	} else if(!strcmp(key, "proto")){
		lua_pushstring(L, cacheprotoent(s->proto));
		return 1;
	} else if(!strcmp(key, "direction")){
		if(s->direction == PF_IN)
			lua_pushliteral(L, "in");
		else
			lua_pushliteral(L, "out");
		return 1;
	} else if(!strcmp(key, "key")){
		lua_newtable(L);

		lua_newtable(L);

		lua_newtable(L);
		pfa = s->key[0].addr[0];
		af = s->key[0].af;
		if(inet_ntop(af, &pfa, addr, sizeof(addr)) == NULL)
			luaL_error(L, "inet_ntop: %s", strerror(errno));
		lua_pushstring(L, addr);
		lua_seti(L, -2, 1);

		pfa = s->key[0].addr[1];
		if(inet_ntop(af, &pfa, addr, sizeof(addr)) == NULL)
			luaL_error(L, "inet_ntop: %s", strerror(errno));
		lua_pushstring(L, addr);
		lua_seti(L, -2, 2);

		lua_setfield(L, -2, "addr");

		lua_newtable(L);
		lua_pushinteger(L, ntohs(s->key[0].port[0]));
		lua_seti(L, -2, 1);
		lua_pushinteger(L, ntohs(s->key[0].port[1]));
		lua_seti(L, -2, 2);
		lua_setfield(L, -2, "port");

		lua_seti(L, -2, 1);

		lua_newtable(L);

		lua_newtable(L);
		pfa = s->key[1].addr[0];
		af = s->key[1].af;
		if(inet_ntop(af, &pfa, addr, sizeof(addr)) == NULL)
			luaL_error(L, "inet_ntop: %s", strerror(errno));
		lua_pushstring(L, addr);
		lua_seti(L, -2, 1);

		pfa = s->key[1].addr[1];
		if(inet_ntop(af, &pfa, addr, sizeof(addr)) == NULL)
			luaL_error(L, "inet_ntop: %s", strerror(errno));
		lua_pushstring(L, addr);
		lua_seti(L, -2, 2);

		lua_setfield(L, -2, "addr");

		lua_newtable(L);
		lua_pushinteger(L, ntohs(s->key[1].port[0]));
		lua_seti(L, -2, 1);
		lua_pushinteger(L, ntohs(s->key[1].port[1]));
		lua_seti(L, -2, 2);
		lua_setfield(L, -2, "port");

		lua_seti(L, -2, 2);

		return 1;
/*
	} else if(!strcmp(key, "source")){
		sk = (s->direction == PF_OUT) ? &s->key[PF_SK_WIRE] : &s->key[PF_SK_STACK];

		lua_pushfstring(L, "%s:%d", addr, ntohs(sk->port[1]));
		return 1;
	} else if(!strcmp(key, "destination")){
		sk = (s->direction == PF_OUT) ? &s->key[PF_SK_WIRE] : &s->key[PF_SK_STACK];
		pfa = sk->addr[0];

		if(inet_ntop(sk->af, &pfa, addr, sizeof(addr)) == NULL)
			luaL_error(L, "inet_ntop: %s", strerror(errno));

		lua_pushfstring(L, "%s:%d", addr, ntohs(sk->port[0]));
		return 1;
*/
	} else if(!strcmp(key, "rule")){
		if(betoh32(s->rule) == (uint32_t)-1)
			lua_pushnil(L);
		else
			lua_pushinteger(L, betoh32(s->rule));
		return 1;
	}

	return 0;
}

static const luaL_Reg pfstatemeta[] = {
	{"__index", pfstateindex},
	{0, 0},
};

static int
pfstateslen(lua_State *L)
{
	struct pfioc_states *ps = luaL_checkudata(L, 1, PFSTATES_MT);
	size_t len = ps->ps_len;

	lua_pushinteger(L, len/(sizeof(ps->ps_states[0])));

	return 1;
}

static int
pfstatesindex(lua_State *L)
{
	struct pfioc_states *ps = luaL_checkudata(L, 1, PFSTATES_MT);
	struct pfsync_state *p = ps->ps_states;
	struct pfsync_state *s;
	int idx, worked;
	size_t n;

	idx = lua_tonumberx(L, 2, &worked);
	n = ps->ps_len / sizeof(ps->ps_states[0]);

	if(!worked || idx > n || idx < 1){
		lua_pushnil(L);
		return 1;
	}

	idx--;

	s = lua_newuserdata(L, sizeof(*s));
	luaL_setmetatable(L, PFSTATE_MT);

	*s = p[idx];

	return 1;
}

static int
pfstatesgc(lua_State *L)
{
	struct pfioc_states *ps = luaL_checkudata(L, 1, PFSTATES_MT);
	free(ps->ps_buf);
	return 0;
}

static const luaL_Reg pfstatesmeta[] = {
	{"__len", pfstateslen},
	{"__index", pfstatesindex},
	{"__gc", pfstatesgc},
	{0, 0},
};

void
luapf_states_register(lua_State *L)
{
	luaL_newmetatable(L, PFSTATES_MT);
	luaL_setfuncs(L, pfstatesmeta, 0);
	//lua_pushvalue(L, -1);
	//lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luaL_newmetatable(L, PFSTATE_MT);
	luaL_setfuncs(L, pfstatemeta, 0);
	lua_pop(L, 1);
}

