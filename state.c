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
#include "property.h"

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

static struct ro_property_head state_properties;

ro_property_generate(state, id) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	lua_pushinteger(L, betoh64(s->id));
	return 1;
}

ro_property_generate(state, ifname) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	lua_pushstring(L, s->ifname);
	return 1;
}

ro_property_generate(state, proto) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	lua_pushstring(L, cacheprotoent(s->proto));
	return 1;
}

ro_property_generate(state, direction) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	lua_pushstring(L, s->direction == PF_IN ? "in" : "out");
	return 1;
}

ro_property_generate(state, rule) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	if(betoh32(s->rule) == (uint32_t)-1)
		lua_pushinteger(L, -1);
	else
		lua_pushinteger(L, betoh32(s->rule));
	return 1;
}

ro_property_generate(state, creation) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	lua_pushinteger(L, betoh32(s->creation));
	return 1;
}

ro_property_generate(state, expire) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	lua_pushinteger(L, betoh32(s->expire));
	return 1;
}

static void
gimmekey(lua_State *L, struct pfsync_state *s, int idx, struct pf_addr **raddr, uint16_t *rport, sa_family_t *raf)
{
	struct pfsync_state_key *key;

	// XXX
	if(s->key[PF_SK_STACK].af != s->key[PF_SK_WIRE].af)
		luaL_error(L, "what even is af-to");

	if(s->direction == PF_IN){
		key = &s->key[PF_SK_STACK];
		*raddr = &key->addr[idx];
		*rport = be16toh(key->port[idx]);
		*raf = key->af;
		return;
	} else if(s->direction == PF_OUT){
		key = &s->key[PF_SK_WIRE];
		*raddr = &key->addr[idx];
		*rport = be16toh(key->port[idx]);
		*raf = key->af;
		return;
	}

	luaL_error(L, "unhandled");
}

/* TODO: maybe source/dest should be a table, or expose rdomain via another
 * property */
ro_property_generate(state, source) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	struct pf_addr *a;
	uint16_t p;
	sa_family_t af;
	char addr[INET6_ADDRSTRLEN];

	gimmekey(L, s, s->direction == PF_OUT ? 1 : 0, &a, &p, &af);

	if(inet_ntop(af, &a->pfa, addr, sizeof(addr)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	switch(af){
	case AF_INET:
		lua_pushfstring(L, "%s:%d", addr, p);
		break;
	case AF_INET6:
		lua_pushfstring(L, "[%s]:%d", addr, p);
		break;
	default:
		abort();
	}

	return 1;
}

ro_property_generate(state, destination) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	struct pf_addr *a;
	uint16_t p;
	sa_family_t af;
	char addr[INET6_ADDRSTRLEN];

	gimmekey(L, s, s->direction == PF_OUT ? 0 : 1, &a, &p, &af);

	if(inet_ntop(af, &a->pfa, addr, sizeof(addr)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	switch(af){
	case AF_INET:
		lua_pushfstring(L, "%s:%d", addr, p);
		break;
	case AF_INET6:
		lua_pushfstring(L, "[%s]:%d", addr, p);
		break;
	default:
		abort();
	}

	return 1;
}

ro_property_generate(state, gateway) {
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	struct pfsync_state_key *stk;
	struct pf_addr *a;
	uint16_t p;
	sa_family_t af;
	char addr[INET6_ADDRSTRLEN];

	if(s->direction != PF_OUT){
		lua_pushnil(L);
		return 1;
	}

	stk = &s->key[PF_SK_STACK];

	a = &stk->addr[1];
	p = be16toh(stk->port[1]);
	af = stk->af;

	if(inet_ntop(af, &a->pfa, addr, sizeof(addr)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	switch(af){
	case AF_INET:
		lua_pushfstring(L, "%s:%d", addr, p);
		break;
	case AF_INET6:
		lua_pushfstring(L, "[%s]:%d", addr, p);
		break;
	default:
		abort();
	}

	return 1;
}

ro_property_generate(state, packets_in){
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->packets[0], d);
	lua_pushinteger(L, d);

	return 1;
}

ro_property_generate(state, packets_out){
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->packets[1], d);
	lua_pushinteger(L, d);

	return 1;
}

ro_property_generate(state, bytes_in){
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->bytes[0], d);
	lua_pushinteger(L, d);

	return 1;
}

ro_property_generate(state, bytes_out){
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);
	uint64_t d;

	pf_state_counter_ntoh(s->bytes[1], d);
	lua_pushinteger(L, d);

	return 1;
}

static void
state_properties_init(void)
{
	STAILQ_INIT(&state_properties);
	STAILQ_INSERT_TAIL(&state_properties, &state_id_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_ifname_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_proto_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_direction_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_rule_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_creation_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_expire_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_source_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_destination_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_gateway_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_packets_in_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_packets_out_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_bytes_in_property, link);
	STAILQ_INSERT_TAIL(&state_properties, &state_bytes_out_property, link);
}

static int
pfstateindex(lua_State *L)
{
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);

	(void) s;

	ro_property_lookup(L, &state_properties, 1, 2);
}

static int
pfstateaux(lua_State *L)
{
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);

	(void) s;

	ro_property_pairs(L, &state_properties, 1, 2);
}

static int
pfstatepairs(lua_State *L)
{
	struct pfsync_state *s = luaL_checkudata(L, 1, PFSTATE_MT);

	(void) s;

	lua_pushcfunction(L, pfstateaux);
	lua_pushvalue(L, 1);
	lua_pushnil(L);

	return 3;
}

static const luaL_Reg pfstatemeta[] = {
	{"__index", pfstateindex},
	{"__pairs", pfstatepairs},
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

	state_properties_init();
}

