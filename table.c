// TODO: add, delete, flush
#include <errno.h>
#include <string.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "property.h"

struct luapftable {
	int luapfref;
	struct pfr_table table;
};

static const luaL_Reg pftablemeta[];

static int
pftableaddresses(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;
	struct pfr_addr *pat, *pa;
	int hostnet;
	int i, ii;
	char addr[INET6_ADDRSTRLEN+4]; // for net

	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);
	pf = luaL_checkudata(L, -1, PF_MT);

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_esize = sizeof(*pa);

	strlcpy(pt.pfrio_table.pfrt_name, lpft->table.pfrt_name, sizeof(pt.pfrio_table.pfrt_name));

	if(ioctl(pf->fd, DIOCRGETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRGETADDRS: %s", strerror(errno));

	pt.pfrio_buffer = lua_newuserdata(L, sizeof(*pa) * pt.pfrio_size);

	if(ioctl(pf->fd, DIOCRGETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRGETTABLES: %s", strerror(errno));

	pat = pt.pfrio_buffer;

	lua_newtable(L);

	for(i = 0, ii = 1; i < pt.pfrio_size; i++){
		pa = &pat[i];

		switch(pa->pfra_af){
		case AF_INET:
			hostnet = 32;
			goto ntop;
		case AF_INET6:
			hostnet = 128;
ntop:
			if(inet_ntop(pa->pfra_af, &pa->pfra_u, addr, sizeof(addr)) == NULL)
				luaL_error(L, "inet_ntop: %s", strerror(errno));

			if(pa->pfra_net < hostnet)
				lua_pushfstring(L, "%s/%d", addr, pa->pfra_net);
			else
				lua_pushstring(L, addr);
			break;

		default:
			continue;
		}

		lua_rawseti(L, -2, ii++);
	}

	return 1;
	
}

static int
pftabletest(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;
	struct pfr_addr pa;
	int bits;
	const char *address = luaL_checkstring(L, 2);

	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);
	pf = luaL_checkudata(L, -1, PF_MT);

	memset(&pt, 0, sizeof(pt));
	memset(&pa, 0, sizeof(pa));

	bits = inet_net_pton(AF_INET6, address, &pa.pfra_u, sizeof(pa.pfra_u));
	if(bits > 0){
		pa.pfra_af = AF_INET6;
	} else {
		bits = inet_net_pton(AF_INET, address, &pa.pfra_u, sizeof(pa.pfra_u));
		if(bits < 0)
			luaL_error(L, "inet_net_pton: %s", strerror(errno));
		pa.pfra_af = AF_INET;
	}

	pa.pfra_net = bits;

	strlcpy(pt.pfrio_table.pfrt_name, lpft->table.pfrt_name, sizeof(pt.pfrio_table.pfrt_name));

	pt.pfrio_esize = sizeof(pa);
	pt.pfrio_buffer = &pa;
	pt.pfrio_size = 1;

	if(ioctl(pf->fd, DIOCRTSTADDRS, &pt) < 0)
		luaL_error(L, "DIOCRTSTADDRS: %s", strerror(errno));

	lua_pushboolean(L, pa.pfra_fback == PFR_FB_MATCH);

	return 1;
}

struct ro_property_head table_properties;

ro_property_generate(table, anchor) {
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);
	lua_pushstring(L, lpft->table.pfrt_anchor);
	return 1;
}

ro_property_generate(table, name) {
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);
	lua_pushstring(L, lpft->table.pfrt_name);
	return 1;
}

#define table_flag(name, flg) \
	ro_property_generate(table, name) { \
		struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT); \
		lua_pushboolean(L, lpft->table.pfrt_flags & flg); \
		return 1; \
	}

table_flag(persist, PFR_TFLAG_PERSIST)
table_flag(const, PFR_TFLAG_CONST)
table_flag(active, PFR_TFLAG_ACTIVE)
table_flag(inactive, PFR_TFLAG_INACTIVE)
table_flag(referenced, PFR_TFLAG_REFERENCED)
table_flag(refdanchor, PFR_TFLAG_REFDANCHOR)
table_flag(counters, PFR_TFLAG_COUNTERS)

static void
table_properties_init(void)
{
	STAILQ_INIT(&table_properties);
	STAILQ_INSERT_TAIL(&table_properties, &table_anchor_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_name_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_persist_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_const_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_active_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_inactive_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_referenced_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_refdanchor_property, link);
	STAILQ_INSERT_TAIL(&table_properties, &table_counters_property, link);
}

static int
pftableindex(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	const luaL_Reg *r;
	const char *k = luaL_checkstring(L, 2);

	(void) lpft;

	for(r = pftablemeta; r->name; r++){
		if(!strcmp(r->name, k)){
			lua_pushcfunction(L, r->func);
			return 1;
		}
	}

	ro_property_lookup(L, &table_properties, 1, 2);
}

static int
pftableaux(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	(void) lpft;

	ro_property_pairs(L, &table_properties, 1, 2);
}

static int
pftablepairs(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);

	(void) lpft;

	lua_pushcfunction(L, pftableaux);
	lua_pushvalue(L, 1);
	lua_pushnil(L);

	return 3;
}

static int
pftablegc(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);

	luaL_unref(L, LUA_REGISTRYINDEX, lpft->luapfref);
	return 0;
}

static const luaL_Reg pftablemeta[] = {
	{"addresses", pftableaddresses},
	{"test", pftabletest},
	{"__index", pftableindex},
	{"__pairs", pftablepairs},
	{"__gc", pftablegc},
	{0, 0},
};

int
pftables(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_table pt;
	struct pfr_table *tables, *t;
	struct luapftable *lpft;
	int i, ii;

	memset(&pt, 0, sizeof(pt));

	pt.pfrio_esize = sizeof(struct pfr_table);

	if(ioctl(pf->fd, DIOCRGETTABLES, &pt) < 0)
		luaL_error(L, "DIOCRGETTABLES: %s", strerror(errno));

	pt.pfrio_buffer = lua_newuserdata(L, sizeof(struct pfr_table) * pt.pfrio_size);

	if(ioctl(pf->fd, DIOCRGETTABLES, &pt) < 0)
		luaL_error(L, "DIOCRGETTABLES: %s", strerror(errno));

	tables = pt.pfrio_buffer;

	lua_newtable(L);

	for(i = 0, ii = 1; i < pt.pfrio_size; i++){
		t = &tables[i];
		if((t->pfrt_flags & PFR_TFLAG_ACTIVE) == 0)
			continue;

		lpft = lua_newuserdata(L, sizeof(*lpft));
		luaL_setmetatable(L, PFTABLE_MT);
		lua_pushvalue(L, 1);
		lpft->luapfref = luaL_ref(L, LUA_REGISTRYINDEX);
		memcpy(&lpft->table, &tables[i], sizeof(lpft->table));
		lua_rawseti(L, -2, ii++);
	}

	return 1;
}

void
luapf_tables_register(lua_State *L)
{
	luaL_newmetatable(L, PFTABLE_MT);
	luaL_setfuncs(L, pftablemeta, 0);
	lua_pop(L, 1);

	table_properties_init();
}

