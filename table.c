#include <errno.h>
#include <string.h>
#include <err.h>

#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/queue.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "property.h"

#define DEBUG 1

struct luapftable {
	int luapfref;
	struct pfr_tstats stats;
	struct pfr_table *table;
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

	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name, sizeof(pt.pfrio_table.pfrt_name));

	if(ioctl(pf->fd, DIOCRGETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRGETADDRS: %s", strerror(errno));

	pt.pfrio_buffer = lua_newuserdata(L, sizeof(*pa) * pt.pfrio_size);
	memset(pt.pfrio_buffer, 0, sizeof(*pa) * pt.pfrio_size);

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
			// TODO: change to inet_net_ntop
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

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor, sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name, sizeof(pt.pfrio_table.pfrt_name));

	pt.pfrio_esize = sizeof(pa);
	pt.pfrio_buffer = &pa;
	pt.pfrio_size = 1;

	if(ioctl(pf->fd, DIOCRTSTADDRS, &pt) < 0)
		luaL_error(L, "DIOCRTSTADDRS: %s", strerror(errno));

	lua_pushboolean(L, pa.pfra_fback == PFR_FB_MATCH);

	return 1;
}

static int
pftableclear(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;

	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);
	pf = luaL_checkudata(L, -1, PF_MT);

	memset(&pt, 0, sizeof(pt));

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor, sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name, sizeof(pt.pfrio_table.pfrt_name));

	if(ioctl(pf->fd, DIOCRCLRADDRS, &pt) < 0)
		luaL_error(L, "DIOCRCLRADDRS: %s", strerror(errno));

	lua_pushinteger(L, pt.pfrio_ndel);

	return 1;
}

static void
strtoaddr(lua_State *L, const char *s, struct pfr_addr *a)
{
	int bits;

	memset(a, 0, sizeof(*a));

	if((bits = inet_net_pton(AF_INET6, s, &a->pfra_u, sizeof(a->pfra_u))) < 0){
		if((bits = inet_net_pton(AF_INET, s, &a->pfra_u, sizeof(a->pfra_u))) < 0)
			luaL_error(L, "inet_net_pton: %s", strerror(errno));
		a->pfra_af = AF_INET;
	} else {
		a->pfra_af = AF_INET6;
	}

	a->pfra_net = bits;
}

void
argstoaddrs(lua_State *L, struct pfioc_table *pt)
{
	const char *s;
	size_t len, i;
	struct pfr_addr *ap;

	pt->pfrio_esize = sizeof(struct pfr_addr);

	len = lua_rawlen(L, 2);

	if(lua_isstring(L, 2)){
		s = luaL_checkstring(L, 2);
		luaL_argcheck(L, (len < INET6_ADDRSTRLEN), 2, "address too long");

		ap = lua_newuserdata(L, sizeof(*ap));
		memset(ap, 0, sizeof(*ap));

		strtoaddr(L, s, ap);
		pt->pfrio_buffer = ap;
		pt->pfrio_size = 1;
	} else if(lua_istable(L, 2)){
		ap = lua_newuserdata(L, len * sizeof(*ap));
		memset(ap, 0, len * sizeof(*ap));
		for(i = 0; i < len; i++){
			lua_rawgeti(L, 2, i+1);
			luaL_argcheck(L, (lua_isstring(L, -1)), 2, "table element not a string");
			luaL_argcheck(L, (lua_rawlen(L, -1) < INET6_ADDRSTRLEN), 2, "address too long");
			s = lua_tostring(L, -1);
			strtoaddr(L, s, &ap[i]);
			lua_pop(L, 1);
		}

		pt->pfrio_buffer = ap;
		pt->pfrio_size = len;
	}
}

static int
pftableadd(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;

	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);
	pf = luaL_checkudata(L, -1, PF_MT);

	memset(&pt, 0, sizeof(pt));

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor, sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name, sizeof(pt.pfrio_table.pfrt_name));

	argstoaddrs(L, &pt);

	if(ioctl(pf->fd, DIOCRADDADDRS, &pt) < 0)
		luaL_error(L, "DIOCRADDADDRS: %s", strerror(errno));

	lua_pushinteger(L, pt.pfrio_nadd);

	return 1;
}

static int
pftabledelete(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;

	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);
	pf = luaL_checkudata(L, -1, PF_MT);

	memset(&pt, 0, sizeof(pt));

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor, sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name, sizeof(pt.pfrio_table.pfrt_name));

	argstoaddrs(L, &pt);

	if(ioctl(pf->fd, DIOCRDELADDRS, &pt) < 0)
		luaL_error(L, "DIOCRDELADDRS: %s", strerror(errno));

	lua_pushinteger(L, pt.pfrio_ndel);

	return 1;
}

struct ro_property_head table_properties;

ro_property_generate(table, anchor) {
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);
	lua_pushstring(L, lpft->table->pfrt_anchor);
	return 1;
}

ro_property_generate(table, name) {
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);
	lua_pushstring(L, lpft->table->pfrt_name);
	return 1;
}

#define table_flag(name, flg) \
	ro_property_generate(table, name) { \
		struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT); \
		lua_pushboolean(L, lpft->table->pfrt_flags & flg); \
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
pftablelen(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);

	lua_pushinteger(L, lpft->stats.pfrts_cnt);

	return 1;
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
	{"clear", pftableclear},
	{"add", pftableadd},
	{"delete", pftabledelete},
	{"__index", pftableindex},
	{"__pairs", pftablepairs},
	{"__len", pftablelen},
	{"__gc", pftablegc},
	{0, 0},
};

int
pftables(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_table pt;
	struct pfr_tstats *tables, *t;
	struct luapftable *lpft;
	int i, ii;

	memset(&pt, 0, sizeof(pt));

	pt.pfrio_esize = sizeof(struct pfr_tstats);

	if(ioctl(pf->fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	pt.pfrio_buffer = lua_newuserdata(L, sizeof(*t) * pt.pfrio_size);
	memset(pt.pfrio_buffer, 0, sizeof(*t) * pt.pfrio_size);

	if(ioctl(pf->fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	tables = pt.pfrio_buffer;

	lua_newtable(L);

	for(i = 0, ii = 1; i < pt.pfrio_size; i++){
		t = &tables[i];
		if((t->pfrts_t.pfrt_flags & PFR_TFLAG_ACTIVE) == 0)
			continue;

		lpft = lua_newuserdata(L, sizeof(*lpft));
		memset(lpft, 0, sizeof(*lpft));
		luaL_setmetatable(L, PFTABLE_MT);
		lua_pushvalue(L, 1);
		lpft->luapfref = luaL_ref(L, LUA_REGISTRYINDEX);
		memcpy(&lpft->stats, t, sizeof(lpft->stats));
		lpft->table = &lpft->stats.pfrts_t;
		lua_rawseti(L, -2, ii++);
	}

	return 1;
}

static void
strtotable(lua_State *L, const char *s, struct pfr_table *t)
{
	size_t len;
	char *ptr;
	char copy[sizeof(t->pfrt_anchor)+sizeof(t->pfrt_name)];

	if((len = strlcpy(copy, s, sizeof(copy))) >= sizeof(copy))
		luaL_error(L, "buffer size bug");

	ptr = strrchr(copy, '/');
	if(ptr){
		*ptr++ = '\0';
		if(strlcpy(t->pfrt_anchor, copy, sizeof(t->pfrt_anchor)) >= sizeof(t->pfrt_anchor))
			luaL_error(L, "buffer size bug");

		if(strlcpy(t->pfrt_name, ptr, sizeof(t->pfrt_name)) >= sizeof(t->pfrt_name))
			luaL_error(L, "buffer size bug");
	} else {
		if(len >= PF_TAG_NAME_SIZE)
			luaL_error(L, "table name too long");
		strlcpy(t->pfrt_name, s, sizeof(t->pfrt_name));
	}
}

int
pfgettable(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct luapftable *lpft;
	struct pfioc_table pt;
	struct pfr_tstats *tables, *t = NULL;
	int i;
	const char *s = luaL_checkstring(L, 2);

	memset(&pt, 0, sizeof(pt));
	memset(&t, 0, sizeof(t));

	// XXX: DIOCRGETTSTATS can't filter by table name, only anchor, so we have to ask the kernel for all tables in an anchor.
	// XXX: kernel ignores table pfrt_name here, this is just to filter anchor

	strtotable(L, s, &pt.pfrio_table);

	pt.pfrio_esize = sizeof(struct pfr_tstats);

	if(ioctl(pf->fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	pt.pfrio_buffer = lua_newuserdata(L, sizeof(*t) * pt.pfrio_size);
	memset(pt.pfrio_buffer, 0, sizeof(*t) * pt.pfrio_size);

	if(ioctl(pf->fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	tables = pt.pfrio_buffer;

	for(i = 0; i < pt.pfrio_size; i++){
		if(!strcmp(tables[i].pfrts_t.pfrt_anchor, pt.pfrio_table.pfrt_anchor) &&
			!strcmp(tables[i].pfrts_t.pfrt_name, pt.pfrio_table.pfrt_name)){
			t = &tables[i];
			break;
		}
	}

	if(!t){
		lua_pushnil(L);
		return 1;
	}

	lpft = lua_newuserdata(L, sizeof(*lpft));
	memset(lpft, 0, sizeof(*lpft));
	luaL_setmetatable(L, PFTABLE_MT);
	lua_pushvalue(L, 1);
	lpft->luapfref = luaL_ref(L, LUA_REGISTRYINDEX);
	memcpy(&lpft->stats, t, sizeof(lpft->stats));
	lpft->table = &lpft->stats.pfrts_t;

	return 1;
}

void
argstotables(lua_State *L, struct pfioc_table *pt)
{
	const char *s;
	size_t len, i;
	struct pfr_table *tp;

	pt->pfrio_esize = sizeof(struct pfr_table);

	len = lua_rawlen(L, 2);

	if(lua_isstring(L, 2)){
		s = luaL_checkstring(L, 2);
		luaL_argcheck(L, (len < PATH_MAX), 2, "table name too long");

		tp = lua_newuserdata(L, sizeof(*tp));
		memset(tp, 0, sizeof(*tp));

		strtotable(L, s, tp);
		pt->pfrio_buffer = tp;
		pt->pfrio_size = 1;
	} else if(lua_istable(L, 2)){
		tp = lua_newuserdata(L, len * sizeof(*tp));
		memset(tp, 0, len * sizeof(*tp));
		for(i = 0; i < len; i++){
			lua_rawgeti(L, 2, i+1);
			luaL_argcheck(L, (lua_isstring(L, -1)), 2, "table element not a string");
			luaL_argcheck(L, (lua_rawlen(L, -1) < PATH_MAX), 2, "table name too long");
			s = lua_tostring(L, -1);
			strtotable(L, s, &tp[i]);
			lua_pop(L, 1);
		}

		pt->pfrio_buffer = tp;
		pt->pfrio_size = len;
	}
}

static void
multitableop(lua_State *L, struct pfioc_table *pt, unsigned long op, const char *label)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	luaL_argcheck(L, (lua_istable(L, 2) || lua_isstring(L, 2)), 2, "expected table or string");

	argstotables(L, pt);

	if(ioctl(pf->fd, op, pt) < 0)
		luaL_error(L, "%s: %s", label, strerror(errno));
}

int
pfaddtables(lua_State *L)
{
	struct pfioc_table pt;

	memset(&pt, 0, sizeof(pt));
	multitableop(L, &pt, DIOCRADDTABLES, "DIOCRADDTABLES");
	lua_pushinteger(L, pt.pfrio_nadd);

	return 1;
}

int
pfcleartables(lua_State *L)
{
	struct pfioc_table pt;

	memset(&pt, 0, sizeof(pt));
	multitableop(L, &pt, DIOCRCLRTSTATS, "DIOCRCLRTSTATS");
	lua_pushinteger(L, pt.pfrio_nzero);

	return 1;
}

int
pfdeletetables(lua_State *L)
{
	struct pfioc_table pt;

	memset(&pt, 0, sizeof(pt));
	multitableop(L, &pt, DIOCRDELTABLES, "DIOCRDELTABLES");
	lua_pushinteger(L, pt.pfrio_ndel);

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

