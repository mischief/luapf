/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <limits.h>
#include <string.h>

#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "property.h"
#include "banned.h"

struct luapftable {
	int luapfref;
	struct pfr_tstats stats;
	struct pfr_table *table;
};

static int pftableindex(lua_State *L);
static int pftablepairs(lua_State *L);
static int pftablelen(lua_State *L);
static int pftablegc(lua_State *L);
static int pftableaddresses(lua_State *L);
static int pftabletest(lua_State *L);
static int pftableclear(lua_State *L);
static int pftableadd(lua_State *L);
static int pftabledelete(lua_State *L);
static int pftablerefresh(lua_State *L);
static int pftableaddrstats(lua_State *L);
static int pftablesetflags(lua_State *L);

/* Methods reachable as t:name(); __index searches this, then the properties. */
static const luaL_Reg pftablemethods[] = {
    {"addresses", pftableaddresses},
    {"test",      pftabletest     },
    {"clear",     pftableclear    },
    {"add",       pftableadd      },
    {"delete",    pftabledelete   },
    {"refresh",   pftablerefresh  },
    {"addrstats", pftableaddrstats},
    {"setflags",  pftablesetflags },
    {NULL,        NULL            },
};

static const luaL_Reg pftablemeta[] = {
    {"__index", pftableindex},
    {"__pairs", pftablepairs},
    {"__len",   pftablelen  },
    {"__gc",    pftablegc   },
    {NULL,      NULL        },
};

/* Copies the table name and anchor into an ioctl request. */
static void
settablename(struct pfioc_table *pt, const struct pfr_table *t)
{
	strlcpy(pt->pfrio_table.pfrt_anchor, t->pfrt_anchor,
	        sizeof(pt->pfrio_table.pfrt_anchor));
	strlcpy(pt->pfrio_table.pfrt_name, t->pfrt_name,
	        sizeof(pt->pfrio_table.pfrt_name));
}

/* Pushes "10.0.0.0/8", or "10.0.0.1" when the entry covers a single host. */
static void
pushaddr(lua_State *L, const struct pfr_addr *pa)
{
	char addr[INET6_ADDRSTRLEN];
	int hostnet;

	switch (pa->pfra_af) {
	case AF_INET:
		hostnet = 32;
		break;
	case AF_INET6:
		hostnet = 128;
		break;
	default:
		lua_pushnil(L);
		return;
	}

	/* TODO: change to inet_net_ntop */
	if (inet_ntop(pa->pfra_af, &pa->pfra_u, addr, sizeof(addr)) == NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	if (pa->pfra_net < hostnet)
		lua_pushfstring(L, "%s/%d", addr, pa->pfra_net);
	else
		lua_pushstring(L, addr);
}

static struct luapf *
tablepf(lua_State *L, const struct luapftable *lpft)
{
	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);

	return luaL_checkudata(L, -1, PF_MT);
}

static int
pftableaddresses(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf = tablepf(L, lpft);
	struct pfioc_table pt;
	const struct pfr_addr *pat;
	int n = 1;

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_esize = sizeof(struct pfr_addr);
	settablename(&pt, lpft->table);

	if (ioctl(pf->fd, DIOCRGETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRGETADDRS: %s", strerror(errno));

	pt.pfrio_buffer =
	    lua_newuserdata(L, sizeof(struct pfr_addr) * (size_t)pt.pfrio_size);
	memset(pt.pfrio_buffer, 0,
	       sizeof(struct pfr_addr) * (size_t)pt.pfrio_size);

	if (ioctl(pf->fd, DIOCRGETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRGETADDRS: %s", strerror(errno));

	pat = pt.pfrio_buffer;

	lua_newtable(L);

	for (int i = 0; i < pt.pfrio_size; i++) {
		pushaddr(L, &pat[i]);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			continue;
		}
		lua_rawseti(L, -2, n++);
	}

	return 1;
}

static uint64_t
addrsum(const uint64_t v[PFR_OP_ADDR_MAX])
{
	uint64_t sum = 0;

	for (int op = 0; op < PFR_OP_ADDR_MAX; op++)
		sum += v[op];

	return sum;
}

/*
 * Per-address counters. The kernel only keeps these while the table carries
 * the counters flag, which t:setflags{counters = true} turns on.
 */
static int
pftableaddrstats(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf = tablepf(L, lpft);
	struct pfioc_table pt;
	const struct pfr_astats *as;
	int n = 1;

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_esize = sizeof(struct pfr_astats);
	settablename(&pt, lpft->table);

	if (ioctl(pf->fd, DIOCRGETASTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETASTATS: %s", strerror(errno));

	pt.pfrio_buffer = lua_newuserdata(L, sizeof(struct pfr_astats) *
	                                         (size_t)pt.pfrio_size);
	memset(pt.pfrio_buffer, 0,
	       sizeof(struct pfr_astats) * (size_t)pt.pfrio_size);

	if (ioctl(pf->fd, DIOCRGETASTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETASTATS: %s", strerror(errno));

	as = pt.pfrio_buffer;

	lua_newtable(L);

	for (int i = 0; i < pt.pfrio_size; i++) {
		const struct pfr_astats *a = &as[i];

		pushaddr(L, &a->pfras_a);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			continue;
		}

		lua_newtable(L);
		lua_insert(L, -2);
		lua_setfield(L, -2, "address");

		lua_pushinteger(
		    L, (lua_Integer)addrsum(a->pfras_packets[PFR_DIR_IN]));
		lua_setfield(L, -2, "packets_in");
		lua_pushinteger(
		    L, (lua_Integer)addrsum(a->pfras_packets[PFR_DIR_OUT]));
		lua_setfield(L, -2, "packets_out");
		lua_pushinteger(
		    L, (lua_Integer)addrsum(a->pfras_bytes[PFR_DIR_IN]));
		lua_setfield(L, -2, "bytes_in");
		lua_pushinteger(
		    L, (lua_Integer)addrsum(a->pfras_bytes[PFR_DIR_OUT]));
		lua_setfield(L, -2, "bytes_out");
		lua_pushinteger(L, (lua_Integer)a->pfras_tzero);
		lua_setfield(L, -2, "cleared");

		lua_rawseti(L, -2, n++);
	}

	return 1;
}

/* Reads one optional boolean field, folding it into the set or clear mask. */
static void
flagfield(lua_State *L, int idx, const char *name, int flag, int *set, int *clr)
{
	if (lua_getfield(L, idx, name) != LUA_TNIL) {
		if (lua_toboolean(L, -1))
			*set |= flag;
		else
			*clr |= flag;
	}

	lua_pop(L, 1);
}

/*
 * Sets or clears persist, const and counters; a nil field is left alone.
 * The kernel drops a table that ends up neither persistent nor referenced.
 */
static int
pftablesetflags(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;
	struct pfr_table *tp;
	int set = 0;
	int clr = 0;

	luaL_checktype(L, 2, LUA_TTABLE);

	flagfield(L, 2, "persist", PFR_TFLAG_PERSIST, &set, &clr);
	flagfield(L, 2, "const", PFR_TFLAG_CONST, &set, &clr);
	flagfield(L, 2, "counters", PFR_TFLAG_COUNTERS, &set, &clr);

	pf = tablepf(L, lpft);

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_esize = sizeof(*tp);
	pt.pfrio_size = 1;
	pt.pfrio_setflag = set;
	pt.pfrio_clrflag = clr;

	/* The kernel rejects a request that carries any flags of its own. */
	tp = lua_newuserdata(L, sizeof(*tp));
	memset(tp, 0, sizeof(*tp));
	strlcpy(tp->pfrt_anchor, lpft->table->pfrt_anchor,
	        sizeof(tp->pfrt_anchor));
	strlcpy(tp->pfrt_name, lpft->table->pfrt_name, sizeof(tp->pfrt_name));
	pt.pfrio_buffer = tp;

	if (ioctl(pf->fd, DIOCRSETTFLAGS, &pt) < 0)
		luaL_error(L, "DIOCRSETTFLAGS: %s", strerror(errno));

	lua_pushinteger(L, (lua_Integer)pt.pfrio_nchange);

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
	if (bits > 0) {
		pa.pfra_af = AF_INET6;
	} else {
		bits = inet_net_pton(AF_INET, address, &pa.pfra_u,
		                     sizeof(pa.pfra_u));
		if (bits < 0)
			luaL_error(L, "inet_net_pton: %s", strerror(errno));
		pa.pfra_af = AF_INET;
	}

	pa.pfra_net = bits;

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor,
	        sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name,
	        sizeof(pt.pfrio_table.pfrt_name));

	pt.pfrio_esize = sizeof(pa);
	pt.pfrio_buffer = &pa;
	pt.pfrio_size = 1;

	if (ioctl(pf->fd, DIOCRTSTADDRS, &pt) < 0)
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

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor,
	        sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name,
	        sizeof(pt.pfrio_table.pfrt_name));

	if (ioctl(pf->fd, DIOCRCLRADDRS, &pt) < 0)
		luaL_error(L, "DIOCRCLRADDRS: %s", strerror(errno));

	lua_pushinteger(L, pt.pfrio_ndel);

	return 1;
}

static void
strtoaddr(lua_State *L, const char *s, struct pfr_addr *a)
{
	int bits;

	memset(a, 0, sizeof(*a));

	if ((bits = inet_net_pton(AF_INET6, s, &a->pfra_u, sizeof(a->pfra_u))) <
	    0) {
		if ((bits = inet_net_pton(AF_INET, s, &a->pfra_u,
		                          sizeof(a->pfra_u))) < 0)
			luaL_error(L, "inet_net_pton: %s", strerror(errno));
		a->pfra_af = AF_INET;
	} else {
		a->pfra_af = AF_INET6;
	}

	a->pfra_net = bits;
}

static void
argstoaddrs(lua_State *L, struct pfioc_table *pt)
{
	const char *s;
	size_t len, i;
	struct pfr_addr *ap;

	pt->pfrio_esize = sizeof(struct pfr_addr);

	len = lua_rawlen(L, 2);

	if (lua_isstring(L, 2)) {
		s = luaL_checkstring(L, 2);
		luaL_argcheck(L, (len < INET6_ADDRSTRLEN), 2,
		              "address too long");

		ap = lua_newuserdata(L, sizeof(*ap));
		memset(ap, 0, sizeof(*ap));

		strtoaddr(L, s, ap);
		pt->pfrio_buffer = ap;
		pt->pfrio_size = 1;
	} else if (lua_istable(L, 2)) {
		ap = lua_newuserdata(L, len * sizeof(*ap));
		memset(ap, 0, len * sizeof(*ap));
		for (i = 0; i < len; i++) {
			lua_rawgeti(L, 2, (lua_Integer)(i + 1));
			luaL_argcheck(L, (lua_isstring(L, -1)), 2,
			              "table element not a string");
			luaL_argcheck(L, (lua_rawlen(L, -1) < INET6_ADDRSTRLEN),
			              2, "address too long");
			s = lua_tostring(L, -1);
			strtoaddr(L, s, &ap[i]);
			lua_pop(L, 1);
		}

		pt->pfrio_buffer = ap;
		pt->pfrio_size = (int)len;
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

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor,
	        sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name,
	        sizeof(pt.pfrio_table.pfrt_name));

	argstoaddrs(L, &pt);

	if (ioctl(pf->fd, DIOCRADDADDRS, &pt) < 0)
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

	strlcpy(pt.pfrio_table.pfrt_anchor, lpft->table->pfrt_anchor,
	        sizeof(pt.pfrio_table.pfrt_anchor));
	strlcpy(pt.pfrio_table.pfrt_name, lpft->table->pfrt_name,
	        sizeof(pt.pfrio_table.pfrt_name));

	argstoaddrs(L, &pt);

	if (ioctl(pf->fd, DIOCRDELADDRS, &pt) < 0)
		luaL_error(L, "DIOCRDELADDRS: %s", strerror(errno));

	lua_pushinteger(L, pt.pfrio_ndel);

	return 1;
}

static int
table_anchor(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushstring(L, lpft->table->pfrt_anchor);

	return 1;
}

static int
table_name(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushstring(L, lpft->table->pfrt_name);

	return 1;
}

static int
tableflag(lua_State *L, int idx, unsigned flag)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushboolean(L, (lpft->table->pfrt_flags & flag) != 0);

	return 1;
}

static int
table_persist(lua_State *L, int idx)
{
	return tableflag(L, idx, PFR_TFLAG_PERSIST);
}

static int
table_const(lua_State *L, int idx)
{
	return tableflag(L, idx, PFR_TFLAG_CONST);
}

static int
table_active(lua_State *L, int idx)
{
	return tableflag(L, idx, PFR_TFLAG_ACTIVE);
}

static int
table_inactive(lua_State *L, int idx)
{
	return tableflag(L, idx, PFR_TFLAG_INACTIVE);
}

static int
table_referenced(lua_State *L, int idx)
{
	return tableflag(L, idx, PFR_TFLAG_REFERENCED);
}

static int
table_refdanchor(lua_State *L, int idx)
{
	return tableflag(L, idx, PFR_TFLAG_REFDANCHOR);
}

static int
table_counters(lua_State *L, int idx)
{
	return tableflag(L, idx, PFR_TFLAG_COUNTERS);
}

/* Packet and byte counters sum every match type, as pfctl -vsT prints them. */
static uint64_t
tablesum(const struct luapftable *lpft, int dir, int bytes)
{
	const uint64_t *v = bytes ? lpft->stats.pfrts_bytes[dir]
	                          : lpft->stats.pfrts_packets[dir];
	uint64_t sum = 0;

	for (int op = 0; op < PFR_OP_TABLE_MAX; op++)
		sum += v[op];

	return sum;
}

static int
table_packets_in(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)tablesum(lpft, PFR_DIR_IN, 0));

	return 1;
}

static int
table_packets_out(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)tablesum(lpft, PFR_DIR_OUT, 0));

	return 1;
}

static int
table_bytes_in(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)tablesum(lpft, PFR_DIR_IN, 1));

	return 1;
}

static int
table_bytes_out(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)tablesum(lpft, PFR_DIR_OUT, 1));

	return 1;
}

static int
table_match(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)lpft->stats.pfrts_match);

	return 1;
}

static int
table_nomatch(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)lpft->stats.pfrts_nomatch);

	return 1;
}

static int
table_addresses_count(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)lpft->stats.pfrts_cnt);

	return 1;
}

static int
table_cleared(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)lpft->stats.pfrts_tzero);

	return 1;
}

static int
table_refcnt_rule(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(L,
	                (lua_Integer)lpft->stats.pfrts_refcnt[PFR_REFCNT_RULE]);

	return 1;
}

static int
table_refcnt_anchor(lua_State *L, int idx)
{
	struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT);

	lua_pushinteger(
	    L, (lua_Integer)lpft->stats.pfrts_refcnt[PFR_REFCNT_ANCHOR]);

	return 1;
}

static const struct ro_property table_properties[] = {
    {"anchor",          table_anchor         },
    {"name",            table_name           },
    {"persist",         table_persist        },
    {"const",           table_const          },
    {"active",          table_active         },
    {"inactive",        table_inactive       },
    {"referenced",      table_referenced     },
    {"refdanchor",      table_refdanchor     },
    {"counters",        table_counters       },
    {"addresses_count", table_addresses_count},
    {"match",           table_match          },
    {"nomatch",         table_nomatch        },
    {"packets_in",      table_packets_in     },
    {"packets_out",     table_packets_out    },
    {"bytes_in",        table_bytes_in       },
    {"bytes_out",       table_bytes_out      },
    {"cleared",         table_cleared        },
    {"refcnt_rule",     table_refcnt_rule    },
    {"refcnt_anchor",   table_refcnt_anchor  },
    {NULL,              NULL                 },
};

static int
pftableindex(lua_State *L)
{
	const char *k = luaL_checkstring(L, 2);

	(void)luaL_checkudata(L, 1, PFTABLE_MT);

	for (const luaL_Reg *r = pftablemethods; r->name != NULL; r++) {
		if (strcmp(r->name, k) == 0) {
			lua_pushcfunction(L, r->func);
			return 1;
		}
	}

	return ro_property_lookup(L, table_properties, 1, 2);
}

static int
pftableaux(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFTABLE_MT);

	return ro_property_next(L, table_properties, 1, 2);
}

static int
pftablepairs(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFTABLE_MT);

	lua_pushcfunction(L, pftableaux);
	lua_pushvalue(L, 1);
	lua_pushnil(L);

	return 3;
}

static int
pftablelen(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);

	lua_pushinteger(L, (lua_Integer)lpft->stats.pfrts_cnt);

	return 1;
}

static int
pftablegc(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);

	luaL_unref(L, LUA_REGISTRYINDEX, lpft->luapfref);
	return 0;
}

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

	if (ioctl(pf->fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	pt.pfrio_buffer =
	    lua_newuserdata(L, sizeof(*t) * (size_t)pt.pfrio_size);
	memset(pt.pfrio_buffer, 0, sizeof(*t) * (size_t)pt.pfrio_size);

	if (ioctl(pf->fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	tables = pt.pfrio_buffer;

	lua_newtable(L);

	for (i = 0, ii = 1; i < pt.pfrio_size; i++) {
		t = &tables[i];
		if ((t->pfrts_t.pfrt_flags & PFR_TFLAG_ACTIVE) == 0)
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
	char copy[sizeof(t->pfrt_anchor) + sizeof(t->pfrt_name)];

	if ((len = strlcpy(copy, s, sizeof(copy))) >= sizeof(copy))
		luaL_error(L, "buffer size bug");

	ptr = strrchr(copy, '/');
	if (ptr) {
		*ptr++ = '\0';
		if (strlcpy(t->pfrt_anchor, copy, sizeof(t->pfrt_anchor)) >=
		    sizeof(t->pfrt_anchor))
			luaL_error(L, "buffer size bug");

		if (strlcpy(t->pfrt_name, ptr, sizeof(t->pfrt_name)) >=
		    sizeof(t->pfrt_name))
			luaL_error(L, "buffer size bug");
	} else {
		if (len >= PF_TAG_NAME_SIZE)
			luaL_error(L, "table name too long");
		strlcpy(t->pfrt_name, s, sizeof(t->pfrt_name));
	}
}

/*
 * DIOCRGETTSTATS filters by anchor only, so ask for every table in the anchor
 * and pick out the one named. The buffer is a lua userdata left on the stack.
 */
static const struct pfr_tstats *
findtstats(lua_State *L, int fd, const struct pfr_table *want)
{
	struct pfioc_table pt;
	const struct pfr_tstats *tables;

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_table = *want;
	pt.pfrio_esize = sizeof(struct pfr_tstats);

	if (ioctl(fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	pt.pfrio_buffer = lua_newuserdata(L, sizeof(struct pfr_tstats) *
	                                         (size_t)pt.pfrio_size);
	memset(pt.pfrio_buffer, 0,
	       sizeof(struct pfr_tstats) * (size_t)pt.pfrio_size);

	if (ioctl(fd, DIOCRGETTSTATS, &pt) < 0)
		luaL_error(L, "DIOCRGETTSTATS: %s", strerror(errno));

	tables = pt.pfrio_buffer;

	for (int i = 0; i < pt.pfrio_size; i++) {
		if (strcmp(tables[i].pfrts_t.pfrt_anchor, want->pfrt_anchor) ==
		        0 &&
		    strcmp(tables[i].pfrts_t.pfrt_name, want->pfrt_name) == 0)
			return &tables[i];
	}

	return NULL;
}

int
pfgettable(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct luapftable *lpft;
	struct pfr_table want;
	const struct pfr_tstats *t;
	const char *s = luaL_checkstring(L, 2);

	memset(&want, 0, sizeof(want));
	strtotable(L, s, &want);

	t = findtstats(L, pf->fd, &want);
	if (t == NULL) {
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

/* Re-read the counters of an existing table object in place. */
static int
pftablerefresh(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	const struct pfr_tstats *t;
	struct pfr_table want = *lpft->table;

	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);
	pf = luaL_checkudata(L, -1, PF_MT);

	t = findtstats(L, pf->fd, &want);
	if (t == NULL)
		luaL_error(L, "table %s no longer exists", want.pfrt_name);

	memcpy(&lpft->stats, t, sizeof(lpft->stats));
	lpft->table = &lpft->stats.pfrts_t;

	lua_pushvalue(L, 1);

	return 1;
}

static void
argstotables(lua_State *L, struct pfioc_table *pt)
{
	const char *s;
	size_t len, i;
	struct pfr_table *tp;

	pt->pfrio_esize = sizeof(struct pfr_table);

	len = lua_rawlen(L, 2);

	if (lua_isstring(L, 2)) {
		s = luaL_checkstring(L, 2);
		luaL_argcheck(L, (len < PATH_MAX), 2, "table name too long");

		tp = lua_newuserdata(L, sizeof(*tp));
		memset(tp, 0, sizeof(*tp));

		strtotable(L, s, tp);
		pt->pfrio_buffer = tp;
		pt->pfrio_size = 1;
	} else if (lua_istable(L, 2)) {
		tp = lua_newuserdata(L, len * sizeof(*tp));
		memset(tp, 0, len * sizeof(*tp));
		for (i = 0; i < len; i++) {
			lua_rawgeti(L, 2, (lua_Integer)(i + 1));
			luaL_argcheck(L, (lua_isstring(L, -1)), 2,
			              "table element not a string");
			luaL_argcheck(L, (lua_rawlen(L, -1) < PATH_MAX), 2,
			              "table name too long");
			s = lua_tostring(L, -1);
			strtotable(L, s, &tp[i]);
			lua_pop(L, 1);
		}

		pt->pfrio_buffer = tp;
		pt->pfrio_size = (int)len;
	}
}

static void
multitableop(lua_State *L, struct pfioc_table *pt, unsigned long op,
             const char *label)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	luaL_argcheck(L, (lua_istable(L, 2) || lua_isstring(L, 2)), 2,
	              "expected table or string");

	argstotables(L, pt);

	if (ioctl(pf->fd, op, pt) < 0)
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
}
