/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
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

/***
@module pf
*/

struct luapftable {
	int luapfref;
	struct pfr_tstats stats;
	struct pfr_table *table;
};

static int pftableindex(lua_State *L);
static int pftablepairs(lua_State *L);
static int pftabletostring(lua_State *L);
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
static int pftablereplace(lua_State *L);
static int pftableclearaddrstats(lua_State *L);
static int pftableentries(lua_State *L);
static void argstoaddrs(lua_State *L, struct pfioc_table *pt);

/* Methods reachable as t:name(); __index searches this, then the properties. */
static const luaL_Reg pftablemethods[] = {
    {"addresses",      pftableaddresses     },
    {"entries",        pftableentries       },
    {"test",           pftabletest          },
    {"clear",          pftableclear         },
    {"add",            pftableadd           },
    {"delete",         pftabledelete        },
    {"refresh",        pftablerefresh       },
    {"addrstats",      pftableaddrstats     },
    {"setflags",       pftablesetflags      },
    {"replace",        pftablereplace       },
    {"clearaddrstats", pftableclearaddrstats},
    {NULL,             NULL                 },
};

static const luaL_Reg pftablemeta[] = {
    {"__index",    pftableindex   },
    {"__pairs",    pftablepairs   },
    {"__len",      pftablelen     },
    {"__tostring", pftabletostring},
    {"__gc",       pftablegc      },
    {NULL,         NULL           },
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

/* Address families are spelled the way rule.c spells them. */
static const char *
afname(uint8_t af)
{
	if (af == AF_INET)
		return "inet";

	return af == AF_INET6 ? "inet6" : "unknown";
}

/* pfctl prints one letter per feedback code; lua gets the whole word. */
static const char *const fbacknames[PFR_FB_MAX] = {
    "none",    "match",     "added",    "deleted",  "changed",
    "cleared", "duplicate", "notmatch", "conflict", "nocount",
};

static const char *
fbackname(uint8_t fb)
{
	return fb < PFR_FB_MAX ? fbacknames[fb] : "unknown";
}

static const char *const entrytypenames[PFRKE_MAX] = {"plain", "route", "cost"};

static const char *
entrytypename(uint8_t type)
{
	return type < PFRKE_MAX ? entrytypenames[type] : "unknown";
}

/*
 * Pushes one lua table holding every field of a pfr_addr. negated is
 * pfra_not: without it a "!" entry is indistinguishable from an ordinary
 * one. fback is how the kernel answered a request about this entry, and
 * its nocount value means the entry has no counter block at all, which is
 * not the same as counters that read zero. Pushes nil for an address
 * family this binding cannot print.
 */
static void
pushentry(lua_State *L, const struct pfr_addr *pa)
{
	pushaddr(L, pa);
	if (lua_isnil(L, -1))
		return;

	lua_newtable(L);
	lua_insert(L, -2);
	lua_setfield(L, -2, "address");

	lua_pushboolean(L, pa->pfra_not != 0);
	lua_setfield(L, -2, "negated");
	lua_pushlstring(L, pa->pfra_ifname,
	                strnlen(pa->pfra_ifname, sizeof(pa->pfra_ifname)));
	lua_setfield(L, -2, "ifname");
	lua_pushinteger(L, (lua_Integer)pa->pfra_states);
	lua_setfield(L, -2, "states");
	lua_pushinteger(L, (lua_Integer)pa->pfra_weight);
	lua_setfield(L, -2, "weight");
	lua_pushstring(L, entrytypename(pa->pfra_type));
	lua_setfield(L, -2, "type");
	lua_pushstring(L, afname(pa->pfra_af));
	lua_setfield(L, -2, "af");
	lua_pushstring(L, fbackname(pa->pfra_fback));
	lua_setfield(L, -2, "fback");
}

/* Pushes an array of entry tables, skipping what pushentry cannot print. */
static void
pushentries(lua_State *L, const struct pfr_addr *pa, int size)
{
	int n = 1;

	lua_newtable(L);

	for (int i = 0; i < size; i++) {
		pushentry(L, &pa[i]);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			continue;
		}
		lua_rawseti(L, -2, n++);
	}
}

static const char *const opnames[] = {"block", "match", "pass", "xpass"};

/*
 * Sets packets_<dir>_<op> and bytes_<dir>_<op> on the lua table on top.
 * A table keeps four ops and an address three, so nops says which.
 */
static void
setopcounters(lua_State *L, const char *dir, const uint64_t *packets,
              const uint64_t *bytes, int nops)
{
	char name[32];

	for (int op = 0; op < nops; op++) {
		snprintf(name, sizeof(name), "packets_%s_%s", dir, opnames[op]);
		lua_pushinteger(L, (lua_Integer)packets[op]);
		lua_setfield(L, -2, name);

		snprintf(name, sizeof(name), "bytes_%s_%s", dir, opnames[op]);
		lua_pushinteger(L, (lua_Integer)bytes[op]);
		lua_setfield(L, -2, name);
	}
}

/* Reads one optional boolean out of an option table, or returns def. */
static int
optbool(lua_State *L, int idx, const char *name, int def)
{
	int v = def;

	if (lua_isnoneornil(L, idx))
		return def;

	luaL_checktype(L, idx, LUA_TTABLE);

	if (lua_getfield(L, idx, name) != LUA_TNIL)
		v = lua_toboolean(L, -1);

	lua_pop(L, 1);

	return v;
}

/* PFR_FLAG_DUMMY asks the kernel to report what it would do, and stop. */
static int
dummyflag(lua_State *L, int idx)
{
	return optbool(L, idx, "dummy", 0) ? PFR_FLAG_DUMMY : 0;
}

static struct luapf *
tablepf(lua_State *L, const struct luapftable *lpft)
{
	lua_rawgeti(L, LUA_REGISTRYINDEX, lpft->luapfref);

	return luaL_checkudata(L, -1, PF_MT);
}

/*
 * Reads every address of a table into a lua userdata buffer, which is
 * left on the stack and returned, and reports how many there are. The
 * first ioctl only fills in the count. The request lives here rather than
 * in the caller: struct pfioc_table carries a whole anchor path, so two
 * of them in one frame overrun the frame size limit this build sets.
 */
static struct pfr_addr *
readaddrs(lua_State *L, const struct luapf *pf, const struct pfr_table *t,
          int *size)
{
	struct pfioc_table pt;

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_esize = sizeof(struct pfr_addr);
	settablename(&pt, t);

	if (ioctl(pf->fd, DIOCRGETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRGETADDRS: %s", strerror(errno));

	pt.pfrio_buffer =
	    lua_newuserdata(L, sizeof(struct pfr_addr) * (size_t)pt.pfrio_size);
	memset(pt.pfrio_buffer, 0,
	       sizeof(struct pfr_addr) * (size_t)pt.pfrio_size);

	if (ioctl(pf->fd, DIOCRGETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRGETADDRS: %s", strerror(errno));

	*size = pt.pfrio_size;

	return pt.pfrio_buffer;
}

/***
List the addresses of a table.

This is the short form; entries returns the same list with every field
the kernel keeps beside the address.
@function table:addresses
@treturn table array of strings, a bare address or address/prefix
@raise if the ioctl fails
*/
static int
pftableaddresses(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf = tablepf(L, lpft);
	const struct pfr_addr *pat;
	int size;
	int n = 1;

	pat = readaddrs(L, pf, lpft->table, &size);

	lua_newtable(L);

	for (int i = 0; i < size; i++) {
		pushaddr(L, &pat[i]);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			continue;
		}
		lua_rawseti(L, -2, n++);
	}

	return 1;
}

/***
List the addresses of a table with every field of each entry.

Each entry holds address, negated, ifname, states, weight, type, af and
fback. negated is the `!` of pf.conf, ifname is what pfctl prints as
`@ifname`, and type is one of plain, route and cost.
@function table:entries
@treturn table array of entry tables
@raise if the ioctl fails
@usage for _, e in ipairs(t:entries()) do print(e.address, e.negated) end
*/
static int
pftableentries(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf = tablepf(L, lpft);
	const struct pfr_addr *pat;
	int size;

	pat = readaddrs(L, pf, lpft->table, &size);
	pushentries(L, pat, size);

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

/***
Read the per-address counters of a table.

The kernel only keeps these while the table carries the counters flag,
which setflags turns on. An entry whose fback is nocount has no counter
block at all, which is not the same as counters that read zero.

Each entry holds every field entries returns, plus cleared, the summed
packets_in, packets_out, bytes_in and bytes_out, and one pair of
packets_<dir>_<op> and bytes_<dir>_<op> for each of the three ops the
kernel keeps per address: block, match and pass. The sums add those
three, while a table object sums four, so an address total and its
table's total only agree while the table's xpass counters are zero.
@function table:addrstats
@treturn table array of counter tables
@raise if the ioctl fails
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

		pushentry(L, &a->pfras_a);
		if (lua_isnil(L, -1)) {
			lua_pop(L, 1);
			continue;
		}

		setopcounters(L, "in", a->pfras_packets[PFR_DIR_IN],
		              a->pfras_bytes[PFR_DIR_IN], PFR_OP_ADDR_MAX);
		setopcounters(L, "out", a->pfras_packets[PFR_DIR_OUT],
		              a->pfras_bytes[PFR_DIR_OUT], PFR_OP_ADDR_MAX);

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

/***
Replace the whole content of a table in one step.
@function table:replace
@param addresses a string, or an array of strings
@tparam[opt] table opts dummy asks what the call would do and changes
nothing
@treturn int added
@treturn int deleted
@treturn int changed
@raise if an address cannot be parsed
*/
static int
pftablereplace(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;
	int flags = dummyflag(L, 3);

	pf = tablepf(L, lpft);

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_flags = flags;
	settablename(&pt, lpft->table);

	argstoaddrs(L, &pt);

	if (ioctl(pf->fd, DIOCRSETADDRS, &pt) < 0)
		luaL_error(L, "DIOCRSETADDRS: %s", strerror(errno));

	lua_pushinteger(L, (lua_Integer)pt.pfrio_nadd);
	lua_pushinteger(L, (lua_Integer)pt.pfrio_ndel);
	lua_pushinteger(L, (lua_Integer)pt.pfrio_nchange);

	return 3;
}

/***
Zero the per-address counters, leaving the addresses in place.

With no argument every address of the table is zeroed. Naming addresses
zeroes only those, as `pfctl -T zero address ...` does.
@function table:clearaddrstats
@param[opt] addresses a string, or an array of strings
@treturn int addresses zeroed
@raise if the ioctl fails
*/
static int
pftableclearaddrstats(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;
	int named = !lua_isnoneornil(L, 2);

	pf = tablepf(L, lpft);

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_esize = sizeof(struct pfr_addr);
	settablename(&pt, lpft->table);

	if (named) {
		argstoaddrs(L, &pt);
	} else {
		/*
		 * The kernel zeroes only the addresses the request names, so
		 * an empty buffer zeroes nothing at all. Read the table's own
		 * addresses back and name every one of them.
		 */
		pt.pfrio_buffer = readaddrs(L, pf, lpft->table, &pt.pfrio_size);
	}

	if (ioctl(pf->fd, DIOCRCLRASTATS, &pt) < 0)
		luaL_error(L, "DIOCRCLRASTATS: %s", strerror(errno));

	lua_pushinteger(L, (lua_Integer)pt.pfrio_nzero);

	return 1;
}

/***
Set or clear the persist, const and counters flags.

A nil field is left alone. The kernel drops a table that ends up neither
persistent nor referenced by a rule, so set persist alongside counters on
a table lua created itself.
@function table:setflags
@tparam table flags any of persist, const and counters
@treturn int tables changed
@raise if the ioctl fails
@usage t:setflags({ counters = true, persist = true })
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

/***
Test whether a table matches an address.
@function table:test
@string address
@treturn bool
@raise if the address cannot be parsed
*/
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

/***
Remove every address from a table.
@function table:clear
@treturn int addresses removed
@raise if the ioctl fails
*/
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

	/*
	 * lua_isstring is also true of a number, and a number reaching
	 * inet_net_pton turns 1 into 1.0.0.0/8, so insist on a string.
	 */
	luaL_argcheck(L, (lua_istable(L, 2) || lua_type(L, 2) == LUA_TSTRING),
	              2, "expected table or string");

	len = lua_rawlen(L, 2);

	if (lua_type(L, 2) == LUA_TSTRING) {
		s = luaL_checkstring(L, 2);
		luaL_argcheck(L, (len < INET6_ADDRSTRLEN), 2,
		              "address too long");

		ap = lua_newuserdata(L, sizeof(*ap));
		memset(ap, 0, sizeof(*ap));

		strtoaddr(L, s, ap);
		pt->pfrio_buffer = ap;
		pt->pfrio_size = 1;
	} else {
		/* pfrio_size is an int, so a longer array would truncate. */
		luaL_argcheck(L, (len <= (size_t)INT_MAX), 2,
		              "too many addresses");

		ap = lua_newuserdata(L, len * sizeof(*ap));
		memset(ap, 0, len * sizeof(*ap));
		for (i = 0; i < len; i++) {
			lua_rawgeti(L, 2, (lua_Integer)(i + 1));
			luaL_argcheck(L, (lua_type(L, -1) == LUA_TSTRING), 2,
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

/***
Add addresses to a table.

opts takes dummy, which asks what the call would do and changes nothing,
and feedback, which adds a second return value: one entry table per
address given, whose fback says what happened to that address. The kernel
does not answer in the order asked, so read the result by address.
@function table:add
@param addresses a string, or an array of strings
@tparam[opt] table opts dummy and feedback
@treturn int addresses added
@treturn ?table per-address results, when feedback is asked for
@raise if an address cannot be parsed
@usage t:add({ "10.0.0.0/8", "192.168.0.1" })
*/
static int
pftableadd(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;
	int feedback = optbool(L, 3, "feedback", 0);
	int flags = dummyflag(L, 3);

	if (feedback)
		flags |= PFR_FLAG_FEEDBACK;

	pf = tablepf(L, lpft);

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_flags = flags;
	settablename(&pt, lpft->table);

	argstoaddrs(L, &pt);

	if (ioctl(pf->fd, DIOCRADDADDRS, &pt) < 0)
		luaL_error(L, "DIOCRADDADDRS: %s", strerror(errno));

	lua_pushinteger(L, pt.pfrio_nadd);

	if (!feedback)
		return 1;

	pushentries(L, pt.pfrio_buffer, pt.pfrio_size);

	return 2;
}

/***
Delete addresses from a table.

opts takes dummy and feedback, as add does.
@function table:delete
@param addresses a string, or an array of strings
@tparam[opt] table opts dummy and feedback
@treturn int addresses deleted
@treturn ?table per-address results, when feedback is asked for
@raise if an address cannot be parsed
*/
static int
pftabledelete(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);
	struct luapf *pf;
	struct pfioc_table pt;
	int feedback = optbool(L, 3, "feedback", 0);
	int flags = dummyflag(L, 3);

	if (feedback)
		flags |= PFR_FLAG_FEEDBACK;

	pf = tablepf(L, lpft);

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_flags = flags;
	settablename(&pt, lpft->table);

	argstoaddrs(L, &pt);

	if (ioctl(pf->fd, DIOCRDELADDRS, &pt) < 0)
		luaL_error(L, "DIOCRDELADDRS: %s", strerror(errno));

	lua_pushinteger(L, pt.pfrio_ndel);

	if (!feedback)
		return 1;

	pushentries(L, pt.pfrio_buffer, pt.pfrio_size);

	return 2;
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

/*
 * One getter per direction and op, since a property serves no context of
 * its own. pfctl -vvsT prints these eight cells and never prints a sum;
 * the summed properties above stay for callers that want one.
 */
#define TABLE_OP_PROPERTY(fn, field, dir, op)                                  \
	static int fn(lua_State *L, int idx)                                   \
	{                                                                      \
		struct luapftable *lpft = luaL_checkudata(L, idx, PFTABLE_MT); \
                                                                               \
		lua_pushinteger(L, (lua_Integer)lpft->stats.field[dir][op]);   \
                                                                               \
		return 1;                                                      \
	}

TABLE_OP_PROPERTY(table_packets_in_block, pfrts_packets, PFR_DIR_IN,
                  PFR_OP_BLOCK)
TABLE_OP_PROPERTY(table_packets_in_match, pfrts_packets, PFR_DIR_IN,
                  PFR_OP_MATCH)
TABLE_OP_PROPERTY(table_packets_in_pass, pfrts_packets, PFR_DIR_IN, PFR_OP_PASS)
TABLE_OP_PROPERTY(table_packets_in_xpass, pfrts_packets, PFR_DIR_IN,
                  PFR_OP_XPASS)
TABLE_OP_PROPERTY(table_packets_out_block, pfrts_packets, PFR_DIR_OUT,
                  PFR_OP_BLOCK)
TABLE_OP_PROPERTY(table_packets_out_match, pfrts_packets, PFR_DIR_OUT,
                  PFR_OP_MATCH)
TABLE_OP_PROPERTY(table_packets_out_pass, pfrts_packets, PFR_DIR_OUT,
                  PFR_OP_PASS)
TABLE_OP_PROPERTY(table_packets_out_xpass, pfrts_packets, PFR_DIR_OUT,
                  PFR_OP_XPASS)
TABLE_OP_PROPERTY(table_bytes_in_block, pfrts_bytes, PFR_DIR_IN, PFR_OP_BLOCK)
TABLE_OP_PROPERTY(table_bytes_in_match, pfrts_bytes, PFR_DIR_IN, PFR_OP_MATCH)
TABLE_OP_PROPERTY(table_bytes_in_pass, pfrts_bytes, PFR_DIR_IN, PFR_OP_PASS)
TABLE_OP_PROPERTY(table_bytes_in_xpass, pfrts_bytes, PFR_DIR_IN, PFR_OP_XPASS)
TABLE_OP_PROPERTY(table_bytes_out_block, pfrts_bytes, PFR_DIR_OUT, PFR_OP_BLOCK)
TABLE_OP_PROPERTY(table_bytes_out_match, pfrts_bytes, PFR_DIR_OUT, PFR_OP_MATCH)
TABLE_OP_PROPERTY(table_bytes_out_pass, pfrts_bytes, PFR_DIR_OUT, PFR_OP_PASS)
TABLE_OP_PROPERTY(table_bytes_out_xpass, pfrts_bytes, PFR_DIR_OUT, PFR_OP_XPASS)

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
    {"anchor",            table_anchor           },
    {"name",              table_name             },
    {"persist",           table_persist          },
    {"const",             table_const            },
    {"active",            table_active           },
    {"inactive",          table_inactive         },
    {"referenced",        table_referenced       },
    {"refdanchor",        table_refdanchor       },
    {"counters",          table_counters         },
    {"addresses_count",   table_addresses_count  },
    {"match",             table_match            },
    {"nomatch",           table_nomatch          },
    {"packets_in",        table_packets_in       },
    {"packets_out",       table_packets_out      },
    {"bytes_in",          table_bytes_in         },
    {"bytes_out",         table_bytes_out        },
    {"packets_in_block",  table_packets_in_block },
    {"packets_in_match",  table_packets_in_match },
    {"packets_in_pass",   table_packets_in_pass  },
    {"packets_in_xpass",  table_packets_in_xpass },
    {"packets_out_block", table_packets_out_block},
    {"packets_out_match", table_packets_out_match},
    {"packets_out_pass",  table_packets_out_pass },
    {"packets_out_xpass", table_packets_out_xpass},
    {"bytes_in_block",    table_bytes_in_block   },
    {"bytes_in_match",    table_bytes_in_match   },
    {"bytes_in_pass",     table_bytes_in_pass    },
    {"bytes_in_xpass",    table_bytes_in_xpass   },
    {"bytes_out_block",   table_bytes_out_block  },
    {"bytes_out_match",   table_bytes_out_match  },
    {"bytes_out_pass",    table_bytes_out_pass   },
    {"bytes_out_xpass",   table_bytes_out_xpass  },
    {"cleared",           table_cleared          },
    {"refcnt_rule",       table_refcnt_rule      },
    {"refcnt_anchor",     table_refcnt_anchor    },
    {NULL,                NULL                   },
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

/***
Render a table exactly as a pfctl -s Tables line prints it: the name, and
the anchor after an @ where the table belongs to one.
@function tableobject:__tostring
@treturn string
@usage print(tostring(t)) -- bruteforce@spamd
*/
static int
pftabletostring(lua_State *L)
{
	struct luapftable *lpft = luaL_checkudata(L, 1, PFTABLE_MT);

	if (lpft->table->pfrt_anchor[0] != '\0')
		lua_pushfstring(L, "%s@%s", lpft->table->pfrt_name,
		                lpft->table->pfrt_anchor);
	else
		lua_pushstring(L, lpft->table->pfrt_name);

	return 1;
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

/***
List the active tables of one ruleset.

The default is the main ruleset. An anchor name lists that anchor
instead, and "*", as pfctl spells it, lists every ruleset at once.
@function pf:tables
@string[opt=""] anchor
@treturn table array of table objects
@raise if the ioctl fails
@usage for _, t in ipairs(h:tables("*")) do print(t.anchor, t.name) end
*/
int
pftables(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *anchor = luaL_optstring(L, 2, "");
	struct pfioc_table pt;
	struct pfr_tstats *tables, *t;
	struct luapftable *lpft;
	int i, ii;

	memset(&pt, 0, sizeof(pt));

	pt.pfrio_esize = sizeof(struct pfr_tstats);

	if (strcmp(anchor, "*") == 0)
		pt.pfrio_flags = PFR_FLAG_ALLRSETS;
	else if (strlcpy(pt.pfrio_table.pfrt_anchor, anchor,
	                 sizeof(pt.pfrio_table.pfrt_anchor)) >=
	         sizeof(pt.pfrio_table.pfrt_anchor))
		luaL_error(L, "anchor name too long");

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

/***
Read one table by name.

The name may carry an anchor path, as in "anchorname/tablename".
@function pf:gettable
@string name
@treturn ?userdata table object, or nil if there is no such table
@raise if the ioctl fails
@usage local t = h:gettable("badboys")
*/
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

/***
Re-read the counters of a table in place.

Table objects are snapshots, so add, delete and replace leave the
properties stale until this runs.
@function table:refresh
@treturn table the same table, so calls chain
@raise if the table no longer exists
@usage print(t:refresh().match)
*/
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
argstotables(lua_State *L, struct pfioc_table *pt, int tflags)
{
	const char *s;
	size_t len, i;
	struct pfr_table *tp;

	pt->pfrio_esize = sizeof(struct pfr_table);

	/*
	 * lua_isstring is also true of a number, and a number reaching this
	 * unchecked is how a table named 42 gets created, so insist on a
	 * string.
	 */
	luaL_argcheck(L, (lua_istable(L, 2) || lua_type(L, 2) == LUA_TSTRING),
	              2, "expected table or string");

	len = lua_rawlen(L, 2);

	if (lua_type(L, 2) == LUA_TSTRING) {
		s = luaL_checkstring(L, 2);
		luaL_argcheck(L, (len < PATH_MAX), 2, "table name too long");

		tp = lua_newuserdata(L, sizeof(*tp));
		memset(tp, 0, sizeof(*tp));

		strtotable(L, s, tp);
		tp->pfrt_flags = (u_int32_t)tflags;
		pt->pfrio_buffer = tp;
		pt->pfrio_size = 1;
	} else {
		/* pfrio_size is an int, so a longer array would truncate. */
		luaL_argcheck(L, (len <= (size_t)INT_MAX), 2,
		              "too many table names");

		tp = lua_newuserdata(L, len * sizeof(*tp));
		memset(tp, 0, len * sizeof(*tp));
		for (i = 0; i < len; i++) {
			lua_rawgeti(L, 2, (lua_Integer)(i + 1));
			luaL_argcheck(L, (lua_type(L, -1) == LUA_TSTRING), 2,
			              "table element not a string");
			luaL_argcheck(L, (lua_rawlen(L, -1) < PATH_MAX), 2,
			              "table name too long");
			s = lua_tostring(L, -1);
			strtotable(L, s, &tp[i]);
			tp[i].pfrt_flags = (u_int32_t)tflags;
			lua_pop(L, 1);
		}

		pt->pfrio_buffer = tp;
		pt->pfrio_size = (int)len;
	}
}

static void
multitableop(lua_State *L, struct pfioc_table *pt, unsigned long op,
             const char *label, int tflags)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	argstotables(L, pt, tflags);

	if (ioctl(pf->fd, op, pt) < 0)
		luaL_error(L, "%s: %s", label, strerror(errno));
}

/***
Create tables.

The new table is persistent unless opts says otherwise, which is what
pfctl asks for: a table that is only active is dropped again as soon as
nothing refers to it, and its own first flag change is enough to do that.
opts also takes const, and dummy, which asks what the call would do and
creates nothing.
@function pf:addtables
@param names a string, or an array of strings
@tparam[opt] table opts persist, defaulting to true, plus const and dummy
@treturn int tables created
@raise if the ioctl fails
@usage h:addtables("badboys", { const = true })
*/
int
pfaddtables(lua_State *L)
{
	struct pfioc_table pt;
	int tflags = 0;

	if (optbool(L, 3, "persist", 1))
		tflags |= PFR_TFLAG_PERSIST;
	if (optbool(L, 3, "const", 0))
		tflags |= PFR_TFLAG_CONST;

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_flags = dummyflag(L, 3);
	multitableop(L, &pt, DIOCRADDTABLES, "DIOCRADDTABLES", tflags);
	lua_pushinteger(L, pt.pfrio_nadd);

	return 1;
}

/***
Zero the counters of tables, and of their addresses.

The addresses themselves stay. This is `pfctl -T zero` with no address
argument: the kernel recurses into the per-address counters, so the two
halves cannot come apart.
@function pf:cleartables
@param names a string, or an array of strings
@treturn int tables zeroed
@raise if the ioctl fails
*/
int
pfcleartables(lua_State *L)
{
	struct pfioc_table pt;

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_flags = PFR_FLAG_ADDRSTOO;
	multitableop(L, &pt, DIOCRCLRTSTATS, "DIOCRCLRTSTATS", 0);
	lua_pushinteger(L, pt.pfrio_nzero);

	return 1;
}

/***
Delete every table in an anchor, defaulting to the main ruleset.
@function pf:clearalltables
@string[opt=""] anchor
@treturn int tables deleted
@raise if the ioctl fails
*/
int
pfclearalltables(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *anchor = luaL_optstring(L, 2, "");
	struct pfioc_table pt;

	memset(&pt, 0, sizeof(pt));

	if (strlcpy(pt.pfrio_table.pfrt_anchor, anchor,
	            sizeof(pt.pfrio_table.pfrt_anchor)) >=
	    sizeof(pt.pfrio_table.pfrt_anchor))
		luaL_error(L, "anchor name too long");

	if (ioctl(pf->fd, DIOCRCLRTABLES, &pt) < 0)
		luaL_error(L, "DIOCRCLRTABLES: %s", strerror(errno));

	lua_pushinteger(L, (lua_Integer)pt.pfrio_ndel);

	return 1;
}

/***
Delete tables by name.
@function pf:deletetables
@param names a string, or an array of strings
@tparam[opt] table opts dummy asks what the call would do and deletes
nothing
@treturn int tables deleted
@raise if the ioctl fails
*/
int
pfdeletetables(lua_State *L)
{
	struct pfioc_table pt;

	memset(&pt, 0, sizeof(pt));
	pt.pfrio_flags = dummyflag(L, 3);
	multitableop(L, &pt, DIOCRDELTABLES, "DIOCRDELTABLES", 0);
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

/***
A single table, as tables and gettable return it.

Read-only properties: name, anchor, persist, const, active, inactive,
referenced, refdanchor, counters, addresses_count, match, nomatch,
packets_in, packets_out, bytes_in, bytes_out, cleared, refcnt_rule and
refcnt_anchor.

The kernel counts packets and bytes per direction and per op, and
packets_in, packets_out, bytes_in and bytes_out are sums over the four
ops. The cells themselves are packets_in_block, packets_in_match,
packets_in_pass, packets_in_xpass, packets_out_block, packets_out_match,
packets_out_pass, packets_out_xpass and the eight bytes_ properties
spelled the same way. An address keeps three ops rather than four, so a
table sum and the sum of its addresses only agree while the xpass cells
are zero.

All of them are a snapshot; refresh re-reads them. The length operator
returns the address count, and tostring renders the table as a
pfctl -s Tables line.
@table tableobject
*/
