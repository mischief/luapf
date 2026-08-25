/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "banned.h"

/***
@module pf
*/

/*
 * A kernel name field can fill its array with no NUL, so bound every such
 * read to the size of the array itself.
 */
static void
pushname(lua_State *L, const char *name, size_t size)
{
	lua_pushlstring(L, name, strnlen(name, size));
}

/* Both limiters carry the same moving-average rate pair. */
static void
pushrate(lua_State *L, unsigned int limit, unsigned int seconds)
{
	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)limit);
	lua_setfield(L, -2, "limit");
	lua_pushinteger(L, (lua_Integer)seconds);
	lua_setfield(L, -2, "seconds");
	lua_setfield(L, -2, "rate");
}

/*
 * The two GETN ioctls walk their trees the same way: ask for the first
 * limiter with an id at or above the one given, then ask again from one
 * past what came back. The kernel reports the end of the walk as ENOENT
 * for state limiters and ESRCH for source limiters, so accept either
 * rather than tie this to which one a release happens to return.
 */
static int
walkdone(void)
{
	return errno == ENOENT || errno == ESRCH;
}

/***
Read the state limiters, the same set pfctl -s Stlimiters prints.

A state limiter caps the number of states, or the rate of state creation,
for the rules that name it. Each entry holds id, name, limit, inuse,
admitted, hardlimited and ratelimited, plus a rate table holding limit
and seconds. A limiter configured with no rate reports both as zero,
which is what pfctl prints as nil.

limit and rate are the configuration; inuse is a gauge of the states the
limiter currently holds, and admitted, hardlimited and ratelimited count
the states it let through, refused for the total limit and refused for
the rate limit. The kernel does not return the description field, so
there is none here.

The list is ordered by id. A read-only handle answers this ioctl.
@function pf:statelimiters
@treturn table array of limiter tables
@raise if the ioctl fails
@usage for _, l in ipairs(h:statelimiters()) do print(l.name, l.inuse) end
*/
int
pfstatelimiters(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_statelim sl;
	uint32_t id = PF_STATELIM_ID_MIN;
	lua_Integer n = 0;

	lua_newtable(L);

	while (id <= PF_STATELIM_ID_MAX) {
		memset(&sl, 0, sizeof(sl));
		sl.id = id;

		if (ioctl(pf->fd, DIOCGETNSTATELIM, &sl) < 0) {
			if (walkdone())
				break;
			luaL_error(L, "DIOCGETNSTATELIM %u: %s", id,
			           strerror(errno));
		}

		lua_newtable(L);

		lua_pushinteger(L, (lua_Integer)sl.id);
		lua_setfield(L, -2, "id");
		pushname(L, sl.name, sizeof(sl.name));
		lua_setfield(L, -2, "name");
		lua_pushinteger(L, (lua_Integer)sl.limit);
		lua_setfield(L, -2, "limit");
		pushrate(L, sl.rate.limit, sl.rate.seconds);
		lua_pushinteger(L, (lua_Integer)sl.inuse);
		lua_setfield(L, -2, "inuse");
		lua_pushinteger(L, (lua_Integer)sl.admitted);
		lua_setfield(L, -2, "admitted");
		lua_pushinteger(L, (lua_Integer)sl.hardlimited);
		lua_setfield(L, -2, "hardlimited");
		lua_pushinteger(L, (lua_Integer)sl.ratelimited);
		lua_setfield(L, -2, "ratelimited");

		lua_rawseti(L, -2, ++n);

		id = sl.id + 1;
	}

	return 1;
}

/***
Read the source limiters, the same set pfctl -s Srclimiters prints.

A source limiter caps the states, or the rate of state creation, for each
source address the rules naming it match. Each entry holds id, name,
entries, limit, nentries, inuse, addrallocs, addrnomem, admitted,
addrlimited, hardlimited, ratelimited, inet_prefix and inet6_prefix, plus
a rate table holding limit and seconds.

entries is the configured cap on tracked source addresses and nentries
the gauge of how many exist; limit is the per-address state cap and inuse
the states held across every address. addrlimited counts the states
refused for the entries cap, hardlimited those refused for limit, and
ratelimited those refused for the rate. inet_prefix and inet6_prefix are
the prefix lengths source addresses are masked to, which pf.conf spells
inet mask and inet6 mask.

overload is set only where the limiter carries an overload table, and
holds table, hwm and lwm -- pf.conf's table, above and below. The kernel
does not return the description field, so there is none here.

The list is ordered by id. A read-only handle answers this ioctl.
@function pf:sourcelimiters
@treturn table array of limiter tables
@raise if the ioctl fails
@usage for _, l in ipairs(h:sourcelimiters()) do print(l.name, l.nentries) end
*/
int
pfsourcelimiters(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_sourcelim sl;
	uint32_t id = PF_SOURCELIM_ID_MIN;
	lua_Integer n = 0;

	lua_newtable(L);

	while (id <= PF_SOURCELIM_ID_MAX) {
		memset(&sl, 0, sizeof(sl));
		sl.id = id;

		if (ioctl(pf->fd, DIOCGETNSOURCELIM, &sl) < 0) {
			if (walkdone())
				break;
			luaL_error(L, "DIOCGETNSOURCELIM %u: %s", id,
			           strerror(errno));
		}

		lua_newtable(L);

		lua_pushinteger(L, (lua_Integer)sl.id);
		lua_setfield(L, -2, "id");
		pushname(L, sl.name, sizeof(sl.name));
		lua_setfield(L, -2, "name");
		lua_pushinteger(L, (lua_Integer)sl.entries);
		lua_setfield(L, -2, "entries");
		lua_pushinteger(L, (lua_Integer)sl.limit);
		lua_setfield(L, -2, "limit");
		pushrate(L, sl.rate.limit, sl.rate.seconds);

		/* An empty table name is the absence of an overload table,
		 * which is why pfctl prints nothing for it. */
		if (sl.overload_tblname[0] != '\0') {
			lua_newtable(L);
			pushname(L, sl.overload_tblname,
			         sizeof(sl.overload_tblname));
			lua_setfield(L, -2, "table");
			lua_pushinteger(L, (lua_Integer)sl.overload_hwm);
			lua_setfield(L, -2, "hwm");
			lua_pushinteger(L, (lua_Integer)sl.overload_lwm);
			lua_setfield(L, -2, "lwm");
			lua_setfield(L, -2, "overload");
		}

		lua_pushinteger(L, (lua_Integer)sl.inet_prefix);
		lua_setfield(L, -2, "inet_prefix");
		lua_pushinteger(L, (lua_Integer)sl.inet6_prefix);
		lua_setfield(L, -2, "inet6_prefix");

		lua_pushinteger(L, (lua_Integer)sl.nentries);
		lua_setfield(L, -2, "nentries");
		lua_pushinteger(L, (lua_Integer)sl.inuse);
		lua_setfield(L, -2, "inuse");
		lua_pushinteger(L, (lua_Integer)sl.addrallocs);
		lua_setfield(L, -2, "addrallocs");
		lua_pushinteger(L, (lua_Integer)sl.addrnomem);
		lua_setfield(L, -2, "addrnomem");
		lua_pushinteger(L, (lua_Integer)sl.admitted);
		lua_setfield(L, -2, "admitted");
		lua_pushinteger(L, (lua_Integer)sl.addrlimited);
		lua_setfield(L, -2, "addrlimited");
		lua_pushinteger(L, (lua_Integer)sl.hardlimited);
		lua_setfield(L, -2, "hardlimited");
		lua_pushinteger(L, (lua_Integer)sl.ratelimited);
		lua_setfield(L, -2, "ratelimited");

		lua_rawseti(L, -2, ++n);

		id = sl.id + 1;
	}

	return 1;
}
