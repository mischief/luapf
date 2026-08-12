/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "banned.h"

/* An anchor tree deeper or wider than this is a bug, not a configuration. */
enum { maxanchors = 4096 };

static void
childpath(lua_State *L, char *dst, size_t dstlen, const char *path,
          const char *name)
{
	int n;

	if (path[0] == '\0')
		n = snprintf(dst, dstlen, "%s", name);
	else
		n = snprintf(dst, dstlen, "%s/%s", path, name);

	if (n < 0 || (size_t)n >= dstlen)
		luaL_error(L, "anchor path too long");
}

/*
 * Appends the immediate children of path to the pending list at pidx and to
 * the result list at ridx, and returns how many it found.
 */
static int
listchildren(lua_State *L, int fd, const char *path, int pidx, int ridx,
             int *found)
{
	struct pfioc_ruleset *pr;
	uint32_t count;
	int top = lua_gettop(L);

	pr = lua_newuserdata(L, sizeof(*pr));
	memset(pr, 0, sizeof(*pr));

	if (strlcpy(pr->path, path, sizeof(pr->path)) >= sizeof(pr->path))
		luaL_error(L, "anchor path too long");

	if (ioctl(fd, DIOCGETRULESETS, pr) < 0)
		luaL_error(L, "DIOCGETRULESETS: %s", strerror(errno));

	count = pr->nr;

	for (uint32_t i = 0; i < count; i++) {
		char child[PATH_MAX];

		pr->nr = i;

		if (ioctl(fd, DIOCGETRULESET, pr) < 0)
			luaL_error(L, "DIOCGETRULESET: %s", strerror(errno));

		/* Every anchor lists itself as its own first child. */
		if (strcmp(pr->name, path) == 0 || pr->name[0] == '\0')
			continue;

		childpath(L, child, sizeof(child), path, pr->name);

		lua_pushstring(L, child);
		lua_rawseti(L, ridx, ++*found);

		lua_pushstring(L, child);
		lua_rawseti(L, pidx, (lua_Integer)lua_rawlen(L, pidx) + 1);
	}

	lua_settop(L, top);

	return (int)count;
}

/*
 * Walks the anchor tree below an optional root. The kernel reports direct
 * children only, so pending paths live in a lua table, not on the C stack.
 */
int
pfanchors(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *root = luaL_optstring(L, 2, "");
	int found = 0;
	int pidx, ridx;

	lua_newtable(L);
	ridx = lua_gettop(L);

	lua_newtable(L);
	pidx = lua_gettop(L);

	lua_pushstring(L, root);
	lua_rawseti(L, pidx, 1);

	for (int seen = 0; seen < maxanchors; seen++) {
		lua_Integer pending = (lua_Integer)lua_rawlen(L, pidx);

		if (pending == 0)
			break;

		lua_rawgeti(L, pidx, pending);
		const char *path = lua_tostring(L, -1);

		lua_pushnil(L);
		lua_rawseti(L, pidx, pending);

		listchildren(L, pf->fd, path, pidx, ridx, &found);

		lua_pop(L, 1);
	}

	/* Sorted, so the order matches pfctl -s Anchors and is reproducible. */
	lua_getglobal(L, "table");
	lua_getfield(L, -1, "sort");
	lua_pushvalue(L, ridx);
	lua_call(L, 1, 0);
	lua_pop(L, 1);

	lua_pushvalue(L, ridx);

	return 1;
}
