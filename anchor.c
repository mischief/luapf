/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
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

/* An anchor tree deeper or wider than this is a bug, not a configuration. */
enum { maxanchors = 4096 };

static int
cmpname(const void *a, const void *b)
{
	return strcmp(*(const char *const *)a, *(const char *const *)b);
}

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
 * Returns how many rules an anchor holds. DIOCGETRULES answers with the
 * count and a ticket, so no rule is copied out of the kernel to count it.
 * The ticket is released again: a ticket left open pins the ruleset.
 */
static uint32_t
rulecount(lua_State *L, int fd, const char *path)
{
	struct pfioc_rule *pr;
	uint32_t nr, ticket;
	int top = lua_gettop(L);

	/* Two PATH_MAX arrays make this far too big for the stack. */
	pr = lua_newuserdata(L, sizeof(*pr));
	memset(pr, 0, sizeof(*pr));

	if (strlcpy(pr->anchor, path, sizeof(pr->anchor)) >= sizeof(pr->anchor))
		luaL_error(L, "anchor path too long");

	pr->rule.action = PF_PASS;

	if (ioctl(fd, DIOCGETRULES, pr) < 0)
		luaL_error(L, "DIOCGETRULES: %s", strerror(errno));

	nr = pr->nr;
	ticket = pr->ticket;
	(void)ioctl(fd, DIOCXEND, &ticket);

	lua_settop(L, top);

	return nr;
}

/***
List every anchor below a root.

The kernel reports direct children only, so this walks the tree. Paths are
full and sorted, matching pfctl -s Anchors -v. With counts set, every entry
is instead a table of the path and the rule count of that anchor, read with
one ioctl and no rule copied. Counting is off by default so that a plain
listing does not pay for it.
@function pf:anchors
@string[opt=""] root
@bool[opt=false] counts return {path=,rules=} entries instead of paths
@treturn table array of anchor paths, or of tables when counts is set
@raise if the root anchor does not exist
@usage for _, a in ipairs(h:anchors()) do print(a) end
@usage for _, a in ipairs(h:anchors("", true)) do print(a.path, a.rules) end
*/
int
pfanchors(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *root = luaL_optstring(L, 2, "");
	int counts = lua_toboolean(L, 3);
	const char **names;
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

	/*
	 * Sort in C, not through the table.sort global, which a caller can
	 * shadow. The names stay owned by the result table, so the pointers
	 * remain valid until that table is replaced below.
	 */
	names = lua_newuserdata(L, (size_t)found * sizeof(*names) + 1);

	for (int i = 0; i < found; i++) {
		lua_rawgeti(L, ridx, i + 1);
		names[i] = lua_tostring(L, -1);
		lua_pop(L, 1);
	}

	qsort(names, (size_t)found, sizeof(*names), cmpname);

	/* The order matches pfctl -s Anchors and is reproducible. */
	lua_newtable(L);

	for (int i = 0; i < found; i++) {
		if (counts) {
			uint32_t n = rulecount(L, pf->fd, names[i]);

			lua_createtable(L, 0, 2);
			lua_pushstring(L, names[i]);
			lua_setfield(L, -2, "path");
			lua_pushinteger(L, (lua_Integer)n);
			lua_setfield(L, -2, "rules");
		} else {
			lua_pushstring(L, names[i]);
		}

		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}
