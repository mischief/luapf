/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <stdlib.h>
#include <grp.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "banned.h"

/***
OpenBSD privilege calls that POSIX does not define, so luaposix omits them.

Every function returns 0 on success, or nil, an error message and errno.
The pledge "pf" promise allows twelve ioctls meant for rule writers, so a
pledged process cannot read rules; drop privilege and keep a read-only
descriptor instead.
@module pf.privsep
@usage pf.privsep.pledge("stdio inet", nil)
*/

static int
pusherr(lua_State *L, int e)
{
	char estr[NL_TEXTMAX];

	lua_pushnil(L);

	if (strerror_r(e, estr, sizeof(estr)) == 0)
		lua_pushstring(L, estr);
	else
		lua_pushfstring(L, "(unknown error %d)", e);

	lua_pushinteger(L, e);

	return 3;
}

/***
Restrict the process to a set of promises.
@function pledge
@string[opt] promises nil leaves the current set alone
@string[opt] execpromises
@treturn int 0
*/
static int
luapledge(lua_State *L)
{
	const char *promises = luaL_optstring(L, 1, NULL);
	const char *execpromises = luaL_optstring(L, 2, NULL);

	if (pledge(promises, execpromises) < 0)
		return pusherr(L, errno);

	lua_pushinteger(L, 0);

	return 1;
}

/***
Expose one path to the process and hide the rest of the filesystem.
@function unveil
@string[opt] path
@string[opt] permissions any of r, w, x and c
@treturn int 0
*/
static int
luaunveil(lua_State *L)
{
	const char *path = luaL_optstring(L, 1, NULL);
	const char *permissions = luaL_optstring(L, 2, NULL);

	if (unveil(path, permissions) < 0)
		return pusherr(L, errno);

	lua_pushinteger(L, 0);

	return 1;
}

/***
Replace the supplementary group list with one group.
@function setgroups
@int gid
@treturn int 0
*/
static int
luasetgroups(lua_State *L)
{
	gid_t gid = (gid_t)luaL_checkinteger(L, 1);

	if (setgroups(1, &gid) < 0)
		return pusherr(L, errno);

	lua_pushinteger(L, 0);

	return 1;
}

/***
Set the real, effective and saved group id.
@function setresgid
@int rgid
@int egid
@int sgid
@treturn int 0
*/
static int
luasetresgid(lua_State *L)
{
	gid_t rgid = (gid_t)luaL_checkinteger(L, 1);
	gid_t egid = (gid_t)luaL_checkinteger(L, 2);
	gid_t sgid = (gid_t)luaL_checkinteger(L, 3);

	if (setresgid(rgid, egid, sgid) < 0)
		return pusherr(L, errno);

	lua_pushinteger(L, 0);

	return 1;
}

/***
Set the real, effective and saved user id.
@function setresuid
@int ruid
@int euid
@int suid
@treturn int 0
*/
static int
luasetresuid(lua_State *L)
{
	uid_t ruid = (uid_t)luaL_checkinteger(L, 1);
	uid_t euid = (uid_t)luaL_checkinteger(L, 2);
	uid_t suid = (uid_t)luaL_checkinteger(L, 3);

	if (setresuid(ruid, euid, suid) < 0)
		return pusherr(L, errno);

	lua_pushinteger(L, 0);

	return 1;
}

/***
Set the text ps shows after the program name.
@function setproctitle
@string title
*/
static int
luasetproctitle(lua_State *L)
{
	const char *title = luaL_checkstring(L, 1);

	setproctitle("%s", title);

	return 0;
}

static const luaL_Reg privseplib[] = {
    {"pledge",       luapledge      },
    {"unveil",       luaunveil      },
    {"setgroups",    luasetgroups   },
    {"setresgid",    luasetresgid   },
    {"setresuid",    luasetresuid   },
    {"setproctitle", luasetproctitle},
    {NULL,           NULL           },
};

void
luapf_privsep_register(lua_State *L)
{
	luaL_newlib(L, privseplib);
	lua_setfield(L, -2, "privsep");
}
