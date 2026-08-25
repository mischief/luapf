/* SPDX-License-Identifier: ISC */
#ifndef LUAPF_FUZZ_RENDER_H
#define LUAPF_FUZZ_RENDER_H

#include <stddef.h>
#include <string.h>

#include <lua.h>
#include <lauxlib.h>

/*
 * Drive one userdata through everything its metatable renders: __tostring,
 * and every property the __pairs iterator walks. Getters report bad kernel
 * data with luaL_error(), so this runs under a pcall and a raised error is
 * a result, not a finding. A crash is the finding.
 */
static int
luapf_render_protected(lua_State *L)
{
	if (luaL_callmeta(L, 1, "__tostring"))
		lua_pop(L, 1);

	if (luaL_getmetafield(L, 1, "__pairs") == LUA_TNIL)
		return 0;

	lua_pushvalue(L, 1);
	lua_call(L, 1, 3); /* iterator, state, control at 2, 3, 4 */

	for (;;) {
		lua_pushvalue(L, 2);
		lua_pushvalue(L, 3);
		lua_pushvalue(L, 4);
		lua_call(L, 2, 2); /* key at 5, value at 6 */

		if (lua_isnil(L, 5))
			break;

		(void)lua_tostring(L, 6);

		lua_pushvalue(L, 5);
		lua_replace(L, 4);
		lua_settop(L, 4);
	}

	return 0;
}

/* Present len bytes of fuzzer input as a userdata of the named metatable. */
static inline void
luapf_render_case(lua_State *L, const char *mt, size_t size,
                  const unsigned char *buf, size_t len)
{
	void *ud;

	lua_pushcfunction(L, luapf_render_protected);

	ud = lua_newuserdata(L, size);
	memset(ud, 0, size);
	memcpy(ud, buf, len < size ? len : size);
	luaL_setmetatable(L, mt);

	if (lua_pcall(L, 1, 0, 0) != LUA_OK)
		lua_pop(L, 1);
}

#endif /* LUAPF_FUZZ_RENDER_H */
