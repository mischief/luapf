/* SPDX-License-Identifier: ISC */
#ifndef LUAPF_PROPERTY_H
#define LUAPF_PROPERTY_H

#include <string.h>

#include <lua.h>
#include <lauxlib.h>

/*
 * Read-only properties of a userdata, served from a NULL-terminated table.
 * The getter reads the userdata at stack index idx and pushes one value.
 */
struct ro_property {
	const char *name;
	int (*get)(lua_State *, int);
};

/* __index: push the value of the named property, or nil. */
static inline int
ro_property_lookup(lua_State *L, const struct ro_property *props, int mtidx,
                   int keyidx)
{
	const char *key = luaL_checkstring(L, keyidx);

	for (const struct ro_property *p = props; p->name != NULL; p++) {
		if (strcmp(p->name, key) == 0)
			return p->get(L, mtidx);
	}

	lua_pushnil(L);

	return 1;
}

/* __pairs iterator: push the property after keyidx and its value. */
static inline int
ro_property_next(lua_State *L, const struct ro_property *props, int mtidx,
                 int keyidx)
{
	const struct ro_property *p = props;

	if (!lua_isnil(L, keyidx)) {
		const char *key = luaL_checkstring(L, keyidx);

		for (; p->name != NULL; p++) {
			if (strcmp(p->name, key) == 0) {
				p++;
				break;
			}
		}
	}

	if (p->name == NULL) {
		lua_pushnil(L);
		return 1;
	}

	lua_pushstring(L, p->name);

	return 1 + p->get(L, mtidx);
}

#endif /* LUAPF_PROPERTY_H */
