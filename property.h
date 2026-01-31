#ifndef propertyh
#define propertyh

typedef int (*ro_property_getter) (lua_State*, int);

struct ro_property {
	STAILQ_ENTRY(ro_property) link;
	const char *name;
	ro_property_getter get;
};

STAILQ_HEAD(ro_property_head, ro_property);

// make a 'struct ro_property pfx_field_property'
#define ro_property_generate(pfx, field) \
	static int pfx##_##field##_get(lua_State*, int); \
	struct ro_property pfx##_##field##_property = { \
		.name = #field, \
		.get = pfx##_##field##_get, \
	}; \
	static int pfx##_##field##_get(lua_State *L, int idx)

#define ro_property_lookup(state, props, mtidx, keyidx) \
	const char *key = luaL_checkstring(state, keyidx); \
	struct ro_property *prop; \
	key = luaL_checkstring(state, 2); \
	STAILQ_FOREACH(prop, props, link) { \
		if(!strcmp(prop->name, key)) \
			break; \
	} \
	if(prop == STAILQ_END(props)){ \
		lua_pushnil(state); \
		return 1; \
	} \
	prop->get(state, mtidx); \
	return 1

#define ro_property_pairs(state, props, mtidx, keyidx) \
	const char *key; \
	struct ro_property *prop; \
	if(lua_isnil(L, 2)){ \
		prop = STAILQ_FIRST(&table_properties); \
	} else { \
		key = luaL_checkstring(L, 2); \
		STAILQ_FOREACH(prop, &table_properties, link) { \
			if(!strcmp(prop->name, key)){ \
				prop = STAILQ_NEXT(prop, link); \
				break; \
			} \
		} \
	} \
	if(prop == STAILQ_END(&table_properties)){ \
		lua_pushnil(L); \
		return 1; \
	} \
	lua_pushstring(L, prop->name); \
	prop->get(L, 1); \
	return 2 \

#endif

