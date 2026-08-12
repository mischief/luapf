/* SPDX-License-Identifier: ISC */
#ifndef LUAPF_PF_H
#define LUAPF_PF_H

#define PF_MT "PFMT"
#define PFSTATES_MT "PFSTATESMT"
#define PFSTATE_MT "PFSTATEMT"
#define PFTABLE_MT "PFTABLEMT"
#define PFRULE_MT "PFRULEMT"

/* The build hides every symbol; the lua loader needs this one. */
#define LUAPF_EXPORT __attribute__((visibility("default")))

struct luapf {
	int fd;
};

LUAPF_EXPORT int luaopen_pf(lua_State *L);

void luapf_states_register(lua_State *L);

/* state.c */
int pfgetstate(lua_State *L);
int pfclearstates(lua_State *L);
void luapf_tables_register(lua_State *L);
void luapf_rules_register(lua_State *L);

/* anchor.c */
int pfanchors(lua_State *L);

/* queue.c */
int pfqueues(lua_State *L);

/* rule.c */
int pfrules(lua_State *L);

/* system.c */
int pflimits(lua_State *L);
int pftimeouts(lua_State *L);
int pfinterfaces(lua_State *L);
int pfsrcnodes(lua_State *L);
int pfkillsrcnodes(lua_State *L);
int pfclearsrcnodes(lua_State *L);

/* table.c */
int pftables(lua_State *L);
int pfgettable(lua_State *L);
int pfaddtables(lua_State *L);
int pfcleartables(lua_State *L);
int pfdeletetables(lua_State *L);
int pfclearalltables(lua_State *L);

#endif /* LUAPF_PF_H */
