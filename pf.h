#ifndef luapfh
#define luapfh

#define PF_MT "PFMT"
#define PFSTATES_MT "PFSTATESMT"
#define PFSTATE_MT "PFSTATEMT"
#define PFTABLE_MT "PFTABLEMT"

struct luapf {
	int fd;
};

void luapf_states_register(lua_State*);
void luapf_tables_register(lua_State*);

int pfqueues(lua_State*);

/* table.c */
int pftables(lua_State*);
int pfgettable(lua_State *L);
int pfaddtables(lua_State *L);
int pfcleartables(lua_State *L);
int pfdeletetables(lua_State *L);

#endif

