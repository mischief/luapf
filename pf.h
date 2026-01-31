#ifndef luapfh
#define luapfh

#include "luapf_vis.h"

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
int pftables(lua_State*);

#endif

