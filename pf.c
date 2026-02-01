#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <endian.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"

static const char *pfcounternames[] = PFRES_NAMES;

static int
pfstart(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	int x;

	if(ioctl(pf->fd, DIOCSTART, &x) < 0)
		luaL_error(L, "DIOCSTART: %s", strerror(errno));
	
	return 1;
}

static int
pfstop(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	int x;

	if(ioctl(pf->fd, DIOCSTOP, &x) < 0)
		luaL_error(L, "DIOCSTOP: %s", strerror(errno));
	
	return 1;
}

static int
pfstatus(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pf_status st;
	char hash[PF_MD5_DIGEST_LENGTH*2+1];
	u_int8_t *c;
	int i;

	if(ioctl(pf->fd, DIOCGETSTATUS, &st) < 0)
		luaL_error(L, "DIOCGETSTATUS: %s", strerror(errno));

	lua_newtable(L);

	lua_pushinteger(L, st.stateid);
	lua_setfield(L, -2, "stateid");
	lua_pushinteger(L, st.since);
	lua_setfield(L, -2, "since");
	lua_pushboolean(L, st.running);
	lua_setfield(L, -2, "running");
	lua_pushinteger(L, st.states);
	lua_setfield(L, -2, "states");
	lua_pushinteger(L, st.states_halfopen);
	lua_setfield(L, -2, "states_halfopen");
	lua_pushinteger(L, st.src_nodes);
	lua_setfield(L, -2, "src_nodes");
	lua_pushinteger(L, st.debug);
	lua_setfield(L, -2, "debug");
	lua_pushinteger(L, st.hostid);
	lua_setfield(L, -2, "hostid");
	lua_pushinteger(L, st.reass);
	lua_setfield(L, -2, "reass");
	lua_pushinteger(L, st.syncookies_active);
	lua_setfield(L, -2, "syncookies_active");
	lua_pushinteger(L, st.syncookies_mode);
	lua_setfield(L, -2, "syncookies_mode");
	lua_pushstring(L, st.ifname);
	lua_setfield(L, -2, "ifname");

	c = st.pf_chksum;

	snprintf(hash, sizeof(hash), "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
		c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7],
		c[8], c[9], c[10], c[11], c[12], c[13], c[14], c[15]);

	lua_pushstring(L, hash);
	lua_setfield(L, -2, "checksum");

	lua_newtable(L);
	for(i = 0; i < PFRES_MAX; i++){
		lua_pushinteger(L, st.counters[i]);
		lua_setfield(L, -2, pfcounternames[i]);
	}
	lua_setfield(L, -2, "counters");

	lua_newtable(L);
	
	lua_newtable(L);
	lua_pushinteger(L, st.bcounters[0][0]);
	lua_setfield(L, -2, "bytesin");
	lua_pushinteger(L, st.bcounters[0][1]);
	lua_setfield(L, -2, "bytesout");
	lua_setfield(L, -2, "v4");
	
	lua_newtable(L);
	lua_pushinteger(L, st.bcounters[1][0]);
	lua_setfield(L, -2, "bytesin");
	lua_pushinteger(L, st.bcounters[1][1]);
	lua_setfield(L, -2, "bytesout");
	lua_setfield(L, -2, "v6");

	lua_setfield(L, -2, "bcounters");

	lua_newtable(L);

	lua_newtable(L);
	lua_pushinteger(L, st.pcounters[0][0][PF_PASS]);
	lua_setfield(L, -2, "packets_in_passed");
	lua_pushinteger(L, st.pcounters[0][0][PF_DROP]);
	lua_setfield(L, -2, "packets_in_blocked");
	lua_pushinteger(L, st.pcounters[0][1][PF_PASS]);
	lua_setfield(L, -2, "packets_out_passed");
	lua_pushinteger(L, st.pcounters[0][1][PF_DROP]);
	lua_setfield(L, -2, "packets_out_blocked");
	lua_setfield(L, -2, "v4");

	lua_newtable(L);
	lua_pushinteger(L, st.pcounters[1][0][PF_PASS]);
	lua_setfield(L, -2, "packets_in_passed");
	lua_pushinteger(L, st.pcounters[1][0][PF_DROP]);
	lua_setfield(L, -2, "packets_in_blocked");
	lua_pushinteger(L, st.pcounters[1][1][PF_PASS]);
	lua_setfield(L, -2, "packets_out_passed");
	lua_pushinteger(L, st.pcounters[1][1][PF_DROP]);
	lua_setfield(L, -2, "packets_out_blocked");
	lua_setfield(L, -2, "v6");

	lua_setfield(L, -2, "pcounters");
	return 1;
}

static int
pfstates(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_states *ps;

	ps = lua_newuserdata(L, sizeof(*ps));
	luaL_setmetatable(L, PFSTATES_MT);

	memset(ps, 0, sizeof(*ps));

	ps->ps_len = 0;

	if(ioctl(pf->fd, DIOCGETSTATES, ps) == -1)
		luaL_error(L,"DIOCGETSTATES: %s", strerror(errno));

	ps->ps_buf = malloc(ps->ps_len);
	if(!ps->ps_buf)
		luaL_error(L, "DIOCGETSTATES: %s", strerror(errno));

	if(ioctl(pf->fd, DIOCGETSTATES, ps) == -1)
		luaL_error(L, "DIOCGETSTATES: %s", strerror(errno));

	return 1;
}

static int
pfgc(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	if(pf->fd >= 0)
		close(pf->fd);

	return 0;
}

static const luaL_Reg pfmeta[] = {
	{"start", pfstart},
	{"stop", pfstop},
	{"status", pfstatus},
	{"states", pfstates},
	{"queues", pfqueues},
	{"tables", pftables},
	{"__gc", pfgc},
	{0, 0},
};

static int
pfopen(lua_State *L)
{
	struct luapf *pf;
	int fd;

	fd = open("/dev/pf", O_RDWR, O_CLOEXEC);
	if(fd < 0)
		luaL_error(L, "open /dev/pf: %s", strerror(errno));

	pf = lua_newuserdata(L, sizeof(*pf));
	luaL_setmetatable(L, PF_MT);
	pf->fd = fd;
	
	return 1;
}

static int
pfopenfd(lua_State *L)
{
	// XXX: take fd / luaL_Stream wrapped fd
	luaL_error(L, "notyet");
	
	return 1;
}

static const luaL_Reg pflib[] = {
	{ "open", pfopen},
	{ "openfd", pfopenfd},
	{ 0, 0 }
};

__attribute__((visibility("default"))) int
luaopen_pf(lua_State* L)
{
	luaL_newlib(L, pflib);

	luaL_newmetatable(L, PF_MT);
	luaL_setfuncs(L, pfmeta, 0);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luapf_states_register(L);
	luapf_tables_register(L);

	return 1;
}

