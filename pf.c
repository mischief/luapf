/* SPDX-License-Identifier: ISC */
#include <endian.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "banned.h"

static const char *pfcounternames[] = PFRES_NAMES;

/***
Read and control the pf packet filter.

Every call raises a lua error on failure, so wrap them in pcall where an
error is expected. Opening /dev/pf needs root, but the kernel gates the
ioctls on the open mode rather than the uid: a read-only descriptor keeps
working after a privilege drop and is refused every write.
@module pf
@usage local pf = require("pf")
*/

/***
Start pf.
@function pf:start
@raise if the ioctl fails
*/
static int
pfstart(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	int x = 0;

	if (ioctl(pf->fd, DIOCSTART, &x) < 0)
		luaL_error(L, "DIOCSTART: %s", strerror(errno));

	return 0;
}

/***
Stop pf.
@function pf:stop
@raise if the ioctl fails
*/
static int
pfstop(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	int x = 0;

	if (ioctl(pf->fd, DIOCSTOP, &x) < 0)
		luaL_error(L, "DIOCSTOP: %s", strerror(errno));

	return 0;
}

/***
Read the global status.

The result holds running, since, states, states_halfopen, src_nodes,
debug, hostid, reass, syncookies_active, syncookies_mode, ifname and
checksum, plus counters, bcounters and pcounters tables.
@function pf:status
@treturn table status
@raise if the ioctl fails
*/
static int
pfstatus(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pf_status st;
	char hash[PF_MD5_DIGEST_LENGTH * 2 + 1];
	const uint8_t *c;

	if (ioctl(pf->fd, DIOCGETSTATUS, &st) < 0)
		luaL_error(L, "DIOCGETSTATUS: %s", strerror(errno));

	lua_newtable(L);

	lua_pushinteger(L, (lua_Integer)st.stateid);
	lua_setfield(L, -2, "stateid");
	lua_pushinteger(L, (lua_Integer)st.since);
	lua_setfield(L, -2, "since");
	lua_pushboolean(L, st.running != 0);
	lua_setfield(L, -2, "running");
	lua_pushinteger(L, (lua_Integer)st.states);
	lua_setfield(L, -2, "states");
	lua_pushinteger(L, (lua_Integer)st.states_halfopen);
	lua_setfield(L, -2, "states_halfopen");
	lua_pushinteger(L, (lua_Integer)st.src_nodes);
	lua_setfield(L, -2, "src_nodes");
	lua_pushinteger(L, (lua_Integer)st.debug);
	lua_setfield(L, -2, "debug");
	lua_pushinteger(L, (lua_Integer)st.hostid);
	lua_setfield(L, -2, "hostid");
	lua_pushinteger(L, (lua_Integer)st.reass);
	lua_setfield(L, -2, "reass");
	lua_pushinteger(L, (lua_Integer)st.syncookies_active);
	lua_setfield(L, -2, "syncookies_active");
	lua_pushinteger(L, (lua_Integer)st.syncookies_mode);
	lua_setfield(L, -2, "syncookies_mode");
	lua_pushstring(L, st.ifname);
	lua_setfield(L, -2, "ifname");

	c = st.pf_chksum;

	snprintf(
	    hash, sizeof(hash),
	    "%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
	    c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10],
	    c[11], c[12], c[13], c[14], c[15]);

	lua_pushstring(L, hash);
	lua_setfield(L, -2, "checksum");

	lua_newtable(L);
	for (int i = 0; i < PFRES_MAX; i++) {
		lua_pushinteger(L, (lua_Integer)st.counters[i]);
		lua_setfield(L, -2, pfcounternames[i]);
	}
	lua_setfield(L, -2, "counters");

	lua_newtable(L);

	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)st.bcounters[0][0]);
	lua_setfield(L, -2, "bytesin");
	lua_pushinteger(L, (lua_Integer)st.bcounters[0][1]);
	lua_setfield(L, -2, "bytesout");
	lua_setfield(L, -2, "v4");

	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)st.bcounters[1][0]);
	lua_setfield(L, -2, "bytesin");
	lua_pushinteger(L, (lua_Integer)st.bcounters[1][1]);
	lua_setfield(L, -2, "bytesout");
	lua_setfield(L, -2, "v6");

	lua_setfield(L, -2, "bcounters");

	lua_newtable(L);

	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)st.pcounters[0][0][PF_PASS]);
	lua_setfield(L, -2, "packets_in_passed");
	lua_pushinteger(L, (lua_Integer)st.pcounters[0][0][PF_DROP]);
	lua_setfield(L, -2, "packets_in_blocked");
	lua_pushinteger(L, (lua_Integer)st.pcounters[0][1][PF_PASS]);
	lua_setfield(L, -2, "packets_out_passed");
	lua_pushinteger(L, (lua_Integer)st.pcounters[0][1][PF_DROP]);
	lua_setfield(L, -2, "packets_out_blocked");
	lua_setfield(L, -2, "v4");

	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)st.pcounters[1][0][PF_PASS]);
	lua_setfield(L, -2, "packets_in_passed");
	lua_pushinteger(L, (lua_Integer)st.pcounters[1][0][PF_DROP]);
	lua_setfield(L, -2, "packets_in_blocked");
	lua_pushinteger(L, (lua_Integer)st.pcounters[1][1][PF_PASS]);
	lua_setfield(L, -2, "packets_out_passed");
	lua_pushinteger(L, (lua_Integer)st.pcounters[1][1][PF_DROP]);
	lua_setfield(L, -2, "packets_out_blocked");
	lua_setfield(L, -2, "v6");

	lua_setfield(L, -2, "pcounters");
	return 1;
}

/***
Read every state.

The result supports the length operator and indexing from one; each entry
is a state object.
@function pf:states
@treturn userdata states
@raise if the ioctl fails
@usage for i = 1, #h:states() do print(h:states()[i].source) end
*/
static int
pfstates(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_states *ps;

	ps = lua_newuserdata(L, sizeof(*ps));
	luaL_setmetatable(L, PFSTATES_MT);

	memset(ps, 0, sizeof(*ps));

	ps->ps_len = 0;

	if (ioctl(pf->fd, DIOCGETSTATES, ps) == -1)
		luaL_error(L, "DIOCGETSTATES: %s", strerror(errno));

	ps->ps_buf = malloc(ps->ps_len);
	if (!ps->ps_buf)
		luaL_error(L, "DIOCGETSTATES: %s", strerror(errno));

	if (ioctl(pf->fd, DIOCGETSTATES, ps) == -1)
		luaL_error(L, "DIOCGETSTATES: %s", strerror(errno));

	return 1;
}

/***
Kill one state by id.
@function pf:killstates
@int id state id, as the id property reports it
@treturn int states killed
@raise if the ioctl fails
*/
/* TODO: accept a table with more filter args */
static int
pfkillstates(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	lua_Integer id = luaL_checkinteger(L, 2);
	struct pfioc_state_kill psk;

	memset(&psk, 0, sizeof(psk));

	psk.psk_pfcmp.id = htobe64((uint64_t)id);

	if (ioctl(pf->fd, DIOCKILLSTATES, &psk) < 0)
		luaL_error(L, "DIOCKILLSTATES: %s", strerror(errno));

	lua_pushinteger(L, (lua_Integer)psk.psk_killed);

	return 1;
}

/***
Zero the global counters, or the counters of one interface.
@function pf:clearstatus
@string[opt] interface
@raise if the ioctl fails
*/
static int
pfclearstatus(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *ifname = luaL_optstring(L, 2, "");
	struct pfioc_iface pi;

	memset(&pi, 0, sizeof(pi));

	if (strlcpy(pi.pfiio_name, ifname, sizeof(pi.pfiio_name)) >=
	    sizeof(pi.pfiio_name))
		luaL_error(L, "interface name too long");

	if (ioctl(pf->fd, DIOCCLRSTATUS, &pi) < 0)
		luaL_error(L, "DIOCCLRSTATUS: %s", strerror(errno));

	return 0;
}

static int
pfgc(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	if (pf->fd >= 0) {
		(void)close(pf->fd);
		pf->fd = -1;
	}

	return 0;
}

static const luaL_Reg pfmethods[] = {
    {"start",          pfstart         },
    {"stop",           pfstop          },
    {"status",         pfstatus        },
    {"clearstatus",    pfclearstatus   },

    {"states",         pfstates        },
    {"killstates",     pfkillstates    },
    {"getstate",       pfgetstate      },
    {"clearstates",    pfclearstates   },

    {"queues",         pfqueues        },

    {"rules",          pfrules         },
    {"anchors",        pfanchors       },

    {"interfaces",     pfinterfaces    },
    {"limits",         pflimits        },
    {"timeouts",       pftimeouts      },

    {"srcnodes",       pfsrcnodes      },
    {"killsrcnodes",   pfkillsrcnodes  },
    {"clearsrcnodes",  pfclearsrcnodes },

    {"tables",         pftables        },
    {"gettable",       pfgettable      },
    {"addtables",      pfaddtables     },
    {"cleartables",    pfcleartables   },
    {"deletetables",   pfdeletetables  },
    {"clearalltables", pfclearalltables},

    {NULL,             NULL            },
};

static const luaL_Reg pfmeta[] = {
    {"__gc", pfgc},
    {NULL,   NULL},
};

/***
Open /dev/pf.
@function pf.open
@treturn userdata handle
@raise if /dev/pf cannot be opened
@usage local h = pf.open()
*/
static int
pfopen(lua_State *L)
{
	struct luapf *pf;
	int fd;

	fd = open("/dev/pf", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		luaL_error(L, "open /dev/pf: %s", strerror(errno));

	pf = lua_newuserdata(L, sizeof(*pf));
	luaL_setmetatable(L, PF_MT);
	pf->fd = fd;

	return 1;
}

/***
Adopt a descriptor already open on /dev/pf.

Lets a process open /dev/pf while privileged and keep reading after it
drops. The descriptor is checked with DIOCGETSTATUS, and the handle closes
it on collection.
@function pf.openfd
@int fd
@treturn userdata handle
@raise if the descriptor is not /dev/pf
*/
static int
pfopenfd(lua_State *L)
{
	int fd = (int)luaL_checkinteger(L, 1);
	struct luapf *pf;
	struct pf_status st;

	if (fd < 0)
		luaL_error(L, "bad descriptor %d", fd);

	if (ioctl(fd, DIOCGETSTATUS, &st) < 0)
		luaL_error(L, "descriptor %d is not /dev/pf: %s", fd,
		           strerror(errno));

	pf = lua_newuserdata(L, sizeof(*pf));
	luaL_setmetatable(L, PF_MT);
	pf->fd = fd;

	return 1;
}

static const luaL_Reg pflib[] = {
    {"open",   pfopen  },
    {"openfd", pfopenfd},
    {NULL,     NULL    },
};

LUAPF_EXPORT int
luaopen_pf(lua_State *L)
{
	luaL_newlib(L, pflib);

	luaL_newmetatable(L, PF_MT);
	luaL_setfuncs(L, pfmeta, 0);
	luaL_newlib(L, pfmethods);
	lua_setfield(L, -2, "__index");
	lua_pop(L, 1);

	luapf_states_register(L);
	luapf_tables_register(L);
	luapf_rules_register(L);
	luapf_privsep_register(L);

	return 1;
}
