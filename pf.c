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

static const char *const pfcounternames[] = PFRES_NAMES;
static const char *const pflimitcounternames[] = LCNT_NAMES;

/*
 * pfvar.h names the indices of these three arrays but ships no names macro
 * beside them, so every label is tied to the kernel's own index macro. pfctl
 * builds all three of its rows from the state table names, so take each set
 * from the macros of its own array instead.
 */
static const char *const pfstatecounternames[FCNT_MAX] = {
    [FCNT_STATE_SEARCH] = "searches",
    [FCNT_STATE_INSERT] = "inserts",
    [FCNT_STATE_REMOVALS] = "removals",
};

static const char *const pfsrcnodecounternames[SCNT_MAX] = {
    [SCNT_SRC_NODE_SEARCH] = "searches",
    [SCNT_SRC_NODE_INSERT] = "inserts",
    [SCNT_SRC_NODE_REMOVALS] = "removals",
};

static const char *const pffragmentcounternames[NCNT_MAX] = {
    [NCNT_FRAG_SEARCH] = "searches",
    [NCNT_FRAG_INSERT] = "inserts",
    [NCNT_FRAG_REMOVALS] = "removals",
};

/***
Read and control the pf packet filter.

Every call raises a lua error on failure, so wrap them in pcall where an
error is expected. Opening /dev/pf needs root, but the kernel gates the
ioctls on the open mode rather than the uid: a read-only descriptor keeps
working after a privilege drop and is refused every write.
@module pf
@usage local pf = require("pf")
*/

/* Idempotent, so __gc, __close and pf:close can all land on it. */
static void
pfrelease(struct luapf *pf)
{
	if (pf->fd >= 0) {
		(void)close(pf->fd);
		pf->fd = -1;
	}
}

/*
 * An explicit close leaves a live handle behind with no descriptor, so
 * every method has to refuse it rather than hand ioctl a -1, or a number
 * the kernel has since given to some other file.
 */
static struct luapf *
checkpf(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	if (pf->fd < 0)
		luaL_error(L, "pf handle closed");

	return pf;
}

/***
Start pf.
@function pf:start
@raise if the ioctl fails
*/
static int
pfstart(lua_State *L)
{
	struct luapf *pf = checkpf(L);
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
	struct luapf *pf = checkpf(L);
	int x = 0;

	if (ioctl(pf->fd, DIOCSTOP, &x) < 0)
		luaL_error(L, "DIOCSTOP: %s", strerror(errno));

	return 0;
}

/* Every counter array in struct pf_status is read the same way. */
static void
pushcounters(lua_State *L, const char *field, const char *const *names,
             const u_int64_t *values, size_t n)
{
	lua_newtable(L);

	for (size_t i = 0; i < n; i++) {
		lua_pushinteger(L, (lua_Integer)values[i]);
		lua_setfield(L, -2, names[i]);
	}

	lua_setfield(L, -2, field);
}

/***
Read the global status.

The result holds running, since, states, states_halfopen, src_nodes,
fragments, debug, hostid, reass, syncookies_active, syncookies_mode,
ifname and checksum, plus the syncookies_inflight pair, the
syncookies_watermarks table and the counters, lcounters, fcounters,
scounters, ncounters, bcounters and pcounters tables.

counters is keyed by drop reason, lcounters by limit, and fcounters,
scounters and ncounters each hold searches, inserts and removals for the
state table, the source node table and the fragment cache.

since is not a wall clock time: it counts from when the machine booted,
the way pfctl reads it to work out how long PF has been running. hostid
is byte swapped into host order, so it reads as pfctl prints it.
syncookies_watermarks holds the adaptive syncookie state counts pfctl
prints as start and end.
@function pf:status
@treturn table status
@raise if either ioctl fails
*/
static int
pfstatus(lua_State *L)
{
	struct luapf *pf = checkpf(L);
	struct pf_status st;
	struct pfioc_synflwats wats;
	char hash[PF_MD5_DIGEST_LENGTH * 2 + 1];
	const uint8_t *c;

	if (ioctl(pf->fd, DIOCGETSTATUS, &st) < 0)
		luaL_error(L, "DIOCGETSTATUS: %s", strerror(errno));

	/* The watermarks live behind their own ioctl, but they describe the
	 * same syncookie state the status table counts, so report them
	 * together. A read-only descriptor answers this one too. */
	memset(&wats, 0, sizeof(wats));

	if (ioctl(pf->fd, DIOCGETSYNFLWATS, &wats) < 0)
		luaL_error(L, "DIOCGETSYNFLWATS: %s", strerror(errno));

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
	lua_pushinteger(L, (lua_Integer)st.fragments);
	lua_setfield(L, -2, "fragments");
	lua_pushinteger(L, (lua_Integer)st.debug);
	lua_setfield(L, -2, "debug");
	/* The kernel keeps this in network order; pfctl prints it swapped,
	 * and two tools naming one host differently helps nobody. */
	lua_pushinteger(L, (lua_Integer)ntohl(st.hostid));
	lua_setfield(L, -2, "hostid");
	lua_pushinteger(L, (lua_Integer)st.reass);
	lua_setfield(L, -2, "reass");
	lua_pushinteger(L, (lua_Integer)st.syncookies_active);
	lua_setfield(L, -2, "syncookies_active");
	lua_pushinteger(L, (lua_Integer)st.syncookies_mode);
	lua_setfield(L, -2, "syncookies_mode");

	/* Two rotating buckets of unACKed cookies, not two named numbers, so
	 * hand them over as the array the kernel keeps. */
	lua_newtable(L);
	for (int i = 0; i < 2; i++) {
		lua_pushinteger(L, (lua_Integer)st.syncookies_inflight[i]);
		lua_rawseti(L, -2, i + 1);
	}
	lua_setfield(L, -2, "syncookies_inflight");

	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)wats.hiwat);
	lua_setfield(L, -2, "hiwat");
	lua_pushinteger(L, (lua_Integer)wats.lowat);
	lua_setfield(L, -2, "lowat");
	lua_setfield(L, -2, "syncookies_watermarks");

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

	pushcounters(L, "counters", pfcounternames, st.counters, PFRES_MAX);
	pushcounters(L, "lcounters", pflimitcounternames, st.lcounters,
	             LCNT_MAX);
	pushcounters(L, "fcounters", pfstatecounternames, st.fcounters,
	             FCNT_MAX);
	pushcounters(L, "scounters", pfsrcnodecounternames, st.scounters,
	             SCNT_MAX);
	pushcounters(L, "ncounters", pffragmentcounternames, st.ncounters,
	             NCNT_MAX);

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

	/* pcounters carries a third slot per direction for PF_SCRUB, which
	 * the kernel never writes: it counts every packet as passed or
	 * dropped. Reporting a number that is always zero would only invite
	 * someone to look for meaning in it. */
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
	struct luapf *pf = checkpf(L);
	struct pfioc_states *ps;

	ps = lua_newuserdata(L, sizeof(*ps));
	luaL_setmetatable(L, PFSTATES_MT);

	memset(ps, 0, sizeof(*ps));

	ps->ps_len = 0;

	if (ioctl(pf->fd, DIOCGETSTATES, ps) == -1)
		luaL_error(L, "DIOCGETSTATES: %s", strerror(errno));

	/* No states: leave a null buffer, which reads as an empty list. */
	if (ps->ps_len == 0)
		return 1;

	ps->ps_buf = malloc(ps->ps_len);
	if (!ps->ps_buf)
		luaL_error(L, "DIOCGETSTATES: out of memory");

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
	struct luapf *pf = checkpf(L);
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
	struct luapf *pf = checkpf(L);
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

/***
Close the descriptor.

Every later call on the handle raises. Collection closes an open handle
anyway, but that happens at an unpredictable time, and descriptors run
out.
@function pf:close
*/
static int
pfclose(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	pfrelease(pf);

	return 0;
}

/*
 * __gc and __close both run on a handle that may already be released, and
 * neither may raise. They must not touch another userdata's descriptor
 * either, because finalizer order is unspecified.
 */
static int
pfgc(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);

	pfrelease(pf);

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

    {"close",          pfclose         },

    {NULL,             NULL            },
};

static const luaL_Reg pfmeta[] = {
    {"__gc",    pfgc},
    {"__close", pfgc},
    {NULL,      NULL},
};

/***
Open /dev/pf.

The mode is "rw" by default. A "r" handle answers every read ioctl and is
refused every write, which is what a process wants to keep across a
privilege drop.
@function pf.open
@string[opt="rw"] mode "r" or "rw"
@treturn userdata handle
@raise if the mode is unknown, or /dev/pf cannot be opened
@usage local h = pf.open("r")
*/
static int
pfopen(lua_State *L)
{
	const char *mode = luaL_optstring(L, 1, "rw");
	struct luapf *pf;
	int flags;

	if (strcmp(mode, "r") == 0)
		flags = O_RDONLY;
	else if (strcmp(mode, "rw") == 0)
		flags = O_RDWR;
	else
		return luaL_error(L, "bad mode \"%s\", want \"r\" or \"rw\"",
		                  mode);

	/*
	 * The userdata comes first, with the metatable that arms __gc, so a
	 * failure past this point cannot strand an open descriptor.
	 */
	pf = lua_newuserdata(L, sizeof(*pf));
	pf->fd = -1;
	luaL_setmetatable(L, PF_MT);

	pf->fd = open("/dev/pf", flags | O_CLOEXEC);
	if (pf->fd < 0)
		luaL_error(L, "open /dev/pf: %s", strerror(errno));

	return 1;
}

/***
Adopt a descriptor already open on /dev/pf.

Lets a process open /dev/pf while privileged and keep reading after it
drops. The descriptor is checked with DIOCGETSTATUS and duplicated; the
caller keeps its own and stays responsible for closing it.
@function pf.openfd
@int fd
@treturn userdata handle
@raise if the descriptor is not /dev/pf, or cannot be duplicated
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

	/*
	 * The probe says what the descriptor is, never who owns it. Own a
	 * duplicate instead, so __gc cannot close a descriptor the caller
	 * still uses and a reused number cannot be written by mistake.
	 */
	pf = lua_newuserdata(L, sizeof(*pf));
	pf->fd = -1;
	luaL_setmetatable(L, PF_MT);

	pf->fd = fcntl(fd, F_DUPFD_CLOEXEC, 0);
	if (pf->fd < 0)
		luaL_error(L, "dup descriptor %d: %s", fd, strerror(errno));

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
