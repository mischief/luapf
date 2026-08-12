/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <net/fq_codel.h>
#include <net/hfsc.h>
#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "banned.h"

/***
@module pf
*/

union queuestats {
	struct fqcodel_stats fqc;
	struct hfsc_class_stats hfsc;
};

static void
pushcounters(lua_State *L, uint64_t qlength, uint64_t qlimit,
             uint64_t xmitpackets, uint64_t xmitbytes, uint64_t droppackets,
             uint64_t dropbytes)
{
	lua_pushinteger(L, (lua_Integer)qlength);
	lua_setfield(L, -2, "queue_length");
	lua_pushinteger(L, (lua_Integer)qlimit);
	lua_setfield(L, -2, "queue_limit");

	lua_pushinteger(L, (lua_Integer)xmitpackets);
	lua_setfield(L, -2, "transmit_packets");
	lua_pushinteger(L, (lua_Integer)xmitbytes);
	lua_setfield(L, -2, "transmit_bytes");

	lua_pushinteger(L, (lua_Integer)droppackets);
	lua_setfield(L, -2, "drop_packets");
	lua_pushinteger(L, (lua_Integer)dropbytes);
	lua_setfield(L, -2, "drop_bytes");
}

/***
Read every queue and its statistics.

Each entry holds name, parent, ifname, qid, parent_qid, scheduler,
queue_length, queue_limit, transmit_packets, transmit_bytes,
drop_packets and drop_bytes, plus flows for a flow queue.
@function pf:queues
@treturn table array of queue tables
@raise if the ioctl fails
*/
int
pfqueues(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct pfioc_queue pq;
	struct pfioc_qstats pqs;
	union queuestats stats;
	unsigned nr;

	memset(&pq, 0, sizeof(pq));
	memset(&pqs, 0, sizeof(pqs));

	if (ioctl(pf->fd, DIOCGETQUEUES, &pq) < 0)
		luaL_error(L, "DIOCGETQUEUES: %s", strerror(errno));

	nr = pq.nr;

	lua_newtable(L);

	for (unsigned i = 0; i < nr; i++) {
		memset(&stats, 0, sizeof(stats));

		pqs.ticket = pq.ticket;
		pqs.nr = i;
		pqs.buf = &stats;
		pqs.nbytes = sizeof(stats);

		if (ioctl(pf->fd, DIOCGETQSTATS, &pqs) < 0)
			luaL_error(L, "DIOCGETQSTATS: %s", strerror(errno));

		lua_newtable(L);
		lua_pushstring(L, pqs.queue.qname);
		lua_setfield(L, -2, "name");
		lua_pushstring(L, pqs.queue.parent);
		lua_setfield(L, -2, "parent");
		lua_pushstring(L, pqs.queue.ifname);
		lua_setfield(L, -2, "ifname");
		lua_pushinteger(L, (lua_Integer)pqs.queue.qid);
		lua_setfield(L, -2, "qid");
		lua_pushinteger(L, (lua_Integer)pqs.queue.parent_qid);
		lua_setfield(L, -2, "parent_qid");

		/* The scheduler picks which arm of the union the kernel wrote.
		 */
		if (pqs.queue.flags & PFQS_FLOWQUEUE) {
			lua_pushstring(L, "flow");
			lua_setfield(L, -2, "scheduler");

			pushcounters(L, stats.fqc.qlength, stats.fqc.qlimit,
			             stats.fqc.xmit_cnt.packets,
			             stats.fqc.xmit_cnt.bytes,
			             stats.fqc.drop_cnt.packets,
			             stats.fqc.drop_cnt.bytes);

			lua_pushinteger(L, (lua_Integer)stats.fqc.flows);
			lua_setfield(L, -2, "flows");
		} else {
			lua_pushstring(L, "fifo");
			lua_setfield(L, -2, "scheduler");

			pushcounters(L, stats.hfsc.qlength, stats.hfsc.qlimit,
			             stats.hfsc.xmit_cnt.packets,
			             stats.hfsc.xmit_cnt.bytes,
			             stats.hfsc.drop_cnt.packets,
			             stats.hfsc.drop_cnt.bytes);
		}

		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}
