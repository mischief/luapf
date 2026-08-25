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

/*
 * Both arms are reported, but percent is always zero on this OpenBSD: the
 * parser refuses one ("no bandwidth in % yet"). There is no rate for it to
 * be a percentage of either -- PF is never told what a link can carry, so
 * a root queue's bandwidth is the operator asserting it, not a measurement,
 * and every child is relative to that assertion.
 */
static void
pushbwspec(lua_State *L, const struct pf_queue_bwspec *bw, const char *name)
{
	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)bw->absolute);
	lua_setfield(L, -2, "absolute");
	lua_pushinteger(L, (lua_Integer)bw->percent);
	lua_setfield(L, -2, "percent");
	lua_setfield(L, -2, name);
}

/*
 * A service curve is two slopes and the time the first one runs for. The
 * burst of "burst X for Nms" is the first slope, so it needs no field of
 * its own.
 */
static void
pushscspec(lua_State *L, const struct pf_queue_scspec *sc, const char *name)
{
	lua_newtable(L);
	pushbwspec(L, &sc->m1, "m1");
	pushbwspec(L, &sc->m2, "m2");
	lua_pushinteger(L, (lua_Integer)sc->d);
	lua_setfield(L, -2, "d");
	lua_setfield(L, -2, name);
}

static void
pushfqspec(lua_State *L, const struct pf_queue_fqspec *fq)
{
	lua_newtable(L);
	lua_pushinteger(L, (lua_Integer)fq->flows);
	lua_setfield(L, -2, "flows");
	lua_pushinteger(L, (lua_Integer)fq->quantum);
	lua_setfield(L, -2, "quantum");
	lua_pushinteger(L, (lua_Integer)fq->target);
	lua_setfield(L, -2, "target");
	lua_pushinteger(L, (lua_Integer)fq->interval);
	lua_setfield(L, -2, "interval");
	lua_setfield(L, -2, "flowqueue");
}

/***
Read every queue, its configuration and its statistics.

Each entry holds these identity and configuration fields:

 - `name`, `parent`, `ifname`, `qid`, `parent_qid`
 - `scheduler`, the discipline that served the queue and produced the
   statistics below, either `"hfsc"` or `"fqcodel"`
 - `flowqueue_class`, true when the ruleset asked for a flow queue with the
   `flows` keyword. Only a flow queue without a parent is served by
   fq-codel, so this is not the same thing as `scheduler`
 - `default_queue`, true for the queue that takes packets no other queue
   matched, and `root_class`, true for the root of an HFSC tree
 - `flags`, the raw kernel flag word behind the two booleans above
 - `qlimit`, the packet limit the ruleset asked for
 - `linkshare` (pf.conf `bandwidth`), `realtime` (`min`) and `upperlimit`
   (`max`), each a service curve `{ m1 = { absolute, percent },
   m2 = { absolute, percent }, d }`. `m1` and `d` carry `burst X for Nms`.
   `percent` is always zero: pf.conf takes no percentage today, and PF is
   never told what a link carries, so a rate is whatever the ruleset said
 - `flowqueue`, the flow queue parameters `{ flows, quantum, target,
   interval }`. `flowqueue.flows` is the configured number of flows, which
   is not the `flows` statistic below

and these statistics:

 - `queue_length`, `queue_limit` as the scheduler holds them
 - `transmit_packets`, `transmit_bytes`, `drop_packets`, `drop_bytes`

A queue that fq-codel served also holds `flows`, the number of flows in use
right now, plus the codel delay parameters in use, `codel_target` and
`codel_interval`, and `delay_sum` and `delay_sum_squared`, the microsecond
sums pfctl averages to print queue delay.
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
		int fqcodel;

		memset(&stats, 0, sizeof(stats));

		pqs.ticket = pq.ticket;
		pqs.nr = i;
		pqs.buf = &stats;
		pqs.nbytes = sizeof(stats);

		if (ioctl(pf->fd, DIOCGETQSTATS, &pqs) < 0)
			luaL_error(L, "DIOCGETQSTATS: %s", strerror(errno));

		lua_newtable(L);
		/*
		 * A kernel name field can fill its array with no NUL, so
		 * bound every such read to the size of the array itself.
		 */
		lua_pushlstring(
		    L, pqs.queue.qname,
		    strnlen(pqs.queue.qname, sizeof(pqs.queue.qname)));
		lua_setfield(L, -2, "name");
		lua_pushlstring(
		    L, pqs.queue.parent,
		    strnlen(pqs.queue.parent, sizeof(pqs.queue.parent)));
		lua_setfield(L, -2, "parent");
		lua_pushlstring(
		    L, pqs.queue.ifname,
		    strnlen(pqs.queue.ifname, sizeof(pqs.queue.ifname)));
		lua_setfield(L, -2, "ifname");
		lua_pushinteger(L, (lua_Integer)pqs.queue.qid);
		lua_setfield(L, -2, "qid");
		lua_pushinteger(L, (lua_Integer)pqs.queue.parent_qid);
		lua_setfield(L, -2, "parent_qid");

		lua_pushinteger(L, (lua_Integer)pqs.queue.flags);
		lua_setfield(L, -2, "flags");
		lua_pushboolean(L, (pqs.queue.flags & PFQS_FLOWQUEUE) != 0);
		lua_setfield(L, -2, "flowqueue_class");
		lua_pushboolean(L, (pqs.queue.flags & PFQS_DEFAULT) != 0);
		lua_setfield(L, -2, "default_queue");
		lua_pushboolean(L, (pqs.queue.flags & PFQS_ROOTCLASS) != 0);
		lua_setfield(L, -2, "root_class");

		/*
		 * The scheduler copies this into the statistics as
		 * queue_limit, but that is the scheduler's own value. Report
		 * what the ruleset asked for as well.
		 */
		lua_pushinteger(L, (lua_Integer)pqs.queue.qlimit);
		lua_setfield(L, -2, "qlimit");

		pushscspec(L, &pqs.queue.linkshare, "linkshare");
		pushscspec(L, &pqs.queue.realtime, "realtime");
		pushscspec(L, &pqs.queue.upperlimit, "upperlimit");
		pushfqspec(L, &pqs.queue.flowqueue);

		/*
		 * The kernel picks the arm of the statistics union with three
		 * conditions, and all three have to hold before the fq-codel
		 * fields mean anything. A flow queue with a parent is served
		 * by HFSC, so reading flows out of it would really read
		 * hfsc_class_stats.period.
		 */
		fqcodel = (pqs.queue.flags & PFQS_FLOWQUEUE) &&
		          pqs.queue.parent_qid == 0 &&
		          !(pqs.queue.flags & PFQS_ROOTCLASS);

		if (fqcodel) {
			lua_pushstring(L, "fqcodel");
			lua_setfield(L, -2, "scheduler");

			pushcounters(L, stats.fqc.qlength, stats.fqc.qlimit,
			             stats.fqc.xmit_cnt.packets,
			             stats.fqc.xmit_cnt.bytes,
			             stats.fqc.drop_cnt.packets,
			             stats.fqc.drop_cnt.bytes);

			lua_pushinteger(L, (lua_Integer)stats.fqc.flows);
			lua_setfield(L, -2, "flows");
			lua_pushinteger(L, (lua_Integer)stats.fqc.target);
			lua_setfield(L, -2, "codel_target");
			lua_pushinteger(L, (lua_Integer)stats.fqc.interval);
			lua_setfield(L, -2, "codel_interval");
			lua_pushinteger(L, (lua_Integer)stats.fqc.delaysum);
			lua_setfield(L, -2, "delay_sum");
			lua_pushinteger(L, (lua_Integer)stats.fqc.delaysumsq);
			lua_setfield(L, -2, "delay_sum_squared");
		} else {
			lua_pushstring(L, "hfsc");
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
