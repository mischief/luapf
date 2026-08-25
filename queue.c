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
/*
 * A queue entry is a lua table rather than userdata, which is no barrier
 * to a metamethod. This renders what pfctl prints for one queue.
 */
static void
addbwspec(lua_State *L, luaL_Buffer *b, const char *prefix, int idx)
{
	static const char unit[] = " KMG";
	lua_Integer pct, abs;
	char num[32];
	int i;

	lua_getfield(L, idx, "percent");
	pct = lua_tointeger(L, -1);
	lua_getfield(L, idx, "absolute");
	abs = lua_tointeger(L, -1);
	lua_pop(L, 2);

	if (pct != 0) {
		snprintf(num, sizeof(num), "%s%lld%%", prefix, (long long)pct);
		luaL_addstring(b, num);
	} else if (abs != 0) {
		for (i = 0; abs >= 1000 && i < 3 && (abs % 1000 == 0); i++)
			abs /= 1000;
		snprintf(num, sizeof(num), "%s%lld%c", prefix, (long long)abs,
		         unit[i]);
		luaL_addstring(b, num);
	}
}

/* A curve is its second slope, plus the first as a burst when one is set. */
static void
addscspec(lua_State *L, luaL_Buffer *b, const char *prefix, const char *field)
{
	char num[32];
	lua_Integer d;

	lua_getfield(L, 1, field);
	if (!lua_istable(L, -1))
		luaL_error(L, "%s is not a table", field);
	lua_getfield(L, -1, "m2");
	addbwspec(L, b, prefix, lua_gettop(L));
	lua_pop(L, 1);

	lua_getfield(L, -1, "d");
	d = lua_tointeger(L, -1);
	lua_pop(L, 1);

	if (d != 0) {
		luaL_addstring(b, " burst ");
		lua_getfield(L, -1, "m1");
		addbwspec(L, b, "", lua_gettop(L));
		lua_pop(L, 1);
		snprintf(num, sizeof(num), " for %lldms", (long long)d);
		luaL_addstring(b, num);
	}
	lua_pop(L, 1);
}

static int
hasbandwidth(lua_State *L)
{
	lua_Integer a1, a2;

	lua_getfield(L, 1, "linkshare");
	lua_getfield(L, -1, "m1");
	lua_getfield(L, -1, "absolute");
	a1 = lua_tointeger(L, -1);
	lua_pop(L, 2);
	lua_getfield(L, -1, "m2");
	lua_getfield(L, -1, "absolute");
	a2 = lua_tointeger(L, -1);
	lua_pop(L, 3);

	return a1 != 0 || a2 != 0;
}

/*
 * A metamethod is reachable through getmetatable, so it can be called
 * with anything at all. Accept only a table this module gave this
 * metatable, and check the fields it reads, which stay writable.
 */
static const char *
queuestring(lua_State *L, const char *field)
{
	const char *str;

	lua_getfield(L, 1, field);
	str = lua_tostring(L, -1);
	if (str == NULL)
		luaL_error(L, "%s is not a string", field);
	lua_pop(L, 1);

	return str;
}

static int
queue_tostring(lua_State *L)
{
	luaL_Buffer b;
	char num[64];
	const char *str;

	if (!lua_getmetatable(L, 1)) {
		luaL_error(L, "expected a queue");
		return 0;
	}
	luaL_getmetatable(L, "PFQUEUEMT");
	if (!lua_rawequal(L, -1, -2))
		luaL_error(L, "expected a queue");
	lua_pop(L, 2);

	luaL_buffinit(L, &b);

	luaL_addstring(&b, "queue ");
	luaL_addstring(&b, queuestring(L, "name"));

	str = queuestring(L, "parent");
	if (*str != '\0') {
		luaL_addstring(&b, " parent ");
		luaL_addstring(&b, str);
	} else {
		str = queuestring(L, "ifname");
		if (*str != '\0') {
			luaL_addstring(&b, " on ");
			luaL_addstring(&b, str);
		}
	}

	lua_getfield(L, 1, "flowqueue_class");
	if (lua_toboolean(L, -1)) {
		lua_getfield(L, 1, "flowqueue");
		lua_getfield(L, -1, "flows");
		snprintf(num, sizeof(num), " flows %lld",
		         (long long)lua_tointeger(L, -1));
		luaL_addstring(&b, num);
		lua_pop(L, 1);
		lua_getfield(L, -1, "quantum");
		if (lua_tointeger(L, -1) > 0) {
			snprintf(num, sizeof(num), " quantum %lld",
			         (long long)lua_tointeger(L, -1));
			luaL_addstring(&b, num);
		}
		lua_pop(L, 2);
	}
	lua_pop(L, 1);

	if (hasbandwidth(L)) {
		addscspec(L, &b, " bandwidth ", "linkshare");
		addscspec(L, &b, ", min ", "realtime");
		addscspec(L, &b, ", max ", "upperlimit");
	}

	lua_getfield(L, 1, "default_queue");
	if (lua_toboolean(L, -1))
		luaL_addstring(&b, " default");
	lua_pop(L, 1);

	lua_getfield(L, 1, "qlimit");
	if (lua_tointeger(L, -1) != 0) {
		snprintf(num, sizeof(num), " qlimit %lld",
		         (long long)lua_tointeger(L, -1));
		luaL_addstring(&b, num);
	}
	lua_pop(L, 1);

	luaL_pushresult(&b);

	return 1;
}

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

		if (luaL_newmetatable(L, "PFQUEUEMT")) {
			lua_pushcfunction(L, queue_tostring);
			lua_setfield(L, -2, "__tostring");
		}
		lua_setmetatable(L, -2);

		lua_rawseti(L, -2, i + 1);
	}

	return 1;
}
