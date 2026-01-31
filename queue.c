#include <errno.h>
#include <string.h>

#include <sys/ioctl.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <net/hfsc.h>
#include <net/fq_codel.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"

int
pfqueues(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	u_int i, nr;
	struct pfioc_queue pq;
	struct pfioc_qstats pqs;
	union {
		struct fqcodel_stats fqc;
		struct hfsc_class_stats hfsc;
	} stats;

	memset(&pq, 0, sizeof(pq));
	memset(&pqs, 0, sizeof(pqs));

	if(ioctl(pf->fd, DIOCGETQUEUES, &pq) < 0)
		luaL_error(L,"DIOCGETQUEUES: %s", strerror(errno));

	nr = pq.nr;

	lua_newtable(L);

	for(i = 0; i < nr; i++){
		pqs.ticket = pq.ticket;
		pqs.nr = i;
		pqs.buf = &stats;
		pqs.nbytes = sizeof(stats);

		if(ioctl(pf->fd, DIOCGETQSTATS, &pqs) < 0)
			luaL_error(L,"DIOCGETQSTATS: %s", strerror(errno));

		lua_newtable(L);
		lua_pushstring(L, pqs.queue.qname);
		lua_setfield(L, -2, "name");
		lua_pushstring(L, pqs.queue.parent);
		lua_setfield(L, -2, "parent");
		lua_pushstring(L, pqs.queue.ifname);
		lua_setfield(L, -2, "ifname");
		lua_pushinteger(L, pqs.queue.qid);
		lua_setfield(L, -2, "qid");
		lua_pushinteger(L, pqs.queue.parent_qid);
		lua_setfield(L, -2, "parent_qid");

		if(pqs.queue.flags & PFQS_FLOWQUEUE){
			lua_pushstring(L, "flow");
			lua_setfield(L, -2, "scheduler");
		} else {
			lua_pushstring(L, "fifo");
			lua_setfield(L, -2, "scheduler");
		}

		lua_pushinteger(L, stats.hfsc.qlength);
		lua_setfield(L, -2, "queue_length");
		lua_pushinteger(L, stats.hfsc.qlimit);
		lua_setfield(L, -2, "queue_limit");

		lua_pushinteger(L, stats.hfsc.xmit_cnt.packets);
		lua_setfield(L, -2, "transmit_packets");
		lua_pushinteger(L, stats.hfsc.xmit_cnt.bytes);
		lua_setfield(L, -2, "transmit_bytes");

		lua_pushinteger(L, stats.hfsc.drop_cnt.packets);
		lua_setfield(L, -2, "drop_packets");
		lua_pushinteger(L, stats.hfsc.drop_cnt.bytes);
		lua_setfield(L, -2, "drop_bytes");

		lua_rawseti(L, -2, i+1);
	}

	return 1;
}

