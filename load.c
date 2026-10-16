/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <pwd.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "banned.h"

/***
@module pf
*/

/*
 * h:load() writes rulesets in one transaction, the way pfctl -f does.
 * pf.dsl builds the table it takes; each rule there is already expanded
 * and has pfctl's defaults filled in, so this file only copies fields.
 */

struct loadctx {
	lua_State *L;
	int fd;
	struct pfioc_trans trans;
	struct pfioc_trans_e *te;
	int nte;
	bool begun;
	char where[64];
};

static int
loadfail(struct loadctx *c, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

/* Roll the transaction back and raise an error that says where. */
static int
loadfail(struct loadctx *c, const char *fmt, ...)
{
	char msg[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);

	if (c->begun) {
		(void)ioctl(c->fd, DIOCXROLLBACK, &c->trans);
		c->begun = false;
	}

	/* lua_error, not luaL_error: where already names the Lua line. */
	lua_pushfstring(c->L, "%s%s%s", c->where, c->where[0] ? ": " : "", msg);
	return lua_error(c->L);
}

static const char *
optstring(lua_State *L, int idx, const char *k)
{
	const char *s;

	lua_getfield(L, idx, k);
	s = lua_tostring(L, -1);
	lua_pop(L, 1);

	return s;
}

static lua_Integer
optint(lua_State *L, int idx, const char *k, lua_Integer def)
{
	lua_Integer v = def;

	lua_getfield(L, idx, k);
	if (lua_isinteger(L, -1))
		v = lua_tointeger(L, -1);
	lua_pop(L, 1);

	return v;
}

static bool
optbool(lua_State *L, int idx, const char *k)
{
	bool v;

	lua_getfield(L, idx, k);
	v = lua_toboolean(L, -1);
	lua_pop(L, 1);

	return v;
}

static void
copyname(struct loadctx *c, char *dst, size_t size, const char *src,
         const char *what)
{
	if (src == NULL)
		return;
	if (strlcpy(dst, src, size) >= size)
		loadfail(c, "%s too long: %s", what, src);
}

static sa_family_t
afnum(const char *af)
{
	if (af == NULL)
		return 0;
	if (strcmp(af, "inet") == 0)
		return AF_INET;
	if (strcmp(af, "inet6") == 0)
		return AF_INET6;
	return 0;
}

static void
setmask(struct pf_addr *m, int bits)
{
	memset(m, 0, sizeof(*m));
	for (int i = 0; i < 4 && bits > 0; i++, bits -= 32)
		m->addr32[i] = bits >= 32 ? 0xffffffff
		                          : htonl(0xffffffffU << (32 - bits));
}

/* The address table at idx, as pf.dsl and rule.spec write it. */
static void
encodeaddr(struct loadctx *c, int idx, struct pf_addr_wrap *aw,
           sa_family_t af)
{
	lua_State *L = c->L;
	const char *type = optstring(L, idx, "type");

	memset(aw, 0, sizeof(*aw));
	aw->type = PF_ADDR_ADDRMASK;

	if (type == NULL || strcmp(type, "any") == 0)
		return;

	if (strcmp(type, "addr") == 0) {
		const char *s = optstring(L, idx, "addr");
		sa_family_t a = afnum(optstring(L, idx, "af"));
		int bits = (int)optint(L, idx, "bits", a == AF_INET ? 32 : 128);

		if (s == NULL || a == 0 || inet_pton(a, s, &aw->v.a.addr) != 1)
			loadfail(c, "bad address %s", s ? s : "(none)");
		setmask(&aw->v.a.mask, bits);
	} else if (strcmp(type, "dyn") == 0) {
		aw->type = PF_ADDR_DYNIFTL;
		copyname(c, aw->v.ifname, sizeof(aw->v.ifname),
		         optstring(L, idx, "name"), "interface name");
		if (optbool(L, idx, "network"))
			aw->iflags |= PFI_AFLAG_NETWORK;
		if (optbool(L, idx, "broadcast"))
			aw->iflags |= PFI_AFLAG_BROADCAST;
		if (optbool(L, idx, "peer"))
			aw->iflags |= PFI_AFLAG_PEER;
		if (optbool(L, idx, "first"))
			aw->iflags |= PFI_AFLAG_NOALIAS;
		/* pfctl masks a dynamic address to the rule's family. */
		setmask(&aw->v.a.mask, af == AF_INET ? 32 : 128);
	} else if (strcmp(type, "table") == 0) {
		aw->type = PF_ADDR_TABLE;
		copyname(c, aw->v.tblname, sizeof(aw->v.tblname),
		         optstring(L, idx, "name"), "table name");
	} else {
		loadfail(c, "cannot load a %s address", type);
	}
}

static uint8_t
opcode(struct loadctx *c, const char *op)
{
	static const struct {
		const char *name;
		uint8_t op;
	} ops[] = {
	    {"=",  PF_OP_EQ },
	    {"!=", PF_OP_NE },
	    {"<",  PF_OP_LT },
	    {"<=", PF_OP_LE },
	    {">",  PF_OP_GT },
	    {">=", PF_OP_GE },
	    {"><", PF_OP_IRG},
	    {"<>", PF_OP_XRG},
	    {":",  PF_OP_RRG},
	};

	if (op == NULL)
		return PF_OP_NONE;
	for (size_t i = 0; i < sizeof(ops) / sizeof(ops[0]); i++)
		if (strcmp(ops[i].name, op) == 0)
			return ops[i].op;
	loadfail(c, "unknown port operator %s", op);
	return PF_OP_NONE;
}

static void
encoderuleaddr(struct loadctx *c, int idx, const char *k,
               struct pf_rule_addr *ra, sa_family_t af)
{
	lua_State *L = c->L;
	int t;

	lua_getfield(L, idx, k);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	t = lua_gettop(L);
	encodeaddr(c, t, &ra->addr, af);
	ra->neg = optbool(L, t, "neg");
	lua_getfield(L, t, "port");
	if (lua_istable(L, -1)) {
		int p = lua_gettop(L);

		ra->port_op = opcode(c, optstring(L, p, "op"));
		ra->port[0] = htons((uint16_t)optint(L, p, "lo", 0));
		ra->port[1] = htons((uint16_t)optint(L, p, "hi", 0));
	}
	lua_pop(L, 2);
}

static uint8_t
pooltype(struct loadctx *c, const char *m)
{
	if (m == NULL)
		return PF_POOL_NONE;
	if (strcmp(m, "round-robin") == 0)
		return PF_POOL_ROUNDROBIN;
	if (strcmp(m, "random") == 0)
		return PF_POOL_RANDOM;
	if (strcmp(m, "source-hash") == 0)
		return PF_POOL_SRCHASH;
	if (strcmp(m, "bitmask") == 0)
		return PF_POOL_BITMASK;
	if (strcmp(m, "least-states") == 0)
		return PF_POOL_LEASTSTATES;
	loadfail(c, "unknown pool method %s", m);
	return PF_POOL_NONE;
}

static void
encodepool(struct loadctx *c, int idx, const char *k, struct pf_pool *p,
           sa_family_t af)
{
	lua_State *L = c->L;
	int t;

	lua_getfield(L, idx, k);
	if (lua_isnil(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	t = lua_gettop(L);
	encodeaddr(c, t, &p->addr, af);
	p->proxy_port[0] = (uint16_t)optint(L, t, "port_lo", 0);
	p->proxy_port[1] = (uint16_t)optint(L, t, "port_hi", 0);
	p->port_op = opcode(c, optstring(L, t, "port_op"));
	p->opts = pooltype(c, optstring(L, t, "method"));
	if (optbool(L, t, "sticky"))
		p->opts |= PF_POOL_STICKYADDR;
	/* pfctl makes up a key when source-hash is given none. */
	if ((p->opts & PF_POOL_TYPEMASK) == PF_POOL_SRCHASH)
		arc4random_buf(&p->key, sizeof(p->key));
	lua_pop(L, 1);
}

static void
encodestate(struct loadctx *c, int idx, struct pf_rule *r)
{
	lua_State *L = c->L;
	int t;

	lua_getfield(L, idx, "state");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	t = lua_gettop(L);

	r->keep_state = (uint8_t)optint(L, t, "keep", 0);
	r->max_states = (uint32_t)optint(L, t, "max", 0);
	r->max_src_states = (uint32_t)optint(L, t, "max_src_states", 0);
	r->max_src_nodes = (uint32_t)optint(L, t, "max_src_nodes", 0);
	r->max_src_conn = (uint32_t)optint(L, t, "max_src_conn", 0);

	lua_getfield(L, t, "max_src_conn_rate");
	if (lua_istable(L, -1)) {
		int m = lua_gettop(L);

		r->max_src_conn_rate.limit = (uint32_t)optint(L, m, "limit", 0);
		r->max_src_conn_rate.seconds =
		    (uint32_t)optint(L, m, "seconds", 0);
	}
	lua_pop(L, 1);

	copyname(c, r->overload_tblname, sizeof(r->overload_tblname),
	         optstring(L, t, "overload"), "overload table name");
	lua_getfield(L, t, "flush");
	if (lua_type(L, -1) == LUA_TSTRING)
		r->flush = PF_FLUSH | PF_FLUSH_GLOBAL;
	else if (lua_toboolean(L, -1))
		r->flush = PF_FLUSH;
	lua_pop(L, 1);

	lua_getfield(L, t, "timeouts");
	if (lua_istable(L, -1)) {
		int m = lua_gettop(L);

		lua_pushnil(L);
		while (lua_next(L, m) != 0) {
			const char *name = lua_tostring(L, -2);
			int i = name ? luapf_timeout_index(name) : -1;

			if (i < 0 || !lua_isinteger(L, -1))
				loadfail(c, "bad state timeout %s",
				         name ? name : "?");
			r->timeout[i] = (uint32_t)lua_tointeger(L, -1);
			lua_pop(L, 1);
		}
	}
	lua_pop(L, 2);
}

static void
encodelimiter(struct loadctx *c, int idx, const char *k, uint8_t *id,
              int *action)
{
	lua_State *L = c->L;

	lua_getfield(L, idx, k);
	if (lua_istable(L, -1)) {
		const char *a = optstring(L, -1, "action");

		*id = (uint8_t)optint(L, lua_gettop(L), "id", 0);
		*action = (a != NULL && strcmp(a, "no-match") == 0)
		              ? PF_LIMITER_NOMATCH
		              : PF_LIMITER_BLOCK;
	}
	lua_pop(L, 1);
}

static void
encodedivert(struct loadctx *c, int idx, struct pf_rule *r)
{
	lua_State *L = c->L;
	const char *type;
	int t;

	lua_getfield(L, idx, "divert");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	t = lua_gettop(L);
	type = optstring(L, t, "type");
	if (type != NULL && strcmp(type, "to") == 0) {
		const char *a = optstring(L, t, "addr");
		sa_family_t af = afnum(optstring(L, t, "af"));

		r->divert.type = PF_DIVERT_TO;
		if (a == NULL || af == 0 ||
		    inet_pton(af, a, &r->divert.addr) != 1)
			loadfail(c, "bad divert address %s", a ? a : "(none)");
	} else if (type != NULL && strcmp(type, "reply") == 0) {
		r->divert.type = PF_DIVERT_REPLY;
	} else if (type != NULL && strcmp(type, "packet") == 0) {
		r->divert.type = PF_DIVERT_PACKET;
	} else {
		loadfail(c, "unknown divert %s", type ? type : "(none)");
	}
	r->divert.port = htons((uint16_t)optint(L, t, "port", 0));
	lua_pop(L, 1);
}

/* One rule table, already expanded, into the kernel's rule. */
static void
encoderule(struct loadctx *c, int idx, struct pf_rule *r)
{
	lua_State *L = c->L;
	const char *s;

	memset(r, 0, sizeof(*r));
	r->rtableid = -1;
	r->onrdomain = -1;
	r->os_fingerprint = PF_OSFP_ANY;

	s = optstring(L, idx, "action");
	if (s == NULL || strcmp(s, "pass") == 0)
		r->action = PF_PASS;
	else if (strcmp(s, "block") == 0)
		r->action = PF_DROP;
	else if (strcmp(s, "match") == 0)
		r->action = PF_MATCH;
	else
		loadfail(c, "unknown action %s", s);

	s = optstring(L, idx, "policy");
	if (s != NULL && strcmp(s, "return") == 0) {
		r->rule_flag |= PFRULE_RETURN;
		r->return_icmp = (ICMP_UNREACH << 8) | ICMP_UNREACH_PORT;
		r->return_icmp6 = (ICMP6_DST_UNREACH << 8) |
		                  ICMP6_DST_UNREACH_NOPORT;
	} else if (s != NULL && strcmp(s, "return-rst") == 0) {
		r->rule_flag |= PFRULE_RETURNRST;
	} else if (s != NULL && strcmp(s, "return-icmp") == 0) {
		r->rule_flag |= PFRULE_RETURNICMP;
		r->return_icmp = (ICMP_UNREACH << 8) | ICMP_UNREACH_PORT;
		r->return_icmp6 = (ICMP6_DST_UNREACH << 8) |
		                  ICMP6_DST_UNREACH_NOPORT;
	}

	s = optstring(L, idx, "direction");
	if (s != NULL)
		r->direction = strcmp(s, "in") == 0 ? PF_IN : PF_OUT;

	lua_getfield(L, idx, "log");
	if (lua_istable(L, -1)) {
		int t = lua_gettop(L);

		r->log = PF_LOG;
		if (optbool(L, t, "all"))
			r->log |= PF_LOG_ALL;
		if (optbool(L, t, "matches"))
			r->log |= PF_LOG_MATCHES;
		if (optbool(L, t, "user"))
			r->log |= PF_LOG_USER;
		r->logif = (uint8_t)optint(L, t, "to", 0);
	}
	lua_pop(L, 1);

	r->quick = optbool(L, idx, "quick");
	copyname(c, r->ifname, sizeof(r->ifname), optstring(L, idx, "ifname"),
	         "interface name");
	r->ifnot = optbool(L, idx, "ifnot");
	r->af = afnum(optstring(L, idx, "af"));
	r->proto = (uint8_t)optint(L, idx, "proto", 0);

	encoderuleaddr(c, idx, "from", &r->src, r->af);
	encoderuleaddr(c, idx, "to", &r->dst, r->af);

	r->flags = (uint8_t)optint(L, idx, "flags", 0);
	r->flagset = (uint8_t)optint(L, idx, "flagset", 0);
	if (optint(L, idx, "icmp_type", -1) >= 0)
		r->type = (uint16_t)(optint(L, idx, "icmp_type", 0) + 1);
	if (optint(L, idx, "icmp_code", -1) >= 0)
		r->code = (uint16_t)(optint(L, idx, "icmp_code", 0) + 1);

	encodestate(c, idx, r);

	s = optstring(L, idx, "source_track");
	if (s != NULL) {
		r->rule_flag |= PFRULE_SRCTRACK;
		if (strcmp(s, "rule") == 0)
			r->rule_flag |= PFRULE_RULESRCTRACK;
	}
	if (optbool(L, idx, "if_bound"))
		r->rule_flag |= PFRULE_IFBOUND;
	if (optbool(L, idx, "sloppy"))
		r->rule_flag |= PFRULE_STATESLOPPY;
	if (optbool(L, idx, "no_sync"))
		r->rule_flag |= PFRULE_NOSYNC;
	if (optbool(L, idx, "pflow"))
		r->rule_flag |= PFRULE_PFLOW;
	if (optbool(L, idx, "once"))
		r->rule_flag |= PFRULE_ONCE;
	r->allow_opts = optbool(L, idx, "allow_opts");

	if (optint(L, idx, "uid", -1) >= 0) {
		r->uid.op = PF_OP_EQ;
		r->uid.uid[0] = (uid_t)optint(L, idx, "uid", 0);
	}

	copyname(c, r->label, sizeof(r->label), optstring(L, idx, "label"),
	         "label");
	copyname(c, r->tagname, sizeof(r->tagname), optstring(L, idx, "tag"),
	         "tag");
	copyname(c, r->match_tagname, sizeof(r->match_tagname),
	         optstring(L, idx, "tagged"), "tag");

	lua_getfield(L, idx, "received_on");
	if (lua_istable(L, -1)) {
		int t = lua_gettop(L);

		copyname(c, r->rcv_ifname, sizeof(r->rcv_ifname),
		         optstring(L, t, "name"), "interface name");
		r->rcvifnot = optbool(L, t, "neg");
	}
	lua_pop(L, 1);

	r->rtableid = (int)optint(L, idx, "rtable", -1);

	lua_getfield(L, idx, "prio");
	if (lua_istable(L, -1)) {
		lua_rawgeti(L, -1, 1);
		lua_rawgeti(L, -2, 2);
		r->set_prio[0] = (uint8_t)lua_tointeger(L, -2);
		r->set_prio[1] = (uint8_t)lua_tointeger(L, -1);
		r->scrub_flags |= PFSTATE_SETPRIO;
		lua_pop(L, 2);
	}
	lua_pop(L, 1);

	lua_getfield(L, idx, "queue");
	if (lua_istable(L, -1)) {
		int t = lua_gettop(L);

		lua_rawgeti(L, t, 1);
		copyname(c, r->qname, sizeof(r->qname), lua_tostring(L, -1),
		         "queue name");
		lua_rawgeti(L, t, 2);
		copyname(c, r->pqname, sizeof(r->pqname), lua_tostring(L, -1),
		         "queue name");
		lua_pop(L, 2);
	}
	lua_pop(L, 1);

	r->naf = afnum(optstring(L, idx, "naf"));
	if (optbool(L, idx, "af_to"))
		r->rule_flag |= PFRULE_AFTO;
	encodepool(c, idx, "nat", &r->nat, r->naf != 0 ? r->naf : r->af);
	encodepool(c, idx, "rdr", &r->rdr, r->naf != 0 ? r->naf : r->af);

	s = optstring(L, idx, "rt");
	if (s != NULL) {
		if (strcmp(s, "route-to") == 0)
			r->rt = PF_ROUTETO;
		else if (strcmp(s, "reply-to") == 0)
			r->rt = PF_REPLYTO;
		else if (strcmp(s, "dup-to") == 0)
			r->rt = PF_DUPTO;
		else
			loadfail(c, "unknown route %s", s);
		encodepool(c, idx, "route", &r->route, r->af);
	}

	encodedivert(c, idx, r);
	if (optbool(L, idx, "scrub_tcp"))
		r->scrub_flags |= PFSTATE_SCRUB_TCP;

	encodelimiter(c, idx, "state_limiter", &r->statelim.id,
	              &r->statelim.limiter_action);
	encodelimiter(c, idx, "source_limiter", &r->sourcelim.id,
	              &r->sourcelim.limiter_action);
}

static uint32_t
ticket(struct loadctx *c, int type, const char *anchor)
{
	for (int i = 0; i < c->nte; i++)
		if (c->te[i].type == type && strcmp(c->te[i].anchor, anchor) == 0)
			return c->te[i].ticket;
	loadfail(c, "no transaction for anchor %s", anchor);
	return 0;
}

static void
loadtable(struct loadctx *c, int idx, const char *anchor)
{
	lua_State *L = c->L;
	struct pfioc_table io;
	struct pfr_addr *addrs = NULL;
	size_t n = 0;
	uint32_t flags = 0;

	memset(&io, 0, sizeof(io));
	copyname(c, io.pfrio_table.pfrt_name, sizeof(io.pfrio_table.pfrt_name),
	         optstring(L, idx, "name"), "table name");
	copyname(c, io.pfrio_table.pfrt_anchor,
	         sizeof(io.pfrio_table.pfrt_anchor), anchor, "anchor");
	snprintf(c->where, sizeof(c->where), "table <%s>",
	         io.pfrio_table.pfrt_name);

	if (optbool(L, idx, "persist"))
		flags |= PFR_TFLAG_PERSIST;
	if (optbool(L, idx, "const"))
		flags |= PFR_TFLAG_CONST;
	if (optbool(L, idx, "counters"))
		flags |= PFR_TFLAG_COUNTERS;
	io.pfrio_table.pfrt_flags = flags;

	lua_getfield(L, idx, "addrs");
	if (lua_istable(L, -1)) {
		int t = lua_gettop(L);

		n = lua_rawlen(L, t);
		if (n > INT_MAX)
			loadfail(c, "too many addresses");
		addrs = lua_newuserdata(L, n * sizeof(*addrs) + 1);
		memset(addrs, 0, n * sizeof(*addrs));
		for (size_t i = 0; i < n; i++) {
			struct pfr_addr *a = &addrs[i];
			const char *s;
			int e;

			lua_rawgeti(L, t, (lua_Integer)i + 1);
			e = lua_gettop(L);
			s = optstring(L, e, "addr");
			a->pfra_af = afnum(optstring(L, e, "af"));
			if (s == NULL || a->pfra_af == 0 ||
			    inet_pton(a->pfra_af, s, &a->pfra_u) != 1)
				loadfail(c, "bad address %s", s ? s : "(none)");
			a->pfra_net = (uint8_t)optint(L, e, "bits",
			                              a->pfra_af == AF_INET ? 32 : 128);
			a->pfra_not = optbool(L, e, "neg");
			lua_pop(L, 1);
		}
		io.pfrio_flags |= PFR_FLAG_ADDRSTOO;
	}

	io.pfrio_buffer = addrs;
	io.pfrio_esize = sizeof(struct pfr_addr);
	io.pfrio_size = (int)n;
	io.pfrio_ticket = ticket(c, PF_TRANS_TABLE, anchor);
	if (ioctl(c->fd, DIOCRINADEFINE, &io) == -1)
		loadfail(c, "DIOCRINADEFINE: %s", strerror(errno));
	lua_pop(L, addrs != NULL ? 2 : 1);
	c->where[0] = '\0';
}

static void
loadstatelim(struct loadctx *c, int idx, uint32_t tk)
{
	lua_State *L = c->L;
	struct pfioc_statelim sl;

	memset(&sl, 0, sizeof(sl));
	sl.ticket = tk;
	copyname(c, sl.name, sizeof(sl.name), optstring(L, idx, "name"),
	         "limiter name");
	sl.id = (uint32_t)optint(L, idx, "id", 0);
	sl.limit = (unsigned int)optint(L, idx, "limit", 0);
	sl.rate.limit = (unsigned int)optint(L, idx, "rate_limit", 0);
	sl.rate.seconds = (unsigned int)optint(L, idx, "rate_seconds", 0);
	snprintf(c->where, sizeof(c->where), "state limiter %s", sl.name);
	if (ioctl(c->fd, DIOCADDSTATELIM, &sl) == -1)
		loadfail(c, "DIOCADDSTATELIM: %s", strerror(errno));
	c->where[0] = '\0';
}

static void
loadsourcelim(struct loadctx *c, int idx, uint32_t tk)
{
	lua_State *L = c->L;
	struct pfioc_sourcelim sl;

	memset(&sl, 0, sizeof(sl));
	sl.ticket = tk;
	copyname(c, sl.name, sizeof(sl.name), optstring(L, idx, "name"),
	         "limiter name");
	sl.id = (uint32_t)optint(L, idx, "id", 0);
	sl.entries = (unsigned int)optint(L, idx, "entries", 0);
	sl.limit = (unsigned int)optint(L, idx, "limit", 0);
	sl.rate.limit = (unsigned int)optint(L, idx, "rate_limit", 0);
	sl.rate.seconds = (unsigned int)optint(L, idx, "rate_seconds", 0);
	copyname(c, sl.overload_tblname, sizeof(sl.overload_tblname),
	         optstring(L, idx, "overload"), "table name");
	sl.overload_hwm = (unsigned int)optint(L, idx, "above", 0);
	sl.overload_lwm = (unsigned int)optint(L, idx, "below", 0);
	sl.inet_prefix = (unsigned int)optint(L, idx, "inet_mask", 32);
	sl.inet6_prefix = (unsigned int)optint(L, idx, "inet6_mask", 128);
	snprintf(c->where, sizeof(c->where), "source limiter %s", sl.name);
	if (ioctl(c->fd, DIOCADDSOURCELIM, &sl) == -1)
		loadfail(c, "DIOCADDSOURCELIM: %s", strerror(errno));
	c->where[0] = '\0';
}

static const struct {
	const char *name;
	int index;
} limitnames[] = {
    {"states",        PF_LIMIT_STATES       },
    {"src-nodes",     PF_LIMIT_SRC_NODES    },
    {"frags",         PF_LIMIT_FRAGS        },
    {"tables",        PF_LIMIT_TABLES       },
    {"table-entries", PF_LIMIT_TABLE_ENTRIES},
    {"pktdelay",      PF_LIMIT_PKTDELAY_PKTS},
    {"anchors",       PF_LIMIT_ANCHORS      },
};

static const struct {
	const char *name;
	int index;
	unsigned int def;
} timeoutdefs[] = {
    {"tcp.first",      PFTM_TCP_FIRST_PACKET,   PFTM_TCP_FIRST_PACKET_VAL  },
    {"tcp.opening",    PFTM_TCP_OPENING,        PFTM_TCP_OPENING_VAL       },
    {"tcp.established", PFTM_TCP_ESTABLISHED,   PFTM_TCP_ESTABLISHED_VAL   },
    {"tcp.closing",    PFTM_TCP_CLOSING,        PFTM_TCP_CLOSING_VAL       },
    {"tcp.finwait",    PFTM_TCP_FIN_WAIT,       PFTM_TCP_FIN_WAIT_VAL      },
    {"tcp.closed",     PFTM_TCP_CLOSED,         PFTM_TCP_CLOSED_VAL        },
    {"tcp.tsdiff",     PFTM_TS_DIFF,            PFTM_TS_DIFF_VAL           },
    {"udp.first",      PFTM_UDP_FIRST_PACKET,   PFTM_UDP_FIRST_PACKET_VAL  },
    {"udp.single",     PFTM_UDP_SINGLE,         PFTM_UDP_SINGLE_VAL        },
    {"udp.multiple",   PFTM_UDP_MULTIPLE,       PFTM_UDP_MULTIPLE_VAL      },
    {"icmp.first",     PFTM_ICMP_FIRST_PACKET,  PFTM_ICMP_FIRST_PACKET_VAL },
    {"icmp.error",     PFTM_ICMP_ERROR_REPLY,   PFTM_ICMP_ERROR_REPLY_VAL  },
    {"other.first",    PFTM_OTHER_FIRST_PACKET, PFTM_OTHER_FIRST_PACKET_VAL},
    {"other.single",   PFTM_OTHER_SINGLE,       PFTM_OTHER_SINGLE_VAL      },
    {"other.multiple", PFTM_OTHER_MULTIPLE,     PFTM_OTHER_MULTIPLE_VAL    },
    {"frag",           PFTM_FRAG,               PFTM_FRAG_VAL              },
    {"interval",       PFTM_INTERVAL,           PFTM_INTERVAL_VAL          },
    {"adaptive.start", PFTM_ADAPTIVE_START,     PFSTATE_ADAPT_START        },
    {"adaptive.end",   PFTM_ADAPTIVE_END,       PFSTATE_ADAPT_END          },
    {"src.track",      PFTM_SRC_NODE,           PFTM_SRC_NODE_VAL          },
};

#define NITEMS(a) (sizeof(a) / sizeof((a)[0]))

/* The value of name in the table at field k of idx, or -1. */
static lua_Integer
optentry(lua_State *L, int idx, const char *k, const char *name)
{
	lua_Integer v = -1;

	lua_getfield(L, idx, k);
	if (lua_istable(L, -1)) {
		lua_getfield(L, -1, name);
		if (lua_isinteger(L, -1))
			v = lua_tointeger(L, -1);
		lua_pop(L, 1);
	}
	lua_pop(L, 1);

	return v;
}

/*
 * The limits pfctl -f sets: states goes back to its default unless set,
 * and the others keep the kernel's value. A small host gets fewer table
 * entries.
 */
static void
setlimits(struct loadctx *c, int idx, unsigned int limits[PF_LIMIT_MAX])
{
	struct pfioc_limit pl;
	int mib[2];
	int64_t mem;
	int mcl;
	size_t size;

	for (int i = 0; i < PF_LIMIT_MAX; i++) {
		memset(&pl, 0, sizeof(pl));
		pl.index = i;
		if (ioctl(c->fd, DIOCGETLIMIT, &pl) == -1)
			loadfail(c, "DIOCGETLIMIT: %s", strerror(errno));
		limits[i] = pl.limit;
	}
	limits[PF_LIMIT_STATES] = PFSTATE_HIWAT;
	if (limits[PF_LIMIT_FRAGS] == 0) {
		mib[0] = CTL_KERN;
		mib[1] = KERN_MAXCLUSTERS;
		size = sizeof(mcl);
		if (sysctl(mib, 2, &mcl, &size, NULL, 0) == -1)
			loadfail(c, "sysctl kern.maxclusters: %s", strerror(errno));
		limits[PF_LIMIT_FRAGS] = (unsigned int)mcl / 4;
	}
	mib[0] = CTL_HW;
	mib[1] = HW_PHYSMEM64;
	size = sizeof(mem);
	if (sysctl(mib, 2, &mem, &size, NULL, 0) == -1)
		loadfail(c, "sysctl hw.physmem: %s", strerror(errno));
	if (mem <= 100 * 1024 * 1024)
		limits[PF_LIMIT_TABLE_ENTRIES] = PFR_KENTRY_HIWAT_SMALL;

	for (size_t i = 0; i < NITEMS(limitnames); i++) {
		lua_Integer v = optentry(c->L, idx, "limits", limitnames[i].name);

		if (v >= 0)
			limits[limitnames[i].index] = (unsigned int)v;
	}
	for (int i = 0; i < PF_LIMIT_MAX; i++) {
		memset(&pl, 0, sizeof(pl));
		pl.index = i;
		pl.limit = limits[i];
		if (ioctl(c->fd, DIOCSETLIMIT, &pl) == -1)
			loadfail(c, "cannot set limit %d to %u: %s", i, limits[i],
			         strerror(errno));
	}
}

/*
 * Every timeout goes back to its default unless set. A states limit with
 * no adaptive timeouts sets them to 60% and 120% of it, as pfctl does.
 */
static void
settimeouts(struct loadctx *c, int idx, unsigned int states)
{
	unsigned int tm[PFTM_MAX];
	bool adaptive = false;
	struct pfioc_tm pt;

	memset(tm, 0, sizeof(tm));
	for (size_t i = 0; i < NITEMS(timeoutdefs); i++) {
		lua_Integer v = optentry(c->L, idx, "timeouts",
		                         timeoutdefs[i].name);

		tm[timeoutdefs[i].index] = timeoutdefs[i].def;
		if (v >= 0) {
			tm[timeoutdefs[i].index] = (unsigned int)v;
			if (timeoutdefs[i].index == PFTM_ADAPTIVE_START ||
			    timeoutdefs[i].index == PFTM_ADAPTIVE_END)
				adaptive = true;
		}
	}
	if (optentry(c->L, idx, "limits", "states") >= 0 && !adaptive) {
		tm[PFTM_ADAPTIVE_START] = (states / 10) * 6;
		tm[PFTM_ADAPTIVE_END] = (states / 10) * 12;
	}
	for (int i = 0; i < PFTM_MAX; i++) {
		memset(&pt, 0, sizeof(pt));
		pt.timeout = i;
		pt.seconds = (int)tm[i];
		if (ioctl(c->fd, DIOCSETTIMEOUT, &pt) == -1)
			loadfail(c, "DIOCSETTIMEOUT: %s", strerror(errno));
	}
}

/* The options of a main ruleset, which pfctl sets before it commits. */
static void
setoptions(struct loadctx *c, int idx)
{
	lua_State *L = c->L;
	unsigned int limits[PF_LIMIT_MAX];
	const char *s;
	int t;

	lua_getfield(L, idx, "options");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	t = lua_gettop(L);
	snprintf(c->where, sizeof(c->where), "options");

	setlimits(c, t, limits);
	settimeouts(c, t, limits[PF_LIMIT_STATES]);

	s = optstring(L, t, "loginterface");
	if (s != NULL) {
		struct pfioc_iface pi;

		memset(&pi, 0, sizeof(pi));
		if (strcmp(s, "none") != 0)
			copyname(c, pi.pfiio_name, sizeof(pi.pfiio_name), s,
			         "interface name");
		if (ioctl(c->fd, DIOCSETSTATUSIF, &pi) == -1)
			loadfail(c, "DIOCSETSTATUSIF: %s", strerror(errno));
	}

	lua_getfield(L, t, "reassemble");
	if (lua_isboolean(L, -1)) {
		uint32_t reass = lua_toboolean(L, -1) ? PF_REASS_ENABLED : 0;

		if (ioctl(c->fd, DIOCSETREASS, &reass) == -1)
			loadfail(c, "DIOCSETREASS: %s", strerror(errno));
	}
	lua_pop(L, 2);
	c->where[0] = '\0';
}

/* Each entry of the list at field k of the table at idx, through fn. */
static void
eachentry(struct loadctx *c, int idx, const char *k,
          void (*fn)(struct loadctx *, int, const char *),
          const char *anchor)
{
	lua_State *L = c->L;
	int t;

	lua_getfield(L, idx, k);
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	t = lua_gettop(L);
	for (lua_Integer i = 1; i <= (lua_Integer)lua_rawlen(L, t); i++) {
		lua_rawgeti(L, t, i);
		fn(c, lua_gettop(L), anchor);
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
}

static void
loadrules(struct loadctx *c, int idx, const char *anchor)
{
	lua_State *L = c->L;
	struct pfioc_rule *pr;
	int t;

	/* Two PATH_MAX arrays make this far too big for the stack. */
	pr = lua_newuserdata(L, sizeof(*pr));

	lua_getfield(L, idx, "rules");
	t = lua_gettop(L);
	for (lua_Integer i = 1; i <= (lua_Integer)lua_rawlen(L, t); i++) {
		int e;

		lua_rawgeti(L, t, i);
		e = lua_gettop(L);
		lua_getfield(L, e, "where");
		snprintf(c->where, sizeof(c->where), "%s",
		         lua_isstring(L, -1) ? lua_tostring(L, -1) : "rule");
		lua_pop(L, 1);

		memset(pr, 0, sizeof(*pr));
		encoderule(c, e, &pr->rule);
		pr->rule.nr = (uint32_t)(i - 1);
		pr->ticket = ticket(c, PF_TRANS_RULESET, anchor);
		copyname(c, pr->anchor, sizeof(pr->anchor), anchor, "anchor");
		copyname(c, pr->anchor_call, sizeof(pr->anchor_call),
		         optstring(L, e, "anchor_call"), "anchor");
		if (ioctl(c->fd, DIOCADDRULE, pr) == -1)
			loadfail(c, "DIOCADDRULE: %s", strerror(errno));
		lua_pop(L, 1);
	}
	lua_pop(L, 2);
	c->where[0] = '\0';
}

static void
loadtableentry(struct loadctx *c, int idx, const char *anchor)
{
	loadtable(c, idx, anchor);
}

static void
setskip(struct loadctx *c, int idx)
{
	lua_State *L = c->L;
	struct pfioc_iface pi;
	int t;

	lua_getfield(L, idx, "skip");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return;
	}
	t = lua_gettop(L);

	/* pfctl clears the flag everywhere, then sets it where named. */
	memset(&pi, 0, sizeof(pi));
	pi.pfiio_flags = PFI_IFLAG_SKIP;
	if (ioctl(c->fd, DIOCCLRIFFLAG, &pi) == -1)
		loadfail(c, "DIOCCLRIFFLAG: %s", strerror(errno));
	for (lua_Integer i = 1; i <= (lua_Integer)lua_rawlen(L, t); i++) {
		lua_rawgeti(L, t, i);
		memset(&pi, 0, sizeof(pi));
		pi.pfiio_flags = PFI_IFLAG_SKIP;
		copyname(c, pi.pfiio_name, sizeof(pi.pfiio_name),
		         lua_tostring(L, -1), "interface name");
		if (ioctl(c->fd, DIOCSETIFFLAG, &pi) == -1)
			loadfail(c, "DIOCSETIFFLAG %s: %s", pi.pfiio_name,
			         strerror(errno));
		lua_pop(L, 1);
	}
	lua_pop(L, 1);
}

/***
Load rulesets in one transaction, the way pfctl -f does.

pf.dsl builds the argument: rulesets is a list of { anchor, rules,
tables }, where each rule is already expanded and carries pfctl's
defaults. A main ruleset may also bring statelimiters, sourcelimiters,
skip and options { limits, timeouts, loginterface, reassemble }. With
check set, everything is sent and then rolled back. Any failure rolls
the whole transaction back.
@function pf:load
@tparam table spec
@treturn boolean true
@raise if a rule, table or limiter is refused, naming it
*/
int
pfload(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	struct loadctx c;
	int rsidx;
	lua_Integer n;

	luaL_checktype(L, 2, LUA_TTABLE);
	memset(&c, 0, sizeof(c));
	c.L = L;
	c.fd = pf->fd;

	lua_getfield(L, 2, "rulesets");
	luaL_argcheck(L, lua_istable(L, -1), 2, "rulesets must be a list");
	rsidx = lua_gettop(L);
	n = (lua_Integer)lua_rawlen(L, rsidx);
	luaL_argcheck(L, n > 0 && n < 1024, 2, "bad number of rulesets");

	c.nte = (int)n * 2;
	c.te = lua_newuserdata(L, sizeof(*c.te) * (size_t)c.nte);
	memset(c.te, 0, sizeof(*c.te) * (size_t)c.nte);
	for (lua_Integer i = 0; i < n; i++) {
		const char *a;

		lua_rawgeti(L, rsidx, i + 1);
		a = optstring(L, -1, "anchor");
		for (int k = 0; k < 2; k++) {
			struct pfioc_trans_e *e = &c.te[i * 2 + k];

			e->type = k == 0 ? PF_TRANS_RULESET : PF_TRANS_TABLE;
			copyname(&c, e->anchor, sizeof(e->anchor), a ? a : "",
			         "anchor");
		}
		lua_pop(L, 1);
	}
	c.trans.size = c.nte;
	c.trans.esize = sizeof(*c.te);
	c.trans.array = c.te;
	if (ioctl(c.fd, DIOCXBEGIN, &c.trans) == -1)
		return luaL_error(L, "DIOCXBEGIN: %s", strerror(errno));
	c.begun = true;

	for (lua_Integer i = 1; i <= n; i++) {
		const char *a;
		int r;

		lua_rawgeti(L, rsidx, i);
		r = lua_gettop(L);
		a = optstring(L, r, "anchor");
		if (a == NULL)
			a = "";
		eachentry(&c, r, "tables", loadtableentry, a);
		if (a[0] == '\0') {
			uint32_t tk = ticket(&c, PF_TRANS_RULESET, "");

			lua_getfield(L, 2, "statelimiters");
			if (lua_istable(L, -1))
				for (lua_Integer j = 1;
				     j <= (lua_Integer)lua_rawlen(L, -1); j++) {
					lua_rawgeti(L, -1, j);
					loadstatelim(&c, lua_gettop(L), tk);
					lua_pop(L, 1);
				}
			lua_pop(L, 1);
			lua_getfield(L, 2, "sourcelimiters");
			if (lua_istable(L, -1))
				for (lua_Integer j = 1;
				     j <= (lua_Integer)lua_rawlen(L, -1); j++) {
					lua_rawgeti(L, -1, j);
					loadsourcelim(&c, lua_gettop(L), tk);
					lua_pop(L, 1);
				}
			lua_pop(L, 1);
		}
		loadrules(&c, r, a);
		lua_pop(L, 1);
	}

	/* A check stops here: everything was accepted, and nothing stays. */
	if (optbool(L, 2, "check")) {
		(void)ioctl(c.fd, DIOCXROLLBACK, &c.trans);
		lua_pushboolean(L, 1);
		return 1;
	}

	setskip(&c, 2);
	setoptions(&c, 2);

	if (ioctl(c.fd, DIOCXCOMMIT, &c.trans) == -1)
		return loadfail(&c, "DIOCXCOMMIT: %s", strerror(errno));
	c.begun = false;

	lua_pushboolean(L, 1);
	return 1;
}

/***
The number of a protocol name, from /etc/protocols.
@function protonumber
@string name
@treturn ?int the number, or nil when there is no such protocol
*/
int
pfprotonumber(lua_State *L)
{
	struct protoent *p = getprotobyname(luaL_checkstring(L, 1));

	if (p == NULL)
		lua_pushnil(L);
	else
		lua_pushinteger(L, p->p_proto);

	return 1;
}

/***
The port of a service name, from /etc/services.
@function servicenumber
@string name
@string proto tcp or udp
@treturn ?int the port, or nil when there is no such service
*/
int
pfservicenumber(lua_State *L)
{
	struct servent *s = getservbyname(luaL_checkstring(L, 1),
	                                  luaL_checkstring(L, 2));

	if (s == NULL)
		lua_pushnil(L);
	else
		lua_pushinteger(L, ntohs((uint16_t)s->s_port));

	return 1;
}

/***
The number of an ICMP type name, as pfctl spells them.
@function icmptype
@string name
@string af inet or inet6
@treturn ?int the type, or nil when there is no such name
*/
int
pficmptype(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	const char *af = luaL_checkstring(L, 2);
	int t = luapf_icmp_type(name, strcmp(af, "inet6") == 0 ? AF_INET6
	                                                       : AF_INET);

	if (t < 0)
		lua_pushnil(L);
	else
		lua_pushinteger(L, t);

	return 1;
}

/***
The uid of a user name, from the password database. "unknown" is the
uid pf gives a socket with no owner.
@function uidnumber
@string name
@treturn ?int the uid, or nil when there is no such user
*/
int
pfuidnumber(lua_State *L)
{
	const char *name = luaL_checkstring(L, 1);
	struct passwd *pw;

	if (strcmp(name, "unknown") == 0) {
		/* pfctl stores "unknown" as -1. */
		lua_pushinteger(L, (lua_Integer)(uid_t)-1);
		return 1;
	}
	pw = getpwnam(name);
	if (pw == NULL)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)pw->pw_uid);

	return 1;
}
