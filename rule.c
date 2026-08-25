/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/pfvar.h>
#include <netdb.h>

#include <lua.h>
#include <lauxlib.h>

#include "pf.h"
#include "property.h"
#include "banned.h"

/***
@module pf
*/

struct luapfrule {
	struct pf_rule rule;
	char anchor[PATH_MAX];
	char anchor_call[PATH_MAX];
	uint32_t nr;
};

static const char *const actionnames[] = {
    "pass",  "block",    "scrub",    "no scrub", "nat",           "no nat",
    "binat", "no binat", "rdr",      "no rdr",   "synproxy drop", "defer",
    "match", "divert",   "route-to", "af-to",
};

/* An anchor call prints as its anchor keyword instead of its action. */
static const char *const anchornames[] = {
    "anchor",     "anchor",       "anchor",       "anchor",     "nat-anchor",
    "nat-anchor", "binat-anchor", "binat-anchor", "rdr-anchor", "rdr-anchor",
};

static const char *
anchorname(uint8_t action)
{
	if (action >= sizeof(anchornames) / sizeof(anchornames[0]))
		return "anchor";

	return anchornames[action];
}

static const char *
actionname(uint8_t action)
{
	if (action >= sizeof(actionnames) / sizeof(actionnames[0]))
		return "?";

	return actionnames[action];
}

/*
 * The kernel fills fixed-size character arrays that it need not NUL
 * terminate, so every read of one is bounded by the size of the array. Pass
 * that size explicitly: sizeof on a parameter would measure the pointer.
 */
static void
pushbounded(lua_State *L, const char *s, size_t size)
{
	lua_pushlstring(L, s, strnlen(s, size));
}

static void
addbounded(luaL_Buffer *b, const char *s, size_t size)
{
	luaL_addlstring(b, s, strnlen(s, size));
}

static void
copybounded(char *dst, size_t dstsize, const char *src, size_t srcsize)
{
	size_t n = strnlen(src, srcsize);

	if (n >= dstsize)
		n = dstsize - 1;

	memcpy(dst, src, n);
	dst[n] = '\0';
}

static int
maskbits(const struct pf_addr *m)
{
	int bits = 0;
	int j = 0;

	while (j < 4 && m->addr32[j] == 0xffffffff) {
		bits += 32;
		j++;
	}

	if (j < 4) {
		uint32_t v = ntohl(m->addr32[j]);

		for (int i = 31; i >= 0 && (v & (1U << i)) != 0; i--)
			bits++;
	}

	return bits;
}

static bool
addriszero(const struct pf_addr *a)
{
	return PF_AZERO(a, AF_INET6);
}

static void
addaddr(lua_State *L, luaL_Buffer *b, sa_family_t af, const struct pf_addr *a)
{
	char s[INET6_ADDRSTRLEN];

	if (inet_ntop(af == AF_INET6 ? AF_INET6 : AF_INET, a, s, sizeof(s)) ==
	    NULL)
		luaL_error(L, "inet_ntop: %s", strerror(errno));

	luaL_addstring(b, s);
}

/* Renders one address the way pfctl -s rules prints it. */
static void
addaddrwrap(lua_State *L, luaL_Buffer *b, const struct pf_addr_wrap *aw,
            sa_family_t af)
{
	char num[16];

	switch (aw->type) {
	case PF_ADDR_DYNIFTL:
		luaL_addchar(b, '(');
		addbounded(b, aw->v.ifname, sizeof(aw->v.ifname));
		luaL_addchar(b, ')');
		return;
	case PF_ADDR_TABLE:
		luaL_addchar(b, '<');
		addbounded(b, aw->v.tblname, sizeof(aw->v.tblname));
		luaL_addchar(b, '>');
		return;
	case PF_ADDR_NOROUTE:
		luaL_addstring(b, "no-route");
		return;
	case PF_ADDR_URPFFAILED:
		luaL_addstring(b, "urpf-failed");
		return;
	case PF_ADDR_RTLABEL:
		luaL_addstring(b, "route \"");
		addbounded(b, aw->v.rtlabelname, sizeof(aw->v.rtlabelname));
		luaL_addchar(b, '"');
		return;
	case PF_ADDR_RANGE:
		/* A range keeps its upper bound in the mask field. */
		addaddr(L, b, af, &aw->v.a.addr);
		luaL_addstring(b, " - ");
		addaddr(L, b, af, &aw->v.a.mask);
		return;
	case PF_ADDR_ADDRMASK:
		break;
	default:
		luaL_addchar(b, '?');
		return;
	}

	if (addriszero(&aw->v.a.addr) && addriszero(&aw->v.a.mask)) {
		luaL_addstring(b, "any");
		return;
	}

	addaddr(L, b, af, &aw->v.a.addr);

	int bits = maskbits(&aw->v.a.mask);

	if (bits < (af == AF_INET6 ? 128 : 32)) {
		snprintf(num, sizeof(num), "/%d", bits);
		luaL_addstring(b, num);
	}
}

static const char *
opname(uint8_t op)
{
	switch (op) {
	case PF_OP_IRG:
		return "><";
	case PF_OP_XRG:
		return "<>";
	case PF_OP_EQ:
		return "=";
	case PF_OP_NE:
		return "!=";
	case PF_OP_LT:
		return "<";
	case PF_OP_LE:
		return "<=";
	case PF_OP_GT:
		return ">";
	case PF_OP_GE:
		return ">=";
	case PF_OP_RRG:
		return ":";
	default:
		return NULL;
	}
}

static void
addport(luaL_Buffer *b, const struct pf_rule_addr *ra)
{
	const char *op = opname(ra->port_op);
	char num[16];

	if (op == NULL)
		return;

	luaL_addstring(b, " port ");

	switch (ra->port_op) {
	case PF_OP_IRG:
	case PF_OP_XRG:
	case PF_OP_RRG:
		snprintf(num, sizeof(num), "%u", ntohs(ra->port[0]));
		luaL_addstring(b, num);
		luaL_addchar(b, ' ');
		luaL_addstring(b, op);
		luaL_addchar(b, ' ');
		snprintf(num, sizeof(num), "%u", ntohs(ra->port[1]));
		luaL_addstring(b, num);
		return;
	default:
		luaL_addstring(b, op);
		luaL_addchar(b, ' ');
		snprintf(num, sizeof(num), "%u", ntohs(ra->port[0]));
		luaL_addstring(b, num);
	}
}

/* pfctl prints "all" when neither endpoint constrains anything. */
static bool
ruleisany(const struct pf_rule_addr *ra)
{
	return ra->addr.type == PF_ADDR_ADDRMASK && !ra->neg &&
	       ra->port_op == PF_OP_NONE && addriszero(&ra->addr.v.a.addr) &&
	       addriszero(&ra->addr.v.a.mask);
}

static int
pushruleaddr(lua_State *L, const struct pf_rule_addr *ra, sa_family_t af)
{
	luaL_Buffer b;

	luaL_buffinit(L, &b);

	if (ra->neg)
		luaL_addstring(&b, "! ");

	addaddrwrap(L, &b, &ra->addr, af);
	addport(&b, ra);

	luaL_pushresult(&b);

	return 1;
}

static int
rule_src(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushruleaddr(L, &r->rule.src, r->rule.af);
}

static int
rule_dst(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushruleaddr(L, &r->rule.dst, r->rule.af);
}

static int
rule_nr(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->nr);

	return 1;
}

static int
rule_action(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushstring(L, actionname(r->rule.action));

	return 1;
}

static int
rule_direction(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	switch (r->rule.direction) {
	case PF_IN:
		lua_pushstring(L, "in");
		break;
	case PF_OUT:
		lua_pushstring(L, "out");
		break;
	default:
		lua_pushnil(L);
	}

	return 1;
}

static int
rule_af(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	switch (r->rule.af) {
	case AF_INET:
		lua_pushstring(L, "inet");
		break;
	case AF_INET6:
		lua_pushstring(L, "inet6");
		break;
	default:
		lua_pushnil(L);
	}

	return 1;
}

static int
rule_proto(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	struct protoent *p;

	if (r->rule.proto == 0) {
		lua_pushnil(L);
		return 1;
	}

	p = getprotobynumber(r->rule.proto);
	if (p == NULL)
		lua_pushinteger(L, (lua_Integer)r->rule.proto);
	else
		lua_pushstring(L, p->p_name);

	return 1;
}

static int
rule_quick(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, r->rule.quick != 0);

	return 1;
}

static int
rule_log(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, r->rule.log != 0);

	return 1;
}

static int
rule_keep_state(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, r->rule.keep_state != 0);

	return 1;
}

static int
rule_interface(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	pushbounded(L, r->rule.ifname, sizeof(r->rule.ifname));

	return 1;
}

static int
rule_label(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	pushbounded(L, r->rule.label, sizeof(r->rule.label));

	return 1;
}

static int
rule_tag(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	pushbounded(L, r->rule.tagname, sizeof(r->rule.tagname));

	return 1;
}

static int
rule_anchor(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	pushbounded(L, r->anchor, sizeof(r->anchor));

	return 1;
}

static int
rule_anchor_call(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	pushbounded(L, r->anchor_call, sizeof(r->anchor_call));

	return 1;
}

static int
rule_evaluations(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.evaluations);

	return 1;
}

static int
rule_packets_in(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.packets[0]);

	return 1;
}

static int
rule_packets_out(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.packets[1]);

	return 1;
}

static int
rule_bytes_in(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.bytes[0]);

	return 1;
}

static int
rule_bytes_out(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.bytes[1]);

	return 1;
}

static int
rule_states_cur(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.states_cur);

	return 1;
}

static int
rule_states_total(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.states_tot);

	return 1;
}

static const struct ro_property rule_properties[] = {
    {"nr",           rule_nr          },
    {"action",       rule_action      },
    {"direction",    rule_direction   },
    {"af",           rule_af          },
    {"proto",        rule_proto       },
    {"quick",        rule_quick       },
    {"log",          rule_log         },
    {"keep_state",   rule_keep_state  },
    {"interface",    rule_interface   },
    {"label",        rule_label       },
    {"tag",          rule_tag         },
    {"anchor",       rule_anchor      },
    {"anchor_call",  rule_anchor_call },
    {"source",       rule_src         },
    {"destination",  rule_dst         },
    {"evaluations",  rule_evaluations },
    {"packets_in",   rule_packets_in  },
    {"packets_out",  rule_packets_out },
    {"bytes_in",     rule_bytes_in    },
    {"bytes_out",    rule_bytes_out   },
    {"states_cur",   rule_states_cur  },
    {"states_total", rule_states_total},
    {NULL,           NULL             },
};

static int
pfruleindex(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFRULE_MT);

	return ro_property_lookup(L, rule_properties, 1, 2);
}

static int
pfruleaux(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFRULE_MT);

	return ro_property_next(L, rule_properties, 1, 2);
}

static int
pfrulepairs(lua_State *L)
{
	(void)luaL_checkudata(L, 1, PFRULE_MT);

	lua_pushcfunction(L, pfruleaux);
	lua_pushvalue(L, 1);
	lua_pushnil(L);

	return 3;
}

/***
Render a rule the way pfctl prints it.

Rule flags and state options are left out, so the text is close to a
pfctl -s rules line but not identical to it.
@function rule:__tostring
@treturn string
@usage print(tostring(r)) -- block drop in log quick from &lt;bad&gt; to any
*/
static int
pfruletostring(lua_State *L)
{
	struct luapfrule *r = luaL_checkudata(L, 1, PFRULE_MT);
	luaL_Buffer b;

	luaL_buffinit(L, &b);

	if (r->anchor_call[0] != '\0') {
		luaL_addstring(&b, anchorname(r->rule.action));
		luaL_addstring(&b, " \"");
		addbounded(&b, r->anchor_call, sizeof(r->anchor_call));
		luaL_addchar(&b, '"');
	} else {
		luaL_addstring(&b, actionname(r->rule.action));
	}

	if (r->anchor_call[0] == '\0' && r->rule.action == PF_DROP) {
		if (r->rule.rule_flag & PFRULE_RETURN)
			luaL_addstring(&b, " return");
		else if (r->rule.rule_flag & PFRULE_RETURNRST)
			luaL_addstring(&b, " return-rst");
		else if (r->rule.rule_flag & PFRULE_RETURNICMP)
			luaL_addstring(&b, " return-icmp");
		else
			luaL_addstring(&b, " drop");
	}

	if (r->rule.direction == PF_IN)
		luaL_addstring(&b, " in");
	else if (r->rule.direction == PF_OUT)
		luaL_addstring(&b, " out");

	if (r->rule.log)
		luaL_addstring(&b, " log");

	if (r->rule.quick)
		luaL_addstring(&b, " quick");

	if (r->rule.ifname[0] != '\0') {
		luaL_addstring(&b, " on ");
		addbounded(&b, r->rule.ifname, sizeof(r->rule.ifname));
	}

	if (r->rule.af == AF_INET)
		luaL_addstring(&b, " inet");
	else if (r->rule.af == AF_INET6)
		luaL_addstring(&b, " inet6");

	if (r->rule.proto != 0) {
		struct protoent *p = getprotobynumber(r->rule.proto);

		luaL_addstring(&b, " proto ");
		luaL_addstring(&b, p != NULL ? p->p_name : "?");
	}

	if (ruleisany(&r->rule.src) && ruleisany(&r->rule.dst)) {
		luaL_addstring(&b, " all");
	} else {
		luaL_addstring(&b, " from ");
		pushruleaddr(L, &r->rule.src, r->rule.af);
		luaL_addvalue(&b);

		luaL_addstring(&b, " to ");
		pushruleaddr(L, &r->rule.dst, r->rule.af);
		luaL_addvalue(&b);
	}

	if (r->rule.label[0] != '\0') {
		luaL_addstring(&b, " label \"");
		addbounded(&b, r->rule.label, sizeof(r->rule.label));
		luaL_addchar(&b, '"');
	}

	luaL_pushresult(&b);

	return 1;
}

static const luaL_Reg pfrulemeta[] = {
    {"__index",    pfruleindex   },
    {"__pairs",    pfrulepairs   },
    {"__tostring", pfruletostring},
    {NULL,         NULL          },
};

/***
Read the rules of an anchor.

The kernel walks a transaction rather than serving rules by number, so the
whole ruleset is read at once.
@function pf:rules
@string[opt=""] anchor
@treturn table array of rule objects
@raise if the anchor does not exist
@usage for _, r in ipairs(h:rules()) do print(tostring(r)) end
*/
int
pfrules(lua_State *L)
{
	struct luapf *pf = luaL_checkudata(L, 1, PF_MT);
	const char *anchor = luaL_optstring(L, 2, "");
	struct pfioc_rule *pr;
	uint32_t ticket;
	int n = 1;

	/* Two PATH_MAX arrays make this far too big for the stack. */
	pr = lua_newuserdata(L, sizeof(*pr));
	memset(pr, 0, sizeof(*pr));

	if (strlcpy(pr->anchor, anchor, sizeof(pr->anchor)) >=
	    sizeof(pr->anchor))
		luaL_error(L, "anchor name too long");

	pr->rule.action = PF_PASS;

	if (ioctl(pf->fd, DIOCGETRULES, pr) < 0)
		luaL_error(L, "DIOCGETRULES: %s", strerror(errno));

	ticket = pr->ticket;

	lua_newtable(L);

	for (;;) {
		struct luapfrule *r;

		memset(&pr->rule, 0, sizeof(pr->rule));
		pr->ticket = ticket;
		pr->action = 0;

		if (ioctl(pf->fd, DIOCGETRULE, pr) < 0) {
			if (errno == ENOENT)
				break;
			(void)ioctl(pf->fd, DIOCXEND, &ticket);
			luaL_error(L, "DIOCGETRULE: %s", strerror(errno));
		}

		r = lua_newuserdata(L, sizeof(*r));
		memset(r, 0, sizeof(*r));
		luaL_setmetatable(L, PFRULE_MT);

		r->rule = pr->rule;
		r->nr = pr->nr;
		copybounded(r->anchor, sizeof(r->anchor), pr->anchor,
		            sizeof(pr->anchor));
		copybounded(r->anchor_call, sizeof(r->anchor_call),
		            pr->anchor_call, sizeof(pr->anchor_call));

		lua_rawseti(L, -2, n++);
	}

	(void)ioctl(pf->fd, DIOCXEND, &ticket);

	return 1;
}

void
luapf_rules_register(lua_State *L)
{
	luaL_newmetatable(L, PFRULE_MT);
	luaL_setfuncs(L, pfrulemeta, 0);
	lua_pop(L, 1);
}

/***
A single rule.

Read-only properties: nr, action, direction, af, proto, quick, log,
keep_state, interface, label, tag, anchor, anchor_call, source,
destination, evaluations, packets_in, packets_out, bytes_in, bytes_out,
states_cur and states_total. Source and destination render the way pfctl
prints them, tables as &lt;name&gt; and interfaces as (name).
@table rule
*/
