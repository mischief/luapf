/* SPDX-License-Identifier: ISC */
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
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
		/*
		 * The modifiers are not decoration: (em0) is the interface's
		 * addresses, (em0:network) is the network it sits on. Dropping
		 * them renders one as the other.
		 */
		luaL_addchar(b, '(');
		addbounded(b, aw->v.ifname, sizeof(aw->v.ifname));
		if (aw->iflags & PFI_AFLAG_NETWORK)
			luaL_addstring(b, ":network");
		if (aw->iflags & PFI_AFLAG_BROADCAST)
			luaL_addstring(b, ":broadcast");
		if (aw->iflags & PFI_AFLAG_PEER)
			luaL_addstring(b, ":peer");
		if (aw->iflags & PFI_AFLAG_NOALIAS)
			luaL_addstring(b, ":0");
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

	/* A rule with no address family compares against the wider width,
	 * the same way pfctl does, so a /32 host still prints its mask. */
	if (bits < (af == AF_INET ? 32 : 128)) {
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

/*
 * Renders the two operands of a comparison the way pfctl writes them. The
 * range operators put the operator between the values; every other operator
 * takes only the first value.
 */
static void
addoperands(luaL_Buffer *b, uint8_t op, uintmax_t v0, uintmax_t v1)
{
	const char *o = opname(op);
	char num[24];

	if (o == NULL)
		return;

	switch (op) {
	case PF_OP_IRG:
	case PF_OP_XRG:
	case PF_OP_RRG:
		snprintf(num, sizeof(num), "%ju", v0);
		luaL_addstring(b, num);
		/* An inclusive range is written tight, unlike >< and <>. */
		if (op != PF_OP_RRG)
			luaL_addchar(b, ' ');
		luaL_addstring(b, o);
		if (op != PF_OP_RRG)
			luaL_addchar(b, ' ');
		snprintf(num, sizeof(num), "%ju", v1);
		luaL_addstring(b, num);
		return;
	default:
		luaL_addstring(b, o);
		luaL_addchar(b, ' ');
		snprintf(num, sizeof(num), "%ju", v0);
		luaL_addstring(b, num);
	}
}

/* The TCP flag letters, in the bit order pf stores them. */
static void
addflags(luaL_Buffer *b, uint8_t f)
{
	static const char letters[] = "FSRPAUEW";

	for (unsigned i = 0; i < 8; i++)
		if (f & (1U << i))
			luaL_addchar(b, letters[i]);
}

static void
addflagspec(luaL_Buffer *b, const struct pf_rule *rule)
{
	addflags(b, rule->flags);
	luaL_addchar(b, '/');
	addflags(b, rule->flagset);
}

struct icmpname {
	uint8_t type;
	const char *name;
};

/* pfctl names ICMP types itself; libc has no lookup for them. */
static const struct icmpname icmp4names[] = {
    {0,  "echorep"    },
    {3,  "unreach"    },
    {4,  "squench"    },
    {5,  "redir"      },
    {6,  "althost"    },
    {8,  "echoreq"    },
    {9,  "routeradv"  },
    {10, "routersol"  },
    {11, "timex"      },
    {12, "paramprob"  },
    {13, "timereq"    },
    {14, "timerep"    },
    {15, "inforeq"    },
    {16, "inforep"    },
    {17, "maskreq"    },
    {18, "maskrep"    },
    {30, "trace"      },
    {31, "dataconv"   },
    {32, "mobredir"   },
    {33, "ipv6-where" },
    {34, "ipv6-here"  },
    {35, "mobregreq"  },
    {36, "mobregrep"  },
    {39, "skip"       },
    {40, "photuris"   },
};

static const struct icmpname icmp6names[] = {
    {1,   "unreach"    },
    {2,   "toobig"     },
    {3,   "timex"      },
    {4,   "paramprob"  },
    {128, "echoreq"    },
    {129, "echorep"    },
    {130, "groupqry"   },
    {131, "grouprep"   },
    {132, "groupterm"  },
    {133, "routersol"  },
    {134, "routeradv"  },
    {135, "neighbrsol" },
    {136, "neighbradv" },
    {137, "redir"      },
    {138, "routrrenum" },
    {139, "fqdnreq"    },
    {140, "fqdnrep"    },
    {200, "wrureq"     },
    {201, "wrurep"     },
};

static const char *
icmpname(uint8_t type, sa_family_t af)
{
	const struct icmpname *t = af == AF_INET6 ? icmp6names : icmp4names;
	size_t n = af == AF_INET6 ? sizeof(icmp6names) / sizeof(icmp6names[0])
	                          : sizeof(icmp4names) / sizeof(icmp4names[0]);

	for (size_t i = 0; i < n; i++)
		if (t[i].type == type)
			return t[i].name;

	return NULL;
}

struct icmpcode {
	uint8_t type;
	uint8_t code;
	const char *name;
};

/* Only the ICMP types that carry a named code appear here; every other
 * code prints as its number, the way pfctl prints an unnamed one. */
static const struct icmpcode icmp4codes[] = {
    {3,  0,  "net-unr"       },
    {3,  1,  "host-unr"      },
    {3,  2,  "proto-unr"     },
    {3,  3,  "port-unr"      },
    {3,  4,  "needfrag"      },
    {3,  5,  "srcfail"       },
    {3,  6,  "net-unk"       },
    {3,  7,  "host-unk"      },
    {3,  8,  "isolate"       },
    {3,  9,  "net-prohib"    },
    {3,  10, "host-prohib"   },
    {3,  11, "net-tos"       },
    {3,  12, "host-tos"      },
    {3,  13, "filter-prohib" },
    {3,  14, "host-preced"   },
    {3,  15, "cutoff-preced" },
    {5,  0,  "redir-net"     },
    {5,  1,  "redir-host"    },
    {5,  2,  "redir-tos-net" },
    {5,  3,  "redir-tos-host"},
    {11, 0,  "transit"       },
    {11, 1,  "reassemb"      },
    {12, 0,  "badhead"       },
    {12, 1,  "optmiss"       },
    {12, 2,  "badlen"        },
    {40, 1,  "unknown-ind"   },
    {40, 2,  "auth-fail"     },
    {40, 3,  "decrypt-fail"  },
};

static const struct icmpcode icmp6codes[] = {
    {1, 0, "noroute-unr"},
    {1, 1, "admin-unr"  },
    {1, 2, "beyond-unr" },
    {1, 3, "addr-unr"   },
    {1, 4, "port-unr"   },
    {3, 0, "transit"    },
    {3, 1, "reassemb"   },
    {4, 0, "badhead"    },
    {4, 1, "nxthdr"     },
};

static const char *
icmpcodename(uint8_t type, uint8_t code, sa_family_t af)
{
	const struct icmpcode *t = af == AF_INET6 ? icmp6codes : icmp4codes;
	size_t n = af == AF_INET6 ? sizeof(icmp6codes) / sizeof(icmp6codes[0])
	                          : sizeof(icmp4codes) / sizeof(icmp4codes[0]);

	for (size_t i = 0; i < n; i++)
		if (t[i].type == type && t[i].code == code)
			return t[i].name;

	return NULL;
}

/* pf stores type and code one above the wire value so that zero means
 * "not set", which is why every read of them subtracts one. */
static void
addicmp(luaL_Buffer *b, const struct pf_rule *rule)
{
	const char *name;
	char num[16];

	if (rule->type == 0)
		return;

	luaL_addstring(b, rule->af == AF_INET6 ? " icmp6-type " :
	                                         " icmp-type ");

	name = icmpname((uint8_t)(rule->type - 1), rule->af);
	if (name != NULL)
		luaL_addstring(b, name);
	else {
		snprintf(num, sizeof(num), "%u", rule->type - 1);
		luaL_addstring(b, num);
	}

	if (rule->code != 0) {
		luaL_addstring(b, " code ");
		name = icmpcodename((uint8_t)(rule->type - 1),
		    (uint8_t)(rule->code - 1), rule->af);
		if (name != NULL)
			luaL_addstring(b, name);
		else {
			snprintf(num, sizeof(num), "%u", rule->code - 1);
			luaL_addstring(b, num);
		}
	}
}

/*
 * The ICMP answer a block rule sends back. pf keeps a v4 and a v6 code in
 * one field each, and a rule with no address family carries both.
 */
static void
addreturnicmp(luaL_Buffer *b, uint16_t v, sa_family_t af)
{
	const char *name = icmpcodename((uint8_t)(v >> 8), (uint8_t)(v & 255),
	    af);
	char num[16];

	if (name != NULL) {
		luaL_addstring(b, name);
		return;
	}

	snprintf(num, sizeof(num), "%u", v & 255);
	luaL_addstring(b, num);
}

static void
addreturn(luaL_Buffer *b, const struct pf_rule *rule)
{
	char num[24];

	if (rule->rule_flag & PFRULE_RETURN) {
		luaL_addstring(b, " return");
		return;
	}

	if (rule->rule_flag & PFRULE_RETURNRST) {
		if (rule->return_ttl == 0)
			luaL_addstring(b, " return-rst");
		else {
			snprintf(num, sizeof(num), " return-rst(ttl %u)",
			    rule->return_ttl);
			luaL_addstring(b, num);
		}
		return;
	}

	if ((rule->rule_flag & PFRULE_RETURNICMP) == 0) {
		luaL_addstring(b, " drop");
		return;
	}

	switch (rule->af) {
	case AF_INET:
		luaL_addstring(b, " return-icmp(");
		addreturnicmp(b, rule->return_icmp, AF_INET);
		break;
	case AF_INET6:
		luaL_addstring(b, " return-icmp6(");
		addreturnicmp(b, rule->return_icmp6, AF_INET6);
		break;
	default:
		/* Without a family the rule answers either one, so pfctl
		 * prints both codes rather than choosing. */
		luaL_addstring(b, " return-icmp(");
		addreturnicmp(b, rule->return_icmp, AF_INET);
		luaL_addstring(b, ", ");
		addreturnicmp(b, rule->return_icmp6, AF_INET6);
		break;
	}

	luaL_addchar(b, ')');
}

/* Appends ", " before every group member except the first. */
static void
addcomma(luaL_Buffer *b, bool *first)
{
	if (*first)
		*first = false;
	else
		luaL_addstring(b, ", ");
}

/* pf_rule.timeout[] is indexed by PFTM_*, so these names are in that order
 * and stop at PFTM_MAX, where the special cases begin. */
static const char *const timeoutnames[PFTM_MAX] = {
    "tcp.first", "tcp.opening", "tcp.established", "tcp.closing",
    "tcp.finwait", "tcp.closed", "udp.first", "udp.single", "udp.multiple",
    "icmp.first", "icmp.error", "other.first", "other.single",
    "other.multiple", "frag", "interval", "adaptive.start", "adaptive.end",
    "src.track", "ts.diff",
};

static bool
hastimeouts(const struct pf_rule *rule)
{
	for (int i = 0; i < PFTM_MAX; i++)
		if (rule->timeout[i] != 0)
			return true;

	return false;
}

/* True when the rule carries state options worth a parenthesized group. */
static bool
hasstateopts(const struct pf_rule *rule)
{
	static const uint32_t flags = PFRULE_NOSYNC | PFRULE_SRCTRACK |
	    PFRULE_IFBOUND | PFRULE_STATESLOPPY | PFRULE_PFLOW;

	return rule->max_states != 0 || rule->max_src_nodes != 0 ||
	       rule->max_src_states != 0 || rule->max_src_conn != 0 ||
	       rule->max_src_conn_rate.limit != 0 ||
	       rule->overload_tblname[0] != '\0' ||
	       (rule->rule_flag & flags) != 0 || hastimeouts(rule);
}

static void
addstateopts(luaL_Buffer *b, const struct pf_rule *rule)
{
	bool first = true;
	char num[48];

	luaL_addstring(b, " (");

	if (rule->max_states != 0) {
		addcomma(b, &first);
		snprintf(num, sizeof(num), "max %u", rule->max_states);
		luaL_addstring(b, num);
	}

	if (rule->rule_flag & PFRULE_NOSYNC) {
		addcomma(b, &first);
		luaL_addstring(b, "no-sync");
	}

	if (rule->rule_flag & PFRULE_SRCTRACK) {
		addcomma(b, &first);
		luaL_addstring(b, "source-track");
		luaL_addstring(b, (rule->rule_flag & PFRULE_RULESRCTRACK) ?
		        " rule" :
		        " global");
	}

	if (rule->max_src_states != 0) {
		addcomma(b, &first);
		snprintf(num, sizeof(num), "max-src-states %u",
		    rule->max_src_states);
		luaL_addstring(b, num);
	}

	if (rule->max_src_conn != 0) {
		addcomma(b, &first);
		snprintf(num, sizeof(num), "max-src-conn %u",
		    rule->max_src_conn);
		luaL_addstring(b, num);
	}

	if (rule->max_src_conn_rate.limit != 0) {
		addcomma(b, &first);
		snprintf(num, sizeof(num), "max-src-conn-rate %u/%u",
		    rule->max_src_conn_rate.limit,
		    rule->max_src_conn_rate.seconds);
		luaL_addstring(b, num);
	}

	if (rule->max_src_nodes != 0) {
		addcomma(b, &first);
		snprintf(num, sizeof(num), "max-src-nodes %u",
		    rule->max_src_nodes);
		luaL_addstring(b, num);
	}

	if (rule->overload_tblname[0] != '\0') {
		addcomma(b, &first);
		luaL_addstring(b, "overload <");
		addbounded(b, rule->overload_tblname,
		    sizeof(rule->overload_tblname));
		luaL_addchar(b, '>');
		if (rule->flush)
			luaL_addstring(b, " flush");
		if (rule->flush & PF_FLUSH_GLOBAL)
			luaL_addstring(b, " global");
	}

	if (rule->rule_flag & PFRULE_IFBOUND) {
		addcomma(b, &first);
		luaL_addstring(b, "if-bound");
	}

	if (rule->rule_flag & PFRULE_STATESLOPPY) {
		addcomma(b, &first);
		luaL_addstring(b, "sloppy");
	}

	if (rule->rule_flag & PFRULE_PFLOW) {
		addcomma(b, &first);
		luaL_addstring(b, "pflow");
	}

	for (int i = 0; i < PFTM_MAX; i++) {
		if (rule->timeout[i] == 0 || timeoutnames[i] == NULL)
			continue;
		addcomma(b, &first);
		snprintf(num, sizeof(num), "%s %u", timeoutnames[i],
		    rule->timeout[i]);
		luaL_addstring(b, num);
	}

	luaL_addchar(b, ')');
}

/* Only the keyword. pfctl puts "probability" between it and the option
 * group, so the two halves cannot be written in one go. */
static void
addstatekeyword(luaL_Buffer *b, const struct pf_rule *rule, bool isanchor)
{
	if (rule->keep_state == 0) {
		/* Only a pass rule can be told to keep no state; a block
		 * rule never had any to keep. */
		if (rule->action == PF_PASS && !isanchor)
			luaL_addstring(b, " no state");
		return;
	}

	if (rule->keep_state == PF_STATE_MODULATE)
		luaL_addstring(b, " modulate state");
	else if (rule->keep_state == PF_STATE_SYNPROXY)
		luaL_addstring(b, " synproxy state");
	else if (hasstateopts(rule))
		luaL_addstring(b, " keep state");
}

/* pf stores a probability as a fraction of the 32-bit range. pfctl turns
 * it back into a percentage and trims the trailing zeros of "%f". */
static void
addprob(luaL_Buffer *b, const struct pf_rule *rule)
{
	char num[32];

	if (rule->prob == 0)
		return;

	snprintf(num, sizeof(num), "%f",
	    (double)rule->prob * 100.0 / ((double)UINT_MAX + 1.0));

	for (int i = (int)strlen(num) - 1; i > 0; i--) {
		if (num[i] == '0')
			num[i] = '\0';
		else {
			if (num[i] == '.')
				num[i] = '\0';
			break;
		}
	}

	luaL_addstring(b, " probability ");
	luaL_addstring(b, num);
	luaL_addchar(b, '%');
}

/* The "scrub (...)" group: what the rule rewrites in a matching packet. */
static void
addscrubopts(luaL_Buffer *b, const struct pf_rule *rule)
{
	bool first = true;
	char num[32];

	if ((rule->scrub_flags & PFSTATE_SCRUBMASK) == 0 &&
	    rule->min_ttl == 0 && rule->max_mss == 0)
		return;

	luaL_addstring(b, " scrub (");

	/* Unlike the other groups pfctl separates these with a space. */
	if (rule->scrub_flags & PFSTATE_NODF) {
		first = false;
		luaL_addstring(b, "no-df");
	}

	if (rule->scrub_flags & PFSTATE_RANDOMID) {
		luaL_addstring(b, first ? "" : " ");
		first = false;
		luaL_addstring(b, "random-id");
	}

	if (rule->min_ttl != 0) {
		snprintf(num, sizeof(num), "%smin-ttl %u", first ? "" : " ",
		    rule->min_ttl);
		first = false;
		luaL_addstring(b, num);
	}

	if (rule->scrub_flags & PFSTATE_SCRUB_TCP) {
		luaL_addstring(b, first ? "" : " ");
		first = false;
		luaL_addstring(b, "reassemble tcp");
	}

	if (rule->max_mss != 0) {
		snprintf(num, sizeof(num), "%smax-mss %u", first ? "" : " ",
		    rule->max_mss);
		luaL_addstring(b, num);
	}

	luaL_addchar(b, ')');
}

static const char *
divertname(uint8_t type)
{
	switch (type) {
	case PF_DIVERT_TO:
		return "divert-to";
	case PF_DIVERT_REPLY:
		return "divert-reply";
	case PF_DIVERT_PACKET:
		return "divert-packet";
	default:
		return NULL;
	}
}

static void
adddivert(lua_State *L, luaL_Buffer *b, const struct pf_rule *rule)
{
	const char *name = divertname(rule->divert.type);
	char num[24];

	if (name == NULL)
		return;

	luaL_addchar(b, ' ');
	luaL_addstring(b, name);

	if (rule->divert.type == PF_DIVERT_TO) {
		luaL_addchar(b, ' ');
		addaddr(L, b, rule->af, &rule->divert.addr);
	}

	if (rule->divert.type != PF_DIVERT_REPLY) {
		snprintf(num, sizeof(num), " port %u",
		    ntohs(rule->divert.port));
		luaL_addstring(b, num);
	}
}

/* The "set (...)" group: what the rule assigns to a matching packet. */
static bool
hassetopts(const struct pf_rule *rule)
{
	return (rule->scrub_flags & PFSTATE_SETMASK) != 0 ||
	       rule->qname[0] != '\0' ||
	       (rule->rule_flag & PFRULE_SETDELAY) != 0;
}

static void
addsetopts(luaL_Buffer *b, const struct pf_rule *rule)
{
	bool first = true;
	char num[32];

	if (!hassetopts(rule))
		return;

	luaL_addstring(b, " set (");

	if (rule->scrub_flags & PFSTATE_SETPRIO) {
		addcomma(b, &first);
		if (rule->set_prio[0] == rule->set_prio[1])
			snprintf(num, sizeof(num), "prio %u",
			    rule->set_prio[0]);
		else
			snprintf(num, sizeof(num), "prio(%u, %u)",
			    rule->set_prio[0], rule->set_prio[1]);
		luaL_addstring(b, num);
	}

	if (rule->qname[0] != '\0') {
		addcomma(b, &first);
		luaL_addstring(b, "queue");
		if (rule->pqname[0] != '\0') {
			luaL_addchar(b, '(');
			addbounded(b, rule->qname, sizeof(rule->qname));
			luaL_addstring(b, ", ");
			addbounded(b, rule->pqname, sizeof(rule->pqname));
			luaL_addchar(b, ')');
		} else {
			luaL_addchar(b, ' ');
			addbounded(b, rule->qname, sizeof(rule->qname));
		}
	}

	if (rule->scrub_flags & PFSTATE_SETTOS) {
		addcomma(b, &first);
		snprintf(num, sizeof(num), "tos 0x%2.2x", rule->set_tos);
		luaL_addstring(b, num);
	}

	if (rule->rule_flag & PFRULE_SETDELAY) {
		addcomma(b, &first);
		snprintf(num, sizeof(num), "delay %u", rule->delay);
		luaL_addstring(b, num);
	}

	luaL_addchar(b, ')');
}

static void
addport(luaL_Buffer *b, const struct pf_rule_addr *ra)
{
	if (opname(ra->port_op) == NULL)
		return;

	luaL_addstring(b, " port ");
	addoperands(b, ra->port_op, ntohs(ra->port[0]), ntohs(ra->port[1]));
}

static bool
addrisany(const struct pf_rule_addr *ra)
{
	return ra->addr.type == PF_ADDR_ADDRMASK && !ra->neg &&
	       ra->port_op == PF_OP_NONE && addriszero(&ra->addr.v.a.addr) &&
	       addriszero(&ra->addr.v.a.mask);
}

/*
 * pfctl prints "all" when neither endpoint constrains anything. An OS
 * fingerprint is written between the two endpoints, so a rule carrying one
 * has to spell "from ... to ..." out to leave anywhere to put it.
 */
static bool
ruleisany(const struct pf_rule *rule)
{
	return rule->os_fingerprint == PF_OSFP_ANY && addrisany(&rule->src) &&
	       addrisany(&rule->dst);
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

/*
 * pfctl leaves a nat pool's port silent when it spans the default proxy
 * range, because that range is what "nat-to" means with no port given.
 */
#define NAT_PROXY_PORT_LOW  50001
#define NAT_PROXY_PORT_HIGH 65535

/* Which of a rule's three pools is in hand, since each prints its port
 * differently and a route pool has no port at all. */
enum poolkind { POOL_NAT, POOL_RDR, POOL_ROUTE };

static const char *
pooltypename(uint8_t opts)
{
	switch (opts & PF_POOL_TYPEMASK) {
	case PF_POOL_BITMASK:
		return "bitmask";
	case PF_POOL_RANDOM:
		return "random";
	case PF_POOL_SRCHASH:
		return "source-hash";
	case PF_POOL_ROUNDROBIN:
		return "round-robin";
	case PF_POOL_LEASTSTATES:
		return "least-states";
	default:
		return NULL;
	}
}

static const char *
routename(uint8_t rt)
{
	switch (rt) {
	case PF_ROUTETO:
		return "route-to";
	case PF_DUPTO:
		return "dup-to";
	case PF_REPLYTO:
		return "reply-to";
	default:
		return NULL;
	}
}

/* True when the pool names a target rather than sitting unused. */
static bool
poolisset(const struct pf_pool *p)
{
	return p->addr.type != PF_ADDR_NONE &&
	       !(p->addr.type == PF_ADDR_ADDRMASK &&
	         addriszero(&p->addr.v.a.addr) && p->ifname[0] == '\0');
}

/*
 * The pool a rule's redirect properties describe. A rule may carry more
 * than one, so the order here is the order pfctl prints them.
 */
static const struct pf_pool *
rulepool(const struct pf_rule *rule, enum poolkind *kind, const char **keyword)
{
	if (poolisset(&rule->nat)) {
		*kind = POOL_NAT;
		*keyword = (rule->rule_flag & PFRULE_AFTO) ? "af-to" : "nat-to";
		return &rule->nat;
	}

	if (poolisset(&rule->rdr)) {
		*kind = POOL_RDR;
		*keyword = "rdr-to";
		return &rule->rdr;
	}

	if (routename(rule->rt) != NULL) {
		*kind = POOL_ROUTE;
		*keyword = routename(rule->rt);
		return &rule->route;
	}

	return NULL;
}

/* The address family a pool's target is written in. An af-to rule
 * translates into naf, so its nat pool is read in that family. */
static sa_family_t
poolaf(const struct pf_rule *rule, enum poolkind kind)
{
	if (kind == POOL_NAT && rule->naf != 0)
		return rule->naf;

	return rule->af;
}

static void
addpooladdr(lua_State *L, luaL_Buffer *b, const struct pf_pool *p,
            sa_family_t af)
{
	/* A pool bound to an interface prints addr@if, or the bare
	 * interface when it has no address of its own. */
	if (p->ifname[0] != '\0') {
		if (!addriszero(&p->addr.v.a.addr)) {
			addaddrwrap(L, b, &p->addr, af);
			luaL_addchar(b, '@');
		}
		addbounded(b, p->ifname, sizeof(p->ifname));
		return;
	}

	addaddrwrap(L, b, &p->addr, af);
}

/* True when the pool's ports say something the reader needs. */
static bool
poolhasport(const struct pf_pool *p, enum poolkind kind)
{
	switch (kind) {
	case POOL_NAT:
		return (p->proxy_port[0] != NAT_PROXY_PORT_LOW ||
		           p->proxy_port[1] != NAT_PROXY_PORT_HIGH) &&
		       (p->proxy_port[0] != 0 || p->proxy_port[1] != 0);
	case POOL_RDR:
		return p->proxy_port[0] != 0;
	default:
		return false;
	}
}

/* A nat pool with both ports zero keeps the source port unchanged. */
static bool
poolisstaticport(const struct pf_pool *p, enum poolkind kind)
{
	return kind == POOL_NAT && p->proxy_port[0] == 0 &&
	       p->proxy_port[1] == 0;
}

static void
addpool(lua_State *L, luaL_Buffer *b, const struct pf_pool *p,
        enum poolkind kind, sa_family_t af)
{
	const char *type = pooltypename(p->opts);
	char num[16];

	addpooladdr(L, b, p, af);

	if (poolhasport(p, kind)) {
		snprintf(num, sizeof(num), " port %u", p->proxy_port[0]);
		luaL_addstring(b, num);
		if (p->proxy_port[1] != 0 &&
		    p->proxy_port[1] != p->proxy_port[0]) {
			snprintf(num, sizeof(num), ":%u", p->proxy_port[1]);
			luaL_addstring(b, num);
		}
	}

	if (type != NULL) {
		luaL_addchar(b, ' ');
		luaL_addstring(b, type);
	}

	if (p->opts & PF_POOL_STICKYADDR)
		luaL_addstring(b, " sticky-address");

	if (poolisstaticport(p, kind))
		luaL_addstring(b, " static-port");
}

/* Appends every translation and routing target the rule carries. */
static void
addtranslation(lua_State *L, luaL_Buffer *b, const struct pf_rule *rule)
{
	if (poolisset(&rule->nat)) {
		luaL_addstring(b,
		    (rule->rule_flag & PFRULE_AFTO) ? " af-to " : " nat-to ");
		addpool(L, b, &rule->nat, POOL_NAT, poolaf(rule, POOL_NAT));
	}

	if (poolisset(&rule->rdr)) {
		luaL_addstring(b, " rdr-to ");
		addpool(L, b, &rule->rdr, POOL_RDR, rule->af);
	}

	if (routename(rule->rt) != NULL) {
		luaL_addchar(b, ' ');
		luaL_addstring(b, routename(rule->rt));
		luaL_addchar(b, ' ');
		addpool(L, b, &rule->route, POOL_ROUTE, rule->af);
	}
}

static int
rule_redirect(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	enum poolkind kind;
	const char *keyword;

	if (rulepool(&r->rule, &kind, &keyword) == NULL)
		lua_pushnil(L);
	else
		lua_pushstring(L, keyword);

	return 1;
}

static int
rule_redirect_address(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	enum poolkind kind;
	const char *keyword;
	const struct pf_pool *p = rulepool(&r->rule, &kind, &keyword);
	luaL_Buffer b;

	if (p == NULL) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);
	addpooladdr(L, &b, p, poolaf(&r->rule, kind));
	luaL_pushresult(&b);

	return 1;
}

static int
pushpoolport(lua_State *L, int idx, int which)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	enum poolkind kind;
	const char *keyword;
	const struct pf_pool *p = rulepool(&r->rule, &kind, &keyword);

	if (p == NULL || !poolhasport(p, kind))
		lua_pushnil(L);
	else if (which == 1 && (p->proxy_port[1] == 0 ||
	                           p->proxy_port[1] == p->proxy_port[0]))
		/* A single translated port has no upper bound to report,
		 * the same reason pfctl leaves one off the line. */
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)p->proxy_port[which]);

	return 1;
}

static int
rule_redirect_port(lua_State *L, int idx)
{
	return pushpoolport(L, idx, 0);
}

static int
rule_redirect_port_end(lua_State *L, int idx)
{
	return pushpoolport(L, idx, 1);
}

static int
rule_pool_type(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	enum poolkind kind;
	const char *keyword;
	const struct pf_pool *p = rulepool(&r->rule, &kind, &keyword);
	const char *type = p == NULL ? NULL : pooltypename(p->opts);

	if (type == NULL)
		lua_pushnil(L);
	else
		lua_pushstring(L, type);

	return 1;
}

static int
rule_sticky_address(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	enum poolkind kind;
	const char *keyword;
	const struct pf_pool *p = rulepool(&r->rule, &kind, &keyword);

	lua_pushboolean(L, p != NULL && (p->opts & PF_POOL_STICKYADDR) != 0);

	return 1;
}

static int
rule_static_port(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	enum poolkind kind;
	const char *keyword;
	const struct pf_pool *p = rulepool(&r->rule, &kind, &keyword);

	lua_pushboolean(L, p != NULL && poolisstaticport(p, kind));

	return 1;
}

static int
pushugid(lua_State *L, uint8_t op, uintmax_t v0, uintmax_t v1)
{
	luaL_Buffer b;

	if (opname(op) == NULL) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);
	addoperands(&b, op, v0, v1);
	luaL_pushresult(&b);

	return 1;
}

static int
rule_user(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushugid(L, r->rule.uid.op, r->rule.uid.uid[0],
	    r->rule.uid.uid[1]);
}

static int
rule_group(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushugid(L, r->rule.gid.op, r->rule.gid.gid[0],
	    r->rule.gid.gid[1]);
}

static int
rule_flags(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	luaL_Buffer b;

	if (r->rule.flags == 0 && r->rule.flagset == 0) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);
	addflagspec(&b, &r->rule);
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

/* True when the rule matches every interface EXCEPT `interface`. */
static int
rule_interface_not(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, r->rule.ifnot != 0);

	return 1;
}

static int
rule_keep_state(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	switch (r->rule.keep_state) {
	case PF_STATE_NORMAL:
		lua_pushstring(L, "normal");
		break;
	case PF_STATE_MODULATE:
		lua_pushstring(L, "modulate");
		break;
	case PF_STATE_SYNPROXY:
		lua_pushstring(L, "synproxy");
		break;
	default:
		lua_pushnil(L);
	}

	return 1;
}

/* A field whose zero means "unset" reads better as nil than as 0. */
static int
pushoptint(lua_State *L, lua_Integer v)
{
	if (v == 0)
		lua_pushnil(L);
	else
		lua_pushinteger(L, v);

	return 1;
}

static int
pushruleflag(lua_State *L, int idx, uint32_t bit)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, (r->rule.rule_flag & bit) != 0);

	return 1;
}

static int
rule_fragment(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_FRAGMENT);
}

static int
rule_no_sync(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_NOSYNC);
}

static int
rule_if_bound(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_IFBOUND);
}

static int
rule_sloppy(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_STATESLOPPY);
}

static int
rule_pflow(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_PFLOW);
}

static int
rule_once(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_ONCE);
}

static int
rule_expired(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_EXPIRED);
}

static int
rule_af_to(lua_State *L, int idx)
{
	return pushruleflag(L, idx, PFRULE_AFTO);
}

/* Which pool of source nodes the rule counts against, if it counts at all. */
static int
rule_source_track(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if ((r->rule.rule_flag & PFRULE_SRCTRACK) == 0)
		lua_pushnil(L);
	else
		lua_pushstring(L,
		    (r->rule.rule_flag & PFRULE_RULESRCTRACK) ? "rule" :
		                                                "global");

	return 1;
}

static int
rule_delay(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if ((r->rule.rule_flag & PFRULE_SETDELAY) == 0)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)r->rule.delay);

	return 1;
}

static int
rule_return_policy(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if (r->rule.action != PF_DROP)
		lua_pushnil(L);
	else if (r->rule.rule_flag & PFRULE_RETURN)
		lua_pushstring(L, "return");
	else if (r->rule.rule_flag & PFRULE_RETURNRST)
		lua_pushstring(L, "return-rst");
	else if (r->rule.rule_flag & PFRULE_RETURNICMP)
		lua_pushstring(L, "return-icmp");
	else
		lua_pushstring(L, "drop");

	return 1;
}

static int
rule_return_ttl(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if ((r->rule.rule_flag & PFRULE_RETURNRST) == 0)
		return pushoptint(L, 0);

	return pushoptint(L, (lua_Integer)r->rule.return_ttl);
}

static int
pushreturnicmp(lua_State *L, int idx, sa_family_t af)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	luaL_Buffer b;

	if ((r->rule.rule_flag & PFRULE_RETURNICMP) == 0) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);
	addreturnicmp(&b, af == AF_INET6 ? r->rule.return_icmp6 :
	                                   r->rule.return_icmp,
	    af);
	luaL_pushresult(&b);

	return 1;
}

static int
rule_return_icmp(lua_State *L, int idx)
{
	return pushreturnicmp(L, idx, AF_INET);
}

static int
rule_return_icmp6(lua_State *L, int idx)
{
	return pushreturnicmp(L, idx, AF_INET6);
}

static int
rule_rdomain(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if (r->rule.onrdomain < 0)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)r->rule.onrdomain);

	return 1;
}

static int
rule_rtable(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if (r->rule.rtableid < 0)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)r->rule.rtableid);

	return 1;
}

static int
rule_probability(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if (r->rule.prob == 0)
		lua_pushnil(L);
	else
		lua_pushnumber(L,
		    (lua_Number)r->rule.prob * 100.0 / ((double)UINT_MAX + 1.0));

	return 1;
}

static int
rule_allow_opts(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, r->rule.allow_opts != 0);

	return 1;
}

static int
rule_min_ttl(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushoptint(L, (lua_Integer)r->rule.min_ttl);
}

static int
rule_max_mss(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushoptint(L, (lua_Integer)r->rule.max_mss);
}

static int
rule_tos(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushoptint(L, (lua_Integer)r->rule.tos);
}

static int
rule_set_tos(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if ((r->rule.scrub_flags & PFSTATE_SETTOS) == 0)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)r->rule.set_tos);

	return 1;
}

static int
pushscrubflag(lua_State *L, int idx, uint16_t bit)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, (r->rule.scrub_flags & bit) != 0);

	return 1;
}

static int
rule_no_df(lua_State *L, int idx)
{
	return pushscrubflag(L, idx, PFSTATE_NODF);
}

static int
rule_random_id(lua_State *L, int idx)
{
	return pushscrubflag(L, idx, PFSTATE_RANDOMID);
}

static int
rule_reassemble_tcp(lua_State *L, int idx)
{
	return pushscrubflag(L, idx, PFSTATE_SCRUB_TCP);
}

static int
rule_match_tag(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	pushbounded(L, r->rule.match_tagname, sizeof(r->rule.match_tagname));

	return 1;
}

/* True when the rule matches every tag EXCEPT `match_tag`. */
static int
rule_match_tag_not(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, r->rule.match_tag_not != 0);

	return 1;
}

/*
 * The packed fingerprint identifier, not a name: naming it needs pfctl's
 * own numbering of /etc/pf.os, which this binding does not read. For the
 * same reason __tostring leaves the fingerprint out of the rendered rule.
 */
static int
rule_os_fingerprint(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if (r->rule.os_fingerprint == PF_OSFP_ANY)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)r->rule.os_fingerprint);

	return 1;
}

static int
rule_anchor_relative(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.anchor_relative);

	return 1;
}

static int
rule_anchor_wildcard(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushboolean(L, r->rule.anchor_wildcard != 0);

	return 1;
}

static int
rule_divert(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	const char *name = divertname(r->rule.divert.type);

	if (name == NULL)
		lua_pushnil(L);
	else
		lua_pushstring(L, name);

	return 1;
}

static int
rule_divert_address(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);
	luaL_Buffer b;

	if (r->rule.divert.type != PF_DIVERT_TO) {
		lua_pushnil(L);
		return 1;
	}

	luaL_buffinit(L, &b);
	addaddr(L, &b, r->rule.af, &r->rule.divert.addr);
	luaL_pushresult(&b);

	return 1;
}

static int
rule_divert_port(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if (divertname(r->rule.divert.type) == NULL ||
	    r->rule.divert.type == PF_DIVERT_REPLY)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)ntohs(r->rule.divert.port));

	return 1;
}

/*
 * How many addresses a dynamic interface or a table resolves to right now.
 * pfctl shows the same counts under -vv as (em0:2) and &lt;tbl:5&gt;.
 * A table pf has not yet resolved reports -1.
 */
static int
pushaddrcount(lua_State *L, const struct pf_addr_wrap *aw)
{
	switch (aw->type) {
	case PF_ADDR_DYNIFTL:
		lua_pushinteger(L, (lua_Integer)aw->p.dyncnt);
		break;
	case PF_ADDR_TABLE:
		lua_pushinteger(L, (lua_Integer)aw->p.tblcnt);
		break;
	default:
		lua_pushnil(L);
	}

	return 1;
}

static int
rule_source_addresses(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushaddrcount(L, &r->rule.src.addr);
}

static int
rule_destination_addresses(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushaddrcount(L, &r->rule.dst.addr);
}

static int
rule_src_nodes(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.src_nodes);

	return 1;
}

static int
rule_max_pkt_rate(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushoptint(L, (lua_Integer)r->rule.pktrate.limit);
}

static int
rule_max_pkt_rate_seconds(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	if (r->rule.pktrate.limit == 0)
		lua_pushnil(L);
	else
		lua_pushinteger(L, (lua_Integer)r->rule.pktrate.seconds);

	return 1;
}

static int
rule_pkt_rate_count(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.pktrate.count);

	return 1;
}

static int
rule_pkt_rate_last(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.pktrate.last);

	return 1;
}

static int
rule_created_uid(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.cuid);

	return 1;
}

static int
rule_created_pid(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	lua_pushinteger(L, (lua_Integer)r->rule.cpid);

	return 1;
}

static int
rule_expires(lua_State *L, int idx)
{
	struct luapfrule *r = luaL_checkudata(L, idx, PFRULE_MT);

	return pushoptint(L, (lua_Integer)r->rule.exptime);
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
    {"interface_not", rule_interface_not},
    {"evaluations",  rule_evaluations },
    {"packets_in",   rule_packets_in  },
    {"packets_out",  rule_packets_out },
    {"bytes_in",     rule_bytes_in    },
    {"bytes_out",    rule_bytes_out   },
    {"states_cur",   rule_states_cur  },
    {"states_total", rule_states_total},
    {"user",         rule_user        },
    {"group",        rule_group       },
    {"flags",        rule_flags       },
    {"redirect",     rule_redirect    },
    {"redirect_address", rule_redirect_address},
    {"redirect_port", rule_redirect_port},
    {"redirect_port_end", rule_redirect_port_end},
    {"pool_type",    rule_pool_type   },
    {"sticky_address", rule_sticky_address},
    {"static_port",  rule_static_port },
    {"rdomain",      rule_rdomain     },
    {"rtable",       rule_rtable      },
    {"return_policy", rule_return_policy},
    {"return_ttl",   rule_return_ttl  },
    {"return_icmp",  rule_return_icmp },
    {"return_icmp6", rule_return_icmp6},
    {"fragment",     rule_fragment    },
    {"no_sync",      rule_no_sync     },
    {"source_track", rule_source_track},
    {"if_bound",     rule_if_bound    },
    {"sloppy",       rule_sloppy      },
    {"pflow",        rule_pflow       },
    {"once",         rule_once        },
    {"expired",      rule_expired     },
    {"af_to",        rule_af_to       },
    {"delay",        rule_delay       },
    {"probability",  rule_probability },
    {"allow_opts",   rule_allow_opts  },
    {"min_ttl",      rule_min_ttl     },
    {"max_mss",      rule_max_mss     },
    {"tos",          rule_tos         },
    {"set_tos",      rule_set_tos     },
    {"no_df",        rule_no_df       },
    {"random_id",    rule_random_id   },
    {"reassemble_tcp", rule_reassemble_tcp},
    {"match_tag",    rule_match_tag   },
    {"match_tag_not", rule_match_tag_not},
    {"os_fingerprint", rule_os_fingerprint},
    {"anchor_relative", rule_anchor_relative},
    {"anchor_wildcard", rule_anchor_wildcard},
    {"divert",       rule_divert      },
    {"divert_address", rule_divert_address},
    {"divert_port",  rule_divert_port },
    {"source_addresses", rule_source_addresses},
    {"destination_addresses", rule_destination_addresses},
    {"src_nodes",    rule_src_nodes   },
    {"max_pkt_rate", rule_max_pkt_rate},
    {"max_pkt_rate_seconds", rule_max_pkt_rate_seconds},
    {"pkt_rate_count", rule_pkt_rate_count},
    {"pkt_rate_last", rule_pkt_rate_last},
    {"created_uid",  rule_created_uid },
    {"created_pid",  rule_created_pid },
    {"expires",      rule_expires     },
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
Render a rule exactly as a pfctl -s rules line prints it, except for an OS
fingerprint: naming one needs pfctl's own numbering of /etc/pf.os. Such a
rule still writes "from ... to ..." rather than "all".
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

	if (r->anchor_call[0] == '\0' && r->rule.action == PF_DROP)
		addreturn(&b, &r->rule);

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
		/* Without this the rule reads as matching exactly the
		 * interface it is written to exclude. */
		if (r->rule.ifnot)
			luaL_addstring(&b, "! ");
		addbounded(&b, r->rule.ifname, sizeof(r->rule.ifname));
	}

	/* A rule bound to one routing domain does not see the others, so
	 * without this it reads as applying everywhere. */
	if (r->rule.onrdomain >= 0) {
		char num[32];

		snprintf(num, sizeof(num), " on %srdomain %d",
		    r->rule.ifnot ? "! " : "", r->rule.onrdomain);
		luaL_addstring(&b, num);
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

	if (ruleisany(&r->rule)) {
		luaL_addstring(&b, " all");
	} else {
		luaL_addstring(&b, " from ");
		pushruleaddr(L, &r->rule.src, r->rule.af);
		luaL_addvalue(&b);

		luaL_addstring(&b, " to ");
		pushruleaddr(L, &r->rule.dst, r->rule.af);
		luaL_addvalue(&b);
	}

	/* The interface the packet came in on, which a rule can test long
	 * after the interface it is being evaluated on. */
	if (r->rule.rcv_ifname[0] != '\0') {
		luaL_addstring(&b, " received-on ");
		if (r->rule.rcvifnot)
			luaL_addstring(&b, "! ");
		addbounded(&b, r->rule.rcv_ifname,
		    sizeof(r->rule.rcv_ifname));
	}

	addicmp(&b, &r->rule);

	if (opname(r->rule.uid.op) != NULL) {
		luaL_addstring(&b, " user ");
		addoperands(&b, r->rule.uid.op, r->rule.uid.uid[0],
		    r->rule.uid.uid[1]);
	}

	if (opname(r->rule.gid.op) != NULL) {
		luaL_addstring(&b, " group ");
		addoperands(&b, r->rule.gid.op, r->rule.gid.gid[0],
		    r->rule.gid.gid[1]);
	}

	if (r->rule.flags != 0 || r->rule.flagset != 0) {
		luaL_addstring(&b, " flags ");
		addflagspec(&b, &r->rule);
	}

	if (r->rule.tos != 0) {
		char num[24];

		snprintf(num, sizeof(num), " tos 0x%2.2x", r->rule.tos);
		luaL_addstring(&b, num);
	}

	if (r->rule.pktrate.limit != 0) {
		char num[32];

		snprintf(num, sizeof(num), " max-pkt-rate %u/%u",
		    r->rule.pktrate.limit, r->rule.pktrate.seconds);
		luaL_addstring(&b, num);
	}

	addsetopts(&b, &r->rule);
	addstatekeyword(&b, &r->rule, r->anchor_call[0] != '\0');
	addprob(&b, &r->rule);

	if (r->rule.keep_state != 0 && hasstateopts(&r->rule))
		addstateopts(&b, &r->rule);

	if (r->rule.rule_flag & PFRULE_FRAGMENT)
		luaL_addstring(&b, " fragment");

	addscrubopts(&b, &r->rule);

	if (r->rule.allow_opts)
		luaL_addstring(&b, " allow-opts");

	if (r->rule.label[0] != '\0') {
		luaL_addstring(&b, " label \"");
		addbounded(&b, r->rule.label, sizeof(r->rule.label));
		luaL_addchar(&b, '"');
	}

	if (r->rule.rule_flag & PFRULE_ONCE)
		luaL_addstring(&b, " once");

	if (r->rule.tagname[0] != '\0') {
		luaL_addstring(&b, " tag ");
		addbounded(&b, r->rule.tagname, sizeof(r->rule.tagname));
	}

	if (r->rule.match_tagname[0] != '\0') {
		luaL_addstring(&b, r->rule.match_tag_not ? " ! tagged " :
		                                           " tagged ");
		addbounded(&b, r->rule.match_tagname,
		    sizeof(r->rule.match_tagname));
	}

	if (r->rule.rtableid >= 0) {
		char num[32];

		snprintf(num, sizeof(num), " rtable %d", r->rule.rtableid);
		luaL_addstring(&b, num);
	}

	adddivert(L, &b, &r->rule);
	addtranslation(L, &b, &r->rule);

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
keep_state, interface, interface_not, label, tag, anchor, anchor_call,
source, destination, evaluations, packets_in, packets_out, bytes_in,
bytes_out, states_cur, states_total, user, group, flags, redirect,
redirect_address, redirect_port, redirect_port_end, pool_type,
sticky_address, static_port, rdomain, rtable, return_policy, return_ttl,
return_icmp, return_icmp6, fragment, no_sync, source_track, if_bound,
sloppy, pflow, once, expired, af_to, delay, probability, allow_opts,
min_ttl, max_mss, tos, set_tos, no_df, random_id, reassemble_tcp,
match_tag, match_tag_not, os_fingerprint, anchor_relative,
anchor_wildcard, divert, divert_address, divert_port, source_addresses,
destination_addresses, src_nodes, max_pkt_rate, max_pkt_rate_seconds,
pkt_rate_count, pkt_rate_last, created_uid, created_pid and expires.

Source and destination render the way pfctl prints them, tables as
&lt;name&gt; and interfaces as (name). interface_not says the rule matches
every interface except the one named, and match_tag_not says the same of
match_tag. anchor is not kernel data: DIOCGETRULE never writes it, so a
rule only ever reports the anchor its ruleset was read from.

keep_state is "normal", "modulate", "synproxy", or nil on a rule that
keeps no state. user and group render a comparison such as "= 55" or
"1000 &gt;&lt; 2000", or are nil when the rule constrains neither. flags
renders the TCP flag pair as "S/SA", or is nil.

The redirect properties describe one pool. A rule may carry a nat, an rdr
and a routing pool at once; the properties report the first of those, which
is the order pfctl prints them in. redirect is the keyword ("nat-to",
"af-to", "rdr-to", "route-to", "reply-to" or "dup-to"), redirect_address
the target as pfctl writes it, and redirect_port the translated port.
redirect_port_end is the top of a translated port range, and nil when the
pool translates to a single port. pool_type is one of "bitmask", "random",
"source-hash",
"round-robin" or "least-states", and sticky_address and static_port the
two pool options. Every one of them is nil, or false, on a rule that
translates nothing.

rdomain is the routing domain the rule is confined to, rtable the routing
table it looks packets up in, and both are nil when the rule names neither.
return_policy is "drop", "return", "return-rst" or "return-icmp" on a block
rule and nil on any other; return_ttl, return_icmp and return_icmp6 carry
the answer that policy sends, and are nil when it sends none.

probability is a percentage. tos, set_tos, min_ttl, max_mss and delay are
nil when the rule sets none of them. divert is "divert-to", "divert-reply"
or "divert-packet", with divert_address and divert_port beside it.
os_fingerprint is the packed identifier, not a name.

source_addresses and destination_addresses say how many addresses a
dynamic interface or a table resolves to right now, the counts pfctl shows
under -vv; a table pf has not resolved reports -1, and an ordinary address
reports nil. src_nodes is the number of source nodes the rule holds.
max_pkt_rate and max_pkt_rate_seconds are the limit the rule was given,
pkt_rate_count and pkt_rate_last how close it stands to it. created_uid
and created_pid name whoever loaded the rule, and expires is when a "once"
rule went away.
@table rule
*/
