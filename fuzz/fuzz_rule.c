/* SPDX-License-Identifier: ISC */
/*
 * Fuzz the rule renderer: put fuzzer bytes in a rule userdata, then read
 * every property and render it. This needs no /dev/pf.
 */
#include <limits.h>
#include <string.h>

#include <sys/types.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "pf.h"
#include "fuzz.h"
#include "render.h"
#include "banned.h"

/*
 * struct luapfrule is private to rule.c, but its members are public types.
 * This is an upper bound on its size with room for padding, which is safe:
 * the getters check the metatable, not the length.
 */
enum { rulesize = sizeof(struct pf_rule) + 2 * PATH_MAX + 128 };

static void
run(const unsigned char *buf, size_t len)
{
	lua_State *L = luaL_newstate();

	if (L == NULL)
		return;

	luaL_openlibs(L);
	luapf_rules_register(L);
	luapf_render_case(L, PFRULE_MT, rulesize, buf, len);
	lua_close(L);
}

__AFL_FUZZ_INIT()

int
main(int argc, char *argv[])
{
	if (argc > 1)
		return fuzz_replay(argc, argv, run);

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif

	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;

	while (__AFL_LOOP(10000))
		run(buf, (size_t)__AFL_FUZZ_TESTCASE_LEN);

	return 0;
}
