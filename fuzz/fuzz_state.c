/* SPDX-License-Identifier: ISC */
/*
 * Fuzz the state renderer. A case is a raw struct pfsync_state, so
 * families, directions and ports arrive unchecked.
 */
#include <string.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/pfvar.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "pf.h"
#include "fuzz.h"
#include "render.h"
#include "banned.h"

static void
run(const unsigned char *buf, size_t len)
{
	lua_State *L = luaL_newstate();

	if (L == NULL)
		return;

	luaL_openlibs(L);
	luapf_states_register(L);
	luapf_render_case(L, PFSTATE_MT, sizeof(struct pfsync_state), buf, len);
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
