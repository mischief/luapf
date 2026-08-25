/* SPDX-License-Identifier: ISC */
#ifndef LUAPF_FUZZ_H
#define LUAPF_FUZZ_H

#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

/*
 * AFL++ persistent mode when built with afl-clang-fast, a single case on
 * stdin otherwise. Either way, file arguments replay each named file once,
 * which is how the corpus tests run with no fuzzer installed.
 */

/* NOLINTBEGIN(bugprone-reserved-identifier) -- AFL++ __AFL_* macros */
#ifndef __AFL_FUZZ_TESTCASE_LEN
static ssize_t fuzz_len;
#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
static unsigned char fuzz_buf[65536];
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_INIT() void sync(void);
#define __AFL_LOOP(x)                                                          \
	((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
#define __AFL_INIT() sync()
#endif
/* NOLINTEND(bugprone-reserved-identifier) */

/* Run every named file through the harness. Returns an exit status. */
static inline int
fuzz_replay(int argc, char *argv[], void (*run)(const unsigned char *, size_t))
{
	static unsigned char buf[65536];

	for (int i = 1; i < argc; i++) {
		FILE *f = fopen(argv[i], "rb");
		size_t n;

		if (f == NULL) {
			perror(argv[i]);
			return 1;
		}

		n = fread(buf, 1, sizeof(buf), f);
		(void)fclose(f);
		run(buf, n);
	}

	return 0;
}

#endif /* LUAPF_FUZZ_H */
