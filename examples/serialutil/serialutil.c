/* SPDX-License-Identifier: ISC */

/* serialutil: the one C module luapf_console.lua needs to drive a vmd
 * guest's serial console from the host -- open a raw tty, and ask
 * whether a read on it would block. Vendored in from nlos's
 * test/hostutil.c rather than depended on: this repo's disposable-VM
 * PF test harness has to build and run on its own, without another
 * project's tree checked out beside it.
 *
 * Trimmed to just what luapf_console.lua actually calls: serial(),
 * fileno(), readable(), sleep(). nlos's original also has socket
 * connect/listen/send/recv and fork+exec process spawning, for driving
 * boards over USB and for its own test suite's host-side network
 * clients; none of that is needed here, since file transfer to the
 * guest goes over the same tty as everything else (see
 * luapf_console.lua's push(): base64 through exec(), not a spawned
 * ZMODEM sender) rather than a second process wired to the port.
 *
 * A HOST tool, built native regardless of what the rest of luapf
 * targets -- this runs on the machine driving the VM, never inside it.
 */

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/types.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include <lauxlib.h>
#include <lua.h>

/* readable(fd [, timeout]) -> true | false
 *
 * Whether a read would return without blocking. serial() hands back a
 * blocking line on purpose (see there: a timeout is a zero-length read
 * and stdio cannot tell that from eof), which leaves a caller no way to
 * ask for something a guest might never say. select answers it without
 * touching the stream.
 */
static int
l_readable(lua_State *L)
{
	int fd = (int)luaL_checkinteger(L, 1);
	double timeout = luaL_optnumber(L, 2, 0.0);
	struct timeval tv;
	fd_set r;
	int n;

	FD_ZERO(&r);
	FD_SET(fd, &r);
	tv.tv_sec = (time_t)timeout;
	tv.tv_usec = (suseconds_t)((timeout - (double)tv.tv_sec) * 1e6);

	n = select(fd + 1, &r, NULL, NULL, &tv);
	lua_pushboolean(L, n > 0);
	return 1;
}

/* fileno(file) -> fd */
static int
l_fileno(lua_State *L)
{
	luaL_Stream *s = (luaL_Stream *)luaL_checkudata(L, 1, LUA_FILEHANDLE);

	lua_pushinteger(L, fileno(s->f));
	return 1;
}

/* now() -> milliseconds on a monotonic clock.
 *
 * os.clock() is CPU time, which is the wrong thing to measure a
 * protocol deadline with: a driver that spins while its peer is
 * starved burns the budget on itself and times out a peer that is
 * merely slow. CLOCK_MONOTONIC also does not step when the wall clock
 * is adjusted.
 */
static int
l_now(lua_State *L)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	lua_pushinteger(L, (lua_Integer)ts.tv_sec * 1000 +
	    ts.tv_nsec / 1000000);
	return 1;
}

/* sleep(seconds) -- without forking /bin/sleep to do it. */
static int
l_sleep(lua_State *L)
{
	double sec = luaL_checknumber(L, 1);
	struct timespec ts;

	if (sec < 0)
		sec = 0;
	ts.tv_sec = (time_t)sec;
	ts.tv_nsec = (long)((sec - (double)ts.tv_sec) * 1e9);

	/* a signal must not shorten the wait: resume what is left */
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
	return 0;
}

/* the close method lua's io library calls on our file handles. */
static int
l_closef(lua_State *L)
{
	luaL_Stream *s = (luaL_Stream *)luaL_checkudata(L, 1, LUA_FILEHANDLE);
	int rc = s->f ? fclose(s->f) : 0;

	s->f = 0;
	return luaL_fileresult(L, rc == 0, NULL);
}

/* serial(path [, baud]) -> file
 *
 * A tty opened as a lua file, so read/write/lines/setvbuf are the ones
 * already in io.
 *
 * No CLOCAL: this opens vmd(8) pty slaves, and a BSD pty whose slave
 * ignores modem control never hangs up when the master closes (see
 * /usr/src/sys/kern/tty_pty.c's ptcclose() -> ttymodem(tp, 0), and
 * ttread()'s `carrier = TS_CARR_ON || CLOCAL` check in
 * /usr/src/sys/kern/tty.c) -- a blocked read on it would otherwise
 * never wake up when the guest dies mid-wait, which is exactly the
 * hang this project hit before finding the cause. HUPCL is also off,
 * so closing our end doesn't itself drop DTR back at vmd.
 *
 * O_NONBLOCK on the open is the ordinary tty courtesy -- do not wait
 * for carrier -- and is cleared right after, because the only reads
 * here go through stdio, which wants a blocking fd and gets VMIN=1 /
 * VTIME=0 below instead: block until at least one byte rather than
 * time out, since a VTIME expiry is a zero-length read that stdio
 * latches as EOF, and lua's io has no clearerr to undo that.
 *
 * Raw: no line discipline, no echo, no CR/LF translation.
 *
 * O_NOCTTY: this must not become the calling process's controlling
 * terminal, or a hangup on the line would signal the driver itself
 * rather than just waking its blocked read.
 */
static int
l_serial(lua_State *L)
{
	const char *path = luaL_checkstring(L, 1);
	lua_Integer baud = luaL_optinteger(L, 2, 115200);
	speed_t sp;
	struct termios t;
	luaL_Stream *s;
	int fd;

	switch (baud) {
	case 9600: sp = B9600; break;
	case 19200: sp = B19200; break;
	case 38400: sp = B38400; break;
	case 57600: sp = B57600; break;
	case 115200: sp = B115200; break;
	case 230400: sp = B230400; break;
#ifdef B460800
	case 460800: sp = B460800; break;
#endif
#ifdef B921600
	case 921600: sp = B921600; break;
#endif
	default:
		return luaL_error(L, "unsupported baud %d", (int)baud);
	}

	fd = open(path, O_RDWR | O_NOCTTY | O_NONBLOCK);
	if (fd < 0) {
		lua_pushnil(L);
		lua_pushstring(L, strerror(errno));
		return 2;
	}
	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) & ~O_NONBLOCK);
	if (tcgetattr(fd, &t) == 0) {
		cfmakeraw(&t);
		cfsetispeed(&t, sp);
		cfsetospeed(&t, sp);
		t.c_cflag |= CREAD;
		t.c_cflag &= ~(unsigned)(CLOCAL | HUPCL);
		t.c_cc[VMIN] = 1;
		t.c_cc[VTIME] = 0;
		tcsetattr(fd, TCSANOW, &t);
	}

	s = (luaL_Stream *)lua_newuserdatauv(L, sizeof *s, 0);
	s->closef = 0;
	luaL_setmetatable(L, LUA_FILEHANDLE);
	s->f = fdopen(fd, "r+");
	if (!s->f) {
		close(fd);
		lua_pushnil(L);
		lua_pushstring(L, "fdopen");
		return 2;
	}
	/* unbuffered: a prompt that arrives without a newline must be
	 * readable, and a command must go out when written.
	 *
	 * Callers must still f:flush() before reading after a write. The
	 * stream is read/write, and C requires the direction change be
	 * separated by a flush or a seek whatever the buffering -- skip
	 * it and the read blocks forever on a line that is working fine.
	 */
	setvbuf(s->f, NULL, _IONBF, 0);
	s->closef = l_closef;
	return 1;
}

static const luaL_Reg serialutil[] = {
	{ "serial", l_serial },
	{ "fileno", l_fileno },
	{ "readable", l_readable },
	{ "now", l_now },
	{ "sleep", l_sleep },
	{ NULL, NULL },
};

int
luaopen_serialutil(lua_State *L)
{
	luaL_newlib(L, serialutil);
	return 1;
}
