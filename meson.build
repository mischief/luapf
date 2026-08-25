project('luapf', 'c',
  meson_version: '>=1.6.0',
  default_options: [
    'c_std=c17',
    'warning_level=3',
    'werror=true',
  ])

cc = meson.get_compiler('c')
native_cc = meson.get_compiler('c', native: true)
pkgconfig = import('pkgconfig')

# Extra warnings, applied only where the compiler knows them.
which_lua = get_option('lua')

hardening_args = [
  '-Wnull-dereference',
  '-Warray-bounds',
  '-Wsign-conversion',
  '-Wfloat-equal',
  '-Wformat',
  '-Wformat-security',
  '-Wuninitialized',
  '-Wshadow',
  '-Wimplicit-fallthrough',
  '-Wswitch',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  '-Wmissing-declarations',
  '-Wvla',
  '-Walloca',
  '-Wshift-overflow',
  '-Wreturn-stack-address',
  '-Wuseless-cast',
  # luaL_Buffer sits on the stack and is eight times larger in 5.3 than in
  # 5.4, so the budget is a property of the lua headers rather than of any
  # code here. Every frame over it holds one of those buffers.
  which_lua == 'lua5.3' ? '-Wframe-larger-than=10240' :
    '-Wframe-larger-than=2048',
  '-fno-omit-frame-pointer',
  '-Wno-unused-parameter',
]

if get_option('trap')
  # Trapping UBSan: OpenBSD ships no sanitizer runtime, so a violation has to
  # abort rather than report. A trap kills the whole lua interpreter with no
  # message, which is why this is a test build only.
  hardening_args += '-fsanitize=undefined'
  hardening_args += '-fsanitize-trap=all'

  # Trapping code is not execute-only clean, so opt this build out of W^X.
  foreach a : ['-Wl,--no-execute-only']
    if cc.has_link_argument(a)
      add_project_link_arguments(a, language: 'c')
    endif
    if native_cc.has_link_argument(a)
      add_project_link_arguments(a, language: 'c', native: true)
    endif
  endforeach
endif

# Both machines: add_project_arguments() defaults to the host machine, which
# leaves a native target such as serialutil with the warning_level flags
# alone. Every compiler this project runs gets the same warning set.
foreach a : hardening_args
  if cc.has_argument(a)
    add_project_arguments(a, language: 'c')
  endif
  if native_cc.has_argument(a)
    add_project_arguments(a, language: 'c', native: true)
  endif
endforeach

install_cmod = get_option('prefix') / 'lib/lua/' + which_lua.replace('lua', '')
install_mod = get_option('prefix') / 'share/lua/' + which_lua.replace('lua', '')


cmod_override = get_option('lua-module-directory')
if cmod_override != ''
  install_cmod = cmod_override
endif

dep_name = which_lua
if build_machine.system() == 'openbsd'
  dep_name = dep_name.replace('.', '')
endif

lua_dep = dependency(dep_name)

lua_pf_srcs = '''
pf.c state.c queue.c table.c rule.c anchor.c system.c privsep.c
limiter.c
'''.split()

lua_pf = shared_library('pf',
  lua_pf_srcs,
  name_prefix: '',
  dependencies: [lua_dep],
  install: true,
  install_dir: install_cmod,
  gnu_symbol_visibility: 'hidden',
)

ldoc_bin = find_program('ldoc', required: false)
if ldoc_bin.found()
  documentation = custom_target('ldoc',
    input: files(lua_pf_srcs),
    output: ['index.html', 'ldoc.css'],
    command: [ldoc_bin, '-d', '@OUTDIR@', '@INPUT@'],
  )
endif

doas_bin = find_program('doas')
lua_bin = find_program(dep_name)

# serialutil: the C module examples/luapf_console.lua needs to open a raw
# tty and poll it non-blockingly, for driving a disposable vmd(8) test VM
# entirely over its serial console (see examples/run_pf_vm_tests.sh and
# examples/build_test_vm_base.sh). Native regardless of what -Dlua targets,
# since this runs on the machine driving the VM, not inside it -- and
# vendored here rather than pulled from nlos, so this repo's VM-building
# machinery does not depend on another project's tree being checked out
# beside it.
#
# Its lua comes from a separate native lookup rather than from lua_dep:
# lua_dep is the host lookup, and linking it into a native module would
# be the target lua's headers and library under a cross build. dep_name
# is already spelled for build_machine, so the two agree whenever the
# build is native, which is the case everyone actually configures.
# Not dep_name: this is a host tool that drives a test guest over a serial
# line, so the lua it links is the one running the driver, not whatever
# -Dlua aims the binding at. It calls lua_newuserdatauv, so it wants 5.4
# even when the binding is built for 5.3.
serialutil_lua_dep = dependency('lua5.4', 'lua54', native: true,
  required: false)

if serialutil_lua_dep.found()
  serialutil = shared_module('serialutil', 'examples/serialutil/serialutil.c',
    dependencies: [serialutil_lua_dep],
    native: true,
    name_prefix: '',
  )
endif

# One LUA_CPATH entry reaches every native module this project builds
# (pf.so, serialutil.so, and whatever else lands in the build root),
# rather than a `depends:`/env pair repeated at every test/script that
# needs one of them -- so a script or test says require("pf") or
# require("serialutil") whether meson is running it or a person is:
#
#	eval "$(meson devenv -C build --dump)"
#	doas lua54 pf_test_tables.lua
#	doas lua54 examples/luapf_console.lua ...
#
# Prepended, so the build tree wins: a module installed under one of
# our names -- pf is an ordinary enough word -- must not answer instead
# of the one just built.
#
# The ';;' goes last, as its own append, where lua expands it to the
# compiled-in default. Behind the caller's own entries rather than
# ahead of them, so a module we do not have resolves the way it would
# outside a build, and a module we do have never loses to it.
#
# Registered twice, same as the module list itself is single-sourced:
# once as the devenv above, and again as the default test setup, so
# `meson test` and an interactive `meson devenv` shell see the same
# modules without this list being kept in sync by hand in two places.
# `test()` below still needs `depends:` -- `meson test` only builds what
# the selected tests declare, not `all`, so a module absent from that
# list would simply not exist yet when a subset of tests is run.
lua_host_env = environment()
lua_host_env.prepend('LUA_CPATH', meson.current_build_dir() / '?.so',
  separator: ';')
lua_host_env.append('LUA_CPATH', ';', separator: ';')
meson.add_devenv(lua_host_env)
add_test_setup('default', is_default: true, env: lua_host_env)

pf_tests = '''
pf_test_tables.lua
pf_test_states.lua
pf_test_rules.lua
pf_test_queues.lua
pf_test_system.lua
pf_test_limiters.lua
'''.split()

# Suite 'pf': these open /dev/pf through doas, so they only run on a host
# with a pf ruleset loaded and a doas rule for the user running them.
foreach t : pf_tests
  test(t,
    doas_bin,
    depends: lua_pf,
    args: [lua_bin, files(t)],
    workdir: meson.current_build_dir(),
    suite: 'pf',
  )
endforeach


if get_option('fuzz')
  subdir('fuzz')
endif

cppcheck = find_program('cppcheck', required: false)
if cppcheck.found()
  run_target('cppcheck',
    command: [
      cppcheck,
      '--project=' + meson.project_build_root() / 'compile_commands.json',
      '--enable=warning,style,performance,portability',
      '--std=' + get_option('c_std'),
      '--error-exitcode=1',
    ],
  )
endif
