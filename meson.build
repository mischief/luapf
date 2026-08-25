project('luapf', 'c',
  meson_version: '>=1.6.0',
  default_options: [
    'c_std=c17',
    'warning_level=3',
    'werror=true',
  ])

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')

# Extra warnings, applied only where the compiler knows them.
hardening_args = [
  '-Wnull-dereference',
  '-Warray-bounds',
  '-Wsign-conversion',
  '-Wformat',
  '-Wformat-security',
  '-Wuninitialized',
  '-Wshadow',
  '-Wimplicit-fallthrough',
  '-Wstrict-prototypes',
  '-Wmissing-prototypes',
  '-Wmissing-declarations',
  '-Wvla',
  '-Walloca',
  '-Wframe-larger-than=8192',
  '-Wno-unused-parameter',
]

if get_option('trap')
  # A trap kills the whole lua interpreter with no message. Test builds only.
  hardening_args += '-fsanitize-trap=all'
endif

foreach a : hardening_args
  if cc.has_argument(a)
    add_project_arguments(a, language: 'c')
  endif
endforeach

which_lua = get_option('lua')

if which_lua == 'luajit'
  install_cmod = get_option('prefix') / 'lib/lua/5.1'
  install_mod = get_option('prefix') / 'share/lua/5.1'
else
  install_cmod = get_option('prefix') / 'lib/lua/' + which_lua.replace('lua', '')
  install_mod = get_option('prefix') / 'share/lua/' + which_lua.replace('lua', '')
endif


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
serialutil = shared_module('serialutil', 'examples/serialutil/serialutil.c',
  dependencies: [lua_dep],
  native: true,
  name_prefix: '',
)

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
'''.split()

foreach t : pf_tests
  test(t,
    doas_bin,
    depends: lua_pf,
    args: [lua_bin, files(t)],
    workdir: meson.current_build_dir()
  )
endforeach


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
