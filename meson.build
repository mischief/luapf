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
pf.c state.c queue.c table.c rule.c
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
    input: [files('pf.c')],
    output: ['index.html', 'ldoc.css'],
    command: [ldoc_bin, '-d', '@OUTDIR@', '@INPUT@'],
  )
endif

doas_bin = find_program('doas')
lua_bin = find_program(dep_name)

pf_tests = '''
pf_test_tables.lua
pf_test_states.lua
pf_test_rules.lua
'''.split()

foreach t : pf_tests
  test(t,
    doas_bin,
    depends: lua_pf,
    args: [lua_bin, files(t)],
    workdir: meson.current_build_dir()
  )
endforeach

devenv = environment()
devenv.append('LUA_CPATH', meson.current_build_dir() / '?.so', separator: ';')
meson.add_devenv(devenv)


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
