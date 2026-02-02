project('luapf', 'c', meson_version: '>=1.6.0')

cc = meson.get_compiler('c')
pkgconfig = import('pkgconfig')

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
pf.c state.c queue.c table.c
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
'''.split()

foreach t : pf_tests
  test(t,
    doas_bin,
    depends: lua_pf,
    args: [lua_bin, files(t)],
    workdir: meson.current_build_dir()
  )
endforeach

