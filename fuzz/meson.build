# Fuzz targets. Built with afl-clang-fast these run in AFL++ persistent
# mode; built with a plain compiler they read one case from stdin, or
# replay the files named on the command line:
#
#	afl-fuzz -i fuzz/corpus/rule -o out -- build/fuzz/fuzz_rule
#	build/fuzz/fuzz_rule fuzz/corpus/rule/*
#
# Only the rendering path is reachable here. Everything else in the
# binding starts at an ioctl on /dev/pf, which a fuzzer cannot supply.

fuzz_inc = include_directories('..')

fuzz_targets = {
  'rule': 'rule.c',
  'state': 'state.c',
}

foreach name, src : fuzz_targets
  exe = executable('fuzz_' + name,
    files('fuzz_' + name + '.c', '..' / src),
    dependencies: [lua_dep],
    include_directories: fuzz_inc,
    build_by_default: false,
  )

  # The corpus doubles as a regression test. It needs neither /dev/pf nor
  # doas, which makes it the part of this project a CI runner can run.
  seeds = run_command(find_program('sh'), '-c',
    'ls ' + meson.current_source_dir() / 'corpus' / name / '*',
    check: true).stdout().strip().split('\n')

  test('fuzz_' + name, exe, args: seeds, suite: 'fuzz')
endforeach
