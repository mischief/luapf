package = "pf"
version = "scm-0"
source = {
   url = "git+https://github.com/mischief/luapf.git"
}
description = {
   homepage = "https://github.com/mischief/luapf",
   license = "ISC",
}
dependencies = {
   "lua >= 5.1, < 5.5",
}

build = {
   type = "command",

   build_command = "CFLAGS='$(CFLAGS)' meson setup --reconfigure --wipe -Dlua=lua$(LUA_VERSION) -Dlua-module-directory=$(LIBDIR) build && ninja -C build",
   install_command = "ninja -C build -v install",
}

