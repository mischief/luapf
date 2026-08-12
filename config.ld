project = "luapf"
title = "luapf"
description = "lua bindings for the OpenBSD packet filter"
format = "markdown"

-- every source contributes to the same pf module
merge = true
file = { "pf.c", "state.c", "queue.c", "table.c", "rule.c", "anchor.c", "system.c", "privsep.c" }
