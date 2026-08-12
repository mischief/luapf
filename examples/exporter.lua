-- Writes pf metrics to stdout, or to the file named by the first argument,
-- replacing it atomically for the node_exporter textfile collector.

package.path = (arg[0]:match("^(.*)/") or ".") .. "/?.lua;" .. package.path

local pfmetrics = require("pfmetrics")

local text = pfmetrics.collect()
local path = arg[1]

if not path then
	io.write(text)
	return
end

local tmp = path .. ".tmp"
local f = assert(io.open(tmp, "w"))
assert(f:write(text))
f:close()
assert(os.rename(tmp, path))
