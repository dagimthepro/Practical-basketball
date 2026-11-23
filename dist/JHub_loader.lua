-- JHub remote loader
-- This is the ONLY thing you give out to buyers. It just fetches and runs
-- the current protected build from GitHub, so updates/revocations go out
-- the moment they're pushed, without resending any file.
local URL = "https://raw.githubusercontent.com/dagimthepro/practical-basketball/main/dist/JHub_PB_bundle.lua"

local ok, src = pcall(function()
    return game:HttpGet(URL, true)
end)

if not ok or type(src) ~= "string" or #src == 0 then
    warn("[JHub] failed to fetch script: " .. tostring(src))
    return
end

local chunk, err = loadstring(src, "JHub")
if not chunk then
    warn("[JHub] failed to load script: " .. tostring(err))
    return
end

return chunk(...)
