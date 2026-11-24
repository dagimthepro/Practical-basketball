-- JHub remote loader
-- This is the ONLY thing you give out to buyers.
--
-- It asks for a key the first time (then remembers it locally), sends it
-- to a small server (a Cloudflare Worker) that checks it and -- only on a
-- valid key -- decodes and returns the real script. There is no file
-- anywhere, static or local, that contains the real script in a form a
-- key alone can unlock offline: the decode happens on the server, per
-- request, so revoking a key stops it immediately on the next load.

local GATE_URL = "https://practical-basketball.dagimwww.workers.dev/"
local KEY_FILE = "JHub/PB/jhub.key"

local function normKey(s)
    return string.lower((string.gsub(s or "", "%s+", "")))
end

local function urlEncode(s)
    return (string.gsub(s or "", "[^%w%-%.%_%~]", function(c)
        return string.format("%%%02X", string.byte(c))
    end))
end

-- Returns (true, scriptSource) on a valid key, or (false, errorMessage).
-- Also reports the local Roblox username and job ID to the gate -- this is
-- just what every execution already is (who's running it, which server),
-- used for anti-leak tracing of which buyer a leaked key/script traces back
-- to, same idea as the per-key licensing itself.
local function getHwid()
    -- device id used to lock a key to one machine; hashed server-side
    local ok, id = pcall(function()
        if type(gethwid) == "function" then return gethwid() end
        return game:GetService("RbxAnalyticsService"):GetClientId()
    end)
    return (ok and id) and tostring(id) or ""
end

local function fetchWithKey(key)
    local okId, robloxUser = pcall(function()
        local lp = game:GetService("Players").LocalPlayer
        return lp and lp.Name or "unknown"
    end)
    local okJob, jobId = pcall(function() return game.JobId end)
    local qs = GATE_URL .. "?key=" .. key
        .. "&user=" .. urlEncode(okId and robloxUser or "unknown")
        .. "&job=" .. urlEncode(okJob and jobId or "unknown")
        .. "&hwid=" .. urlEncode(getHwid())
    local ok, resp = pcall(function()
        return request({
            Url = qs,
            Method = "GET",
        })
    end)
    if not ok then
        return false, "request failed: " .. tostring(resp), false
    end
    if resp.StatusCode == 200 and type(resp.Body) == "string" and #resp.Body > 0 then
        return true, resp.Body
    end
    if resp.StatusCode == 403 then
        -- the gate said no for a real reason (invalid / blacklisted / expired / wrong device)
        return false, (type(resp.Body) == "string" and #resp.Body > 0 and #resp.Body < 80) and resp.Body or "invalid key", true
    end
    return false, "gate returned " .. tostring(resp.StatusCode) .. ": " .. tostring(resp.Body), false
end

local function saveKey(norm)
    pcall(function()
        if not isfolder("JHub") then makefolder("JHub") end
        if not isfolder("JHub/PB") then makefolder("JHub/PB") end
        writefile(KEY_FILE, norm)
    end)
end

local function run(src, ...)
    local chunk, err = loadstring(src, "JHub")
    if not chunk then
        warn("[JHub] failed to compile script from gate: " .. tostring(err))
        return
    end
    return chunk(...)
end

-- Plain-GUI key prompt. Only used if OkloUI itself can't be fetched (bad
-- network, GitHub blocked, etc.) -- promptKey below tries OkloUI first.
local function promptKeyFallback(onUnlocked)
    local okCore, CoreGui = pcall(function() return game:GetService("CoreGui") end)
    local gui = Instance.new("ScreenGui")
    gui.Name = "JHubKeyGate"
    gui.ResetOnSpawn = false
    gui.IgnoreGuiInset = true
    local parented = false
    if okCore then
        parented = pcall(function() gui.Parent = CoreGui end)
    end
    if not parented then
        local lp = game:GetService("Players").LocalPlayer
        pcall(function() gui.Parent = lp:WaitForChild("PlayerGui", 10) end)
    end

    local frame = Instance.new("Frame")
    frame.Size = UDim2.new(0, 320, 0, 170)
    frame.Position = UDim2.new(0.5, -160, 0.5, -85)
    frame.BackgroundColor3 = Color3.fromRGB(24, 24, 28)
    frame.BorderSizePixel = 0
    frame.Parent = gui
    local corner = Instance.new("UICorner")
    corner.CornerRadius = UDim.new(0, 10)
    corner.Parent = frame

    local title = Instance.new("TextLabel")
    title.Text = "JHub - Enter your key"
    title.Size = UDim2.new(1, -20, 0, 30)
    title.Position = UDim2.new(0, 10, 0, 12)
    title.BackgroundTransparency = 1
    title.TextColor3 = Color3.fromRGB(255, 255, 255)
    title.Font = Enum.Font.GothamBold
    title.TextSize = 18
    title.TextXAlignment = Enum.TextXAlignment.Left
    title.Parent = frame

    local box = Instance.new("TextBox")
    box.Size = UDim2.new(1, -20, 0, 36)
    box.Position = UDim2.new(0, 10, 0, 50)
    box.PlaceholderText = "Key"
    box.Text = ""
    box.ClearTextOnFocus = false
    box.BackgroundColor3 = Color3.fromRGB(40, 40, 46)
    box.TextColor3 = Color3.fromRGB(255, 255, 255)
    box.Font = Enum.Font.Gotham
    box.TextSize = 16
    box.Parent = frame
    local boxCorner = Instance.new("UICorner")
    boxCorner.CornerRadius = UDim.new(0, 6)
    boxCorner.Parent = box

    local errLabel = Instance.new("TextLabel")
    errLabel.Size = UDim2.new(1, -20, 0, 20)
    errLabel.Position = UDim2.new(0, 10, 0, 90)
    errLabel.BackgroundTransparency = 1
    errLabel.Text = ""
    errLabel.TextColor3 = Color3.fromRGB(255, 90, 90)
    errLabel.Font = Enum.Font.Gotham
    errLabel.TextSize = 13
    errLabel.TextXAlignment = Enum.TextXAlignment.Left
    errLabel.Parent = frame

    local btn = Instance.new("TextButton")
    btn.Size = UDim2.new(1, -20, 0, 34)
    btn.Position = UDim2.new(0, 10, 0, 118)
    btn.Text = "Unlock"
    btn.BackgroundColor3 = Color3.fromRGB(70, 120, 255)
    btn.TextColor3 = Color3.fromRGB(255, 255, 255)
    btn.Font = Enum.Font.GothamBold
    btn.TextSize = 16
    btn.AutoButtonColor = true
    btn.Parent = frame
    local btnCorner = Instance.new("UICorner")
    btnCorner.CornerRadius = UDim.new(0, 6)
    btnCorner.Parent = btn

    local busy = false
    local function attempt()
        if busy then
            return
        end
        local text = box.Text
        local norm = normKey(text)
        if norm == "" then
            errLabel.Text = "Enter a key"
            return
        end
        busy = true
        errLabel.Text = "Checking..."
        local ok, result = fetchWithKey(norm)
        busy = false
        if ok then
            saveKey(norm)
            pcall(function() gui:Destroy() end)
            onUnlocked(result)
        else
            errLabel.Text = (type(result) == "string" and #result < 60) and result or "Invalid key - try again"
        end
    end
    btn.MouseButton1Click:Connect(attempt)
    box.FocusLost:Connect(function(enterPressed)
        if enterPressed then
            attempt()
        end
    end)
end

-- Same key prompt, built with oklo's own UI lib (the lib the rest of JHub uses)
-- instead of a hand-rolled GUI, so it actually looks like the hub. Loaded
-- straight from okdude42's public repo -- this lib itself is not part of what
-- a key unlocks, it is a general-purpose menu toolkit, so it is fine to fetch
-- before a key is ever entered.
local function promptKey(onUnlocked)
    local okLib, OkloUI = pcall(function()
        return loadstring(request({
            Url = "https://raw.githubusercontent.com/okdude42/main-scripts/main/oklo-uilib/OkloUI.luau",
            Method = "GET",
        }).Body)()
    end)
    if not okLib or not OkloUI then
        return promptKeyFallback(onUnlocked)
    end

    local okUi, ui = pcall(function()
        return OkloUI.new({
            Title = "JHub",
            Subtitle = "enter your key",
            Folder = "JHub",
            NoSidebar = true,
            Width = 420,
            Height = 260,
        })
    end)
    if not okUi or not ui then
        return promptKeyFallback(onUnlocked)
    end

    pcall(function() ui:tab("Key") end)

    local keyText, statusMsg, statusColor, busy = "", "paste your key below", nil, false

    local function attempt()
        if busy then
            return
        end
        local norm = normKey(keyText)
        if norm == "" then
            statusMsg, statusColor = "Enter a key", Color3.fromRGB(255, 90, 90)
            return
        end
        busy = true
        statusMsg, statusColor = "Checking...", nil
        local ok, result = fetchWithKey(norm)
        busy = false
        if ok then
            saveKey(norm)
            pcall(function() ui:closePopup() end)
            pcall(function() ui:destroy() end)
            onUnlocked(result)
        else
            statusMsg, statusColor = (type(result) == "string" and #result < 60) and result or "Invalid key - try again", Color3.fromRGB(255, 90, 90)
        end
    end

    -- Define the popup before start() (that part's fine -- it's just a table
    -- registration), but DON'T open it yet. OkloUI's own example only ever
    -- opens a popup from inside a callback that fires after ui:start() is
    -- already running the UI's render loop -- opening it inline before
    -- start() is a no-op, which is why the key screen rendered as an empty
    -- "Key" tab with nothing in it. So: register the popup, start() the UI,
    -- then open the popup as the very next thing once the UI is live.
    pcall(function()
        ui:popup("jhubkeygate", {
            Width = 300,
            Height = 190,
            Title = "JHub - enter your key",
            Locked = true,
            Render = function(kit, window)
                kit:text(statusMsg, 14, 42, 13, statusColor or window.Pal.Sub)
                kit:input("jhubkeygate:input", 14, 64, kit.Width - 28, 34, keyText == "" and "Key" or keyText, function()
                    window:beginInput("jhubkeygate:input", keyText, {
                        commit = function(text) keyText = text end,
                    })
                end)
                kit:button("jhubkeygate:unlock", 14, 108, kit.Width - 28, 32, attempt, { label = "Unlock", align = "center" })
            end,
        })
    end)
    pcall(function() ui:start() end)
    pcall(function() ui:openPopup("jhubkeygate") end)
end

local function start(...)
    local n = select("#", ...)
    local args = table.pack(...)
    local function proceedWith(src)
        return run(src, table.unpack(args, 1, n))
    end

    local storedOk, storedKey = pcall(readfile, KEY_FILE)
    if storedOk and type(storedKey) == "string" and storedKey ~= "" then
        local ok, result, definitive = fetchWithKey(normKey(storedKey))
        local tries = 1
        -- a network hiccup / server error while joining a match is NOT a bad key: retry quietly instead of
        -- popping the key screen up every match
        while not ok and not definitive and tries < 4 do
            task.wait(2)
            tries += 1
            ok, result, definitive = fetchWithKey(normKey(storedKey))
        end
        if ok then
            return proceedWith(result)
        end
        if not definitive then
            warn("[JHub] could not reach the key server (" .. tostring(result) .. ") - not asking for your key again, just re-run the script")
            return
        end
        warn("[JHub] your saved key was refused: " .. tostring(result))
        -- a real refusal (revoked, expired, wrong device...) falls through to the prompt
    end
    promptKey(proceedWith)
end

return start(...)
