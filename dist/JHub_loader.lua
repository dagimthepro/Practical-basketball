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

-- Returns (true, scriptSource) on a valid key, or (false, errorMessage).
local function fetchWithKey(key)
    local ok, resp = pcall(function()
        return request({
            Url = GATE_URL .. "?key=" .. key,
            Method = "GET",
        })
    end)
    if not ok then
        return false, "request failed: " .. tostring(resp)
    end
    if resp.StatusCode == 200 and type(resp.Body) == "string" and #resp.Body > 0 then
        return true, resp.Body
    end
    if resp.StatusCode == 403 then
        return false, "invalid key"
    end
    return false, "gate returned " .. tostring(resp.StatusCode) .. ": " .. tostring(resp.Body)
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

local function promptKey(onUnlocked)
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
            errLabel.Text = "Invalid key - try again"
        end
    end
    btn.MouseButton1Click:Connect(attempt)
    box.FocusLost:Connect(function(enterPressed)
        if enterPressed then
            attempt()
        end
    end)
end

local function start(...)
    local n = select("#", ...)
    local args = table.pack(...)
    local function proceedWith(src)
        return run(src, table.unpack(args, 1, n))
    end

    local storedOk, storedKey = pcall(readfile, KEY_FILE)
    if storedOk and type(storedKey) == "string" and storedKey ~= "" then
        local ok, result = fetchWithKey(normKey(storedKey))
        if ok then
            return proceedWith(result)
        end
        -- stored key no longer works (revoked, corrupted, etc.) -- fall through to prompt
    end
    promptKey(proceedWith)
end

return start(...)
