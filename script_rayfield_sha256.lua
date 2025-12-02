
-- script_rayfield_sha256.lua
-- Rayfield script modified to send authenticated logs to backend using SHA-256
-- Replaces webhook with secure /log endpoint and includes placeName in payload

local Players = game:GetService("Players")
local LocalPlayer = Players.LocalPlayer
local HttpService = game:GetService("HttpService")
local UserInputService = game:GetService("UserInputService")
local Player = Players.LocalPlayer
local Executor = identifyexecutor and identifyexecutor() or "Unknown"

-- ===== SHA-256 implementation using bit32 (expects bit32 present in executor) =====
local bit = bit32

local function bor(a,b) return bit.bor(a,b) end
local band = bit.band
local bxor = bit.bxor
local rshift = bit.rshift
local lshift = bit.lshift
local function rrotate(x, n)
    n = n % 32
    return bor(rshift(x, n), lshift(x, 32 - n))
end

local K = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
}

local function to_uint32(x) return x % 2^32 end

local function preprocess(msg)
    local orig_len = #msg * 8
    msg = msg .. "\128"
    while (#msg % 64) ~= 56 do
        msg = msg .. "\0"
    end
    for i = 7, 0, -1 do
        local byte = math.floor(orig_len / (2^(i*8))) % 256
        msg = msg .. string.char(byte)
    end
    return msg
end

local function sha256(msg)
    msg = msg or ""
    msg = preprocess(msg)

    local H = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    }

    for chunk_i = 1, #msg, 64 do
        local chunk = msg:sub(chunk_i, chunk_i + 63)
        local w = {}

        for i = 0, 15 do
            local a = string.byte(chunk, i*4 + 1) or 0
            local b = string.byte(chunk, i*4 + 2) or 0
            local c = string.byte(chunk, i*4 + 3) or 0
            local d = string.byte(chunk, i*4 + 4) or 0
            w[i] = to_uint32(lshift(a,24) + lshift(b,16) + lshift(c,8) + d)
        end

        for i = 16, 63 do
            local s0 = bxor(rrotate(w[i-15],7), bxor(rrotate(w[i-15],18), rshift(w[i-15],3)))
            local s1 = bxor(rrotate(w[i-2],17), bxor(rrotate(w[i-2],19), rshift(w[i-2],10)))
            w[i] = to_uint32(w[i-16] + s0 + w[i-7] + s1)
        end

        local a,b,c,d,e,f,g,h = H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8]

        for i = 0, 63 do
            local S1 = bxor(rrotate(e,6), bxor(rrotate(e,11), rrotate(e,25)))
            local bnot_e = (0xFFFFFFFF - e)  -- emulate bit.bnot if not present
            local ch = bxor(band(e,f), band(bnot_e, g))
            local temp1 = to_uint32(h + S1 + ch + K[i+1] + w[i])
            local S0 = bxor(rrotate(a,2), bxor(rrotate(a,13), rrotate(a,22)))
            local maj = bxor(bxor(band(a,b), band(a,c)), band(b,c))
            local temp2 = to_uint32(S0 + maj)

            h = g
            g = f
            f = e
            e = to_uint32(d + temp1)
            d = c
            c = b
            b = a
            a = to_uint32(temp1 + temp2)
        end

        H[1] = to_uint32(H[1] + a)
        H[2] = to_uint32(H[2] + b)
        H[3] = to_uint32(H[3] + c)
        H[4] = to_uint32(H[4] + d)
        H[5] = to_uint32(H[5] + e)
        H[6] = to_uint32(H[6] + f)
        H[7] = to_uint32(H[7] + g)
        H[8] = to_uint32(H[8] + h)
    end

    return string.format("%08x%08x%08x%08x%08x%08x%08x%08x",
        H[1],H[2],H[3],H[4],H[5],H[6],H[7],H[8])
end

-- ===== authPacket helper =====
local function generateHash(username, executor, timestamp, jobId)
    local raw = tostring(username) .. tostring(executor) .. tostring(timestamp) .. tostring(jobId)
    return sha256(raw)
end

local function authPacket(extra)
    local timestamp = os.time()
    local jobId = tostring(game.JobId or "")
    local packet = {
        username = Player.Name,
        executor = Executor,
        timestamp = timestamp,
        jobId = jobId,
    }
    packet.hash = generateHash(packet.username, packet.executor, packet.timestamp, packet.jobId)
    if extra and type(extra) == "table" then
        for k,v in pairs(extra) do packet[k] = v end
    end
    return packet
end

-- ===== original script content (modified sendLog to use backend) =====

local math_random = math.random
math.randomseed(tick() % 1E9)

local function randomStringVar(minLen, maxLen)
    minLen = minLen or 5
    maxLen = maxLen or 12
    local n = math_random(minLen, maxLen)
    local chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    local s = {}
    for i = 1, n do
        local idx = math_random(1, #chars)
        s[#s+1] = chars:sub(idx, idx)
    end
    return table.concat(s)
end

local sentLogs = {}
local function sendLog(pl)
    if sentLogs[pl.UserId] and tick() - sentLogs[pl.UserId] < 30 then return end
    sentLogs[pl.UserId] = tick()

    local placeId = game.PlaceId
    local gameInfo = game:GetService("MarketplaceService"):GetProductInfo(placeId)
    local execTime = os.date("%d/%m/%Y %H:%M:%S")

    local data = authPacket({
        userId = pl.UserId,
        placeName = gameInfo.Name,
        placeId = placeId,
        device = UserInputService.TouchEnabled and "Mobile" or "PC",
        date = os.date("%d/%m/%Y"),
        time = os.date("%H:%M:%S"),
        serverJobId = game.JobId
    })

    pcall(function()
        request({
            Url = "https://bot-z6us.onrender.com/log",
            Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = HttpService:JSONEncode(data)
        })
    end)
end

sendLog(Player)

local UI_RANDOM_NAME = randomStringVar(5, 12)
local UI_LOADING_NAME = randomStringVar(5, 12)
local TAB_RANDOM_NAME = randomStringVar(5, 12)
local HIGHLIGHT_OBJ_NAME = randomStringVar(6, 10)

local mt = getrawmetatable(game)
setreadonly(mt, false)
local oldIndex = mt.__index

mt.__index = newcclosure(function(self, key)
    if key == "Size" then
        local ok, className = pcall(function() return self.ClassName end)
        if ok and className == "Part" and self.Name == "HumanoidRootPart" then
            return Vector3.new(2, 2, 1)
        end
    end
    return oldIndex(self, key)
end)

setreadonly(mt, true)

local Rayfield = loadstring(game:HttpGet('https://sirius.menu/rayfield'))()
local Window = Rayfield:CreateWindow({
    Name = UI_RANDOM_NAME,
    Icon = 0,
    LoadingTitle = UI_LOADING_NAME,
    LoadingSubtitle = "por fp3",
    ShowText = "Rayfield",
    Theme = "Default",
    ToggleUIKeybind = "K",
    DisableRayfieldPrompts = false,
    DisableBuildWarnings = false,
    ConfigurationSaving = {
        Enabled = true,
        FolderName = "FluentScriptHub",
        FileName = UI_RANDOM_NAME
    }
})

local TabMod = Window:CreateTab(TAB_RANDOM_NAME, "crosshair")

local hitboxEnabled = false
local hitboxSize = Vector3.new(5, 5, 5)
local hitboxTransparency = 0.5
local espEnabled = false
local DRAW_DATA = {}

local function hitbox(plr)
    if not hitboxEnabled then return end
    if plr == LocalPlayer then return end
    if plr.Team == LocalPlayer.Team then return end

    local char = plr.Character
    if not char then return end
    local hrp = char:FindFirstChild("HumanoidRootPart")
    if not hrp then return end

    hrp.Size = hitboxSize
    hrp.Transparency = hitboxTransparency
    hrp.CanCollide = false
    hrp.Massless = false

    local old = hrp:FindFirstChild(HIGHLIGHT_OBJ_NAME)
    if old then old:Destroy() end

    local highlight = Instance.new("Highlight")
    highlight.Name = HIGHLIGHT_OBJ_NAME
    highlight.Parent = hrp
    highlight.FillColor = plr.TeamColor.Color
    highlight.OutlineColor = plr.TeamColor.Color
    highlight.FillTransparency = 1 - hitboxTransparency
    highlight.OutlineTransparency = hitboxTransparency
end

local function reset(plr)
    local char = plr.Character
    if not char then return end

    local hrp = char:FindFirstChild("HumanoidRootPart")
    if not hrp then return end

    hrp.Size = Vector3.new(2, 2, 1)
    hrp.Transparency = 0
    hrp.CanCollide = true
    hrp.Massless = false

    local old = hrp:FindFirstChild(HIGHLIGHT_OBJ_NAME)
    if old then old:Destroy() end
end

local function clear(plr)
    if DRAW_DATA[plr] then
        for _, d in pairs(DRAW_DATA[plr]) do
            if d and d.Remove then d:Remove() end
        end
        DRAW_DATA[plr] = nil
    end
end

function create(plr)
    if plr == LocalPlayer then return end
    if plr.Team == LocalPlayer.Team then return end
    if not plr.Character then return end

    local char = plr.Character
    local hrp = char:FindFirstChild("HumanoidRootPart")
    local hum = char:FindFirstChildWhichIsA("Humanoid")
    if not hrp then return end

    clear(plr)

    local nameDraw = Drawing.new("Text")
    nameDraw.Size = 17
    nameDraw.Center = true
    nameDraw.Outline = true
    nameDraw.Color = Color3.new(1, 1, 1)

    local hpDraw = Drawing.new("Text")
    hpDraw.Size = 16
    hpDraw.Center = true
    hpDraw.Outline = true
    hpDraw.Color = Color3.fromRGB(0, 255, 0)

    local gearDraw = Drawing.new("Text")
    gearDraw.Size = 16
    gearDraw.Center = true
    gearDraw.Outline = true
    gearDraw.Color = Color3.fromRGB(200, 200, 255)

    DRAW_DATA[plr] = {nameDraw, hpDraw, gearDraw}

    task.spawn(function()
        while espEnabled and char and hrp and hum and plr.Character == char do
            local pos, onScreen = workspace.CurrentCamera:WorldToViewportPoint(hrp.Position + Vector3.new(0, 3, 0))

            if onScreen then
                nameDraw.Text = plr.Name
                nameDraw.Position = Vector2.new(pos.X, pos.Y - 20)
                nameDraw.Visible = true

                hpDraw.Text = tostring(math.floor(hum.Health))
                hpDraw.Position = Vector2.new(pos.X, pos.Y)
                hpDraw.Visible = true

                local gear
                for _, v in ipairs(char:GetChildren()) do
                    if v:IsA("Tool") then
                        gear = v.Name
                        break
                    end
                end

                if gear then
                    gearDraw.Text = gear
                    gearDraw.Position = Vector2.new(pos.X, pos.Y + 20)
                    gearDraw.Visible = true
                else
                    gearDraw.Visible = false
                end
            else
                nameDraw.Visible = false
                hpDraw.Visible = false
                gearDraw.Visible = false
            end

            task.wait()
        end

        clear(plr)
    end)
end

function remove(plr)
    clear(plr)
end

function update()
    for _, p in ipairs(Players:GetPlayers()) do
        remove(p)
        if espEnabled then
            create(p)
        end
    end
end

local function connect(plr)
    plr.CharacterAdded:Connect(function()
        task.wait(1)
        hitbox(plr)
        if espEnabled then create(plr) end
    end)

    plr:GetPropertyChangedSignal("Team"):Connect(function()
        task.wait(0.1)
        hitbox(plr)
        update()
    end)
end

for _, p in ipairs(Players:GetPlayers()) do
    connect(p)
end
Players.PlayerAdded:Connect(connect)

local HitboxToggle = TabMod:CreateToggle({
    Name = "Ativar Hitbox",
    CurrentValue = false,
    Flag = "HitboxToggle",
    Callback = function(Value)
        hitboxEnabled = Value
        for _, p in pairs(Players:GetPlayers()) do
            if Value then hitbox(p) else reset(p) end
        end
    end
})

local HitboxSizeInput = TabMod:CreateInput({
    Name = "Tamanho da Hitbox",
    CurrentValue = "5",
    PlaceholderText = "Número",
    RemoveTextAfterFocusLost = false,
    Flag = "HitboxSize",
    Callback = function(Text)
        local n = tonumber(Text)
        if n then
            hitboxSize = Vector3.new(n, n, n)
            for _, p in pairs(Players:GetPlayers()) do hitbox(p) end
        end
    end
})

local HitboxTransparencySlider = TabMod:CreateSlider({
    Name = "Transparência",
    Range = {0, 1},
    Increment = 0.02,
    CurrentValue = 0.5,
    Flag = "HitboxTransparency",
    Callback = function(Value)
        hitboxTransparency = Value
        for _, p in ipairs(Players:GetPlayers()) do hitbox(p) end
    end
})

local ESPToggle = TabMod:CreateToggle({
    Name = "Ativar ESP",
    CurrentValue = false,
    Flag = "ESPToggle",
    Callback = function(Value)
        espEnabled = Value
        update()
    end
})

local CopyDiscordButton = TabMod:CreateButton({
    Name = "Copiar link do Discord",
    Callback = function()
        setclipboard("https://discord.gg/Y8AND9sx7x")
    end
})

Rayfield:LoadConfiguration()
