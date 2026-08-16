-- IronBrew2 independent executor console logger.
-- Run this script BEFORE the feature probe, then click the GUI button to copy captured output.
-- Standard Lua 5.1 syntax; no network or filesystem access.

local NativePrint = print
local NativeWarn = warn
local NativeType = type
local NativeToString = tostring
local NativePCall = pcall
local NativeRawGet = rawget
local NativeRawSet = rawset
local NativeRawEqual = rawequal
local NativeSelect = select
local NativeConcat = table.concat

local LOGGER_KEY = "__IB2_CONSOLE_LOGGER_V1"
local MAX_BYTES = 262144
local MAX_LINES = 2048

local function safeRawGet(container, key)
    if NativeType(container) ~= "table" then return nil, false end
    local ok, value = NativePCall(NativeRawGet, container, key)
    return ok and value or nil, ok
end

local function getBaseEnvironment()
    local getfenvValue = getfenv
    if NativeType(getfenvValue) == "function" then
        local ok, value = NativePCall(getfenvValue, 0)
        if ok and NativeType(value) == "table" then return value end
        ok, value = NativePCall(getfenvValue)
        if ok and NativeType(value) == "table" then return value end
    end
    if NativeType(_G) == "table" then return _G end
    return nil
end

local BaseEnvironment = getBaseEnvironment()
local GetGenV = safeRawGet(BaseEnvironment, "getgenv")
local CapabilityEnvironment = nil
if NativeType(GetGenV) == "function" then
    local ok, value = NativePCall(GetGenV)
    if ok and NativeType(value) == "table" then CapabilityEnvironment = value end
end

local function resolve(name)
    local value = safeRawGet(CapabilityEnvironment, name)
    if value == nil then value = safeRawGet(BaseEnvironment, name) end
    if value == nil and NativeType(_G) == "table" then value = safeRawGet(_G, name) end
    return value
end

local InstallEnvironment = CapabilityEnvironment or BaseEnvironment or _G
local PreviousState = safeRawGet(InstallEnvironment, LOGGER_KEY)
if NativeType(PreviousState) == "table" and NativeType(PreviousState.stop) == "function" then
    NativePCall(PreviousState.stop)
end

local Lines = {}
local Head = 1
local LineCount = 0
local ByteCount = 0
local Sequence = 0
local StatusLabel = nil

local function safeText(value)
    local ok, text = NativePCall(NativeToString, value)
    if not ok then return "<tostring-error>" end
    return text
end

local function argumentsToText(...)
    local values = {}
    local count = NativeSelect("#", ...)
    for index = 1, count do
        values[index] = safeText(NativeSelect(index, ...))
    end
    return NativeConcat(values, "\t")
end

local function updateStatus(message)
    if StatusLabel == nil then return end
    NativePCall(function()
        StatusLabel.Text = message or ("Recorded " .. LineCount .. " lines / " .. ByteCount .. " bytes")
    end)
end

local function compactBufferIfNeeded()
    if Head <= 256 then return end
    local compacted = {}
    for index = Head, #Lines do
        compacted[#compacted + 1] = Lines[index]
    end
    Lines = compacted
    Head = 1
end

local function append(level, ...)
    local ok, text = NativePCall(argumentsToText, ...)
    if not ok then text = "<argument-format-error>" end
    Sequence = Sequence + 1
    local line = string.format("%04d [%s] %s", Sequence, level, text)
    Lines[#Lines + 1] = line
    LineCount = LineCount + 1
    ByteCount = ByteCount + #line + 1

    while (ByteCount > MAX_BYTES or LineCount > MAX_LINES) and Head <= #Lines do
        local removed = Lines[Head]
        Lines[Head] = false
        Head = Head + 1
        LineCount = LineCount - 1
        ByteCount = ByteCount - #removed - 1
    end
    compactBufferIfNeeded()
    updateStatus()
end

local function buildReport()
    local output = {
        "IB2 console logger v1",
        "captured_lines=" .. LineCount .. ",captured_bytes=" .. ByteCount,
        "---"
    }
    for index = Head, #Lines do
        if Lines[index] then output[#output + 1] = Lines[index] end
    end
    return NativeConcat(output, "\n")
end

local function chooseParent()
    local GetHui = resolve("gethui")
    if NativeType(GetHui) == "function" then
        local ok, value = NativePCall(GetHui)
        if ok and value ~= nil then return value, "gethui" end
    end

    local Game = resolve("game")
    if Game ~= nil then
        local ok, coreGui = NativePCall(function() return Game:GetService("CoreGui") end)
        if ok and coreGui ~= nil then return coreGui, "CoreGui" end

        local playersOK, players = NativePCall(function() return Game:GetService("Players") end)
        if playersOK and players ~= nil then
            local playerOK, localPlayer = NativePCall(function() return players.LocalPlayer end)
            if playerOK and localPlayer ~= nil then
                local guiOK, playerGui = NativePCall(function()
                    return localPlayer:FindFirstChildOfClass("PlayerGui")
                        or localPlayer:FindFirstChild("PlayerGui")
                end)
                if guiOK and playerGui ~= nil then return playerGui, "PlayerGui" end
            end
        end
    end
    return nil, "none"
end

local Parent, ParentKind = chooseParent()
local InstanceValue = resolve("Instance")
local UDim2Value = resolve("UDim2") or UDim2
local Color3Value = resolve("Color3") or Color3
local EnumValue = resolve("Enum") or Enum

local guiOK, Gui, Frame, Title, Status, CopyButton, ClearButton, CloseButton = NativePCall(function()
    if NativeType(InstanceValue) ~= "table" or NativeType(InstanceValue.new) ~= "function" then
        error("Instance.new is unavailable")
    end
    if Parent == nil then error("no GUI parent is available") end

    local screenGui = InstanceValue.new("ScreenGui")
    screenGui.Name = "IB2ConsoleLogger"
    screenGui.ResetOnSpawn = false
    screenGui.IgnoreGuiInset = true
    screenGui.DisplayOrder = 2147483647

    local frame = InstanceValue.new("Frame")
    frame.Name = "Panel"
    frame.Size = UDim2Value.new(0, 330, 0, 150)
    frame.Position = UDim2Value.new(0.5, -165, 0.12, 0)
    frame.BackgroundColor3 = Color3Value.fromRGB(24, 27, 34)
    frame.BorderSizePixel = 0
    frame.Active = true
    NativePCall(function() frame.Draggable = true end)
    frame.Parent = screenGui

    local title = InstanceValue.new("TextLabel")
    title.Name = "Title"
    title.Size = UDim2Value.new(1, -44, 0, 34)
    title.Position = UDim2Value.new(0, 12, 0, 6)
    title.BackgroundTransparency = 1
    title.Text = "IB2 Console Logger"
    title.TextColor3 = Color3Value.fromRGB(238, 241, 247)
    title.TextSize = 18
    title.TextXAlignment = EnumValue.TextXAlignment.Left
    title.Font = EnumValue.Font.SourceSansBold
    title.Parent = frame

    local close = InstanceValue.new("TextButton")
    close.Name = "Close"
    close.Size = UDim2Value.new(0, 32, 0, 32)
    close.Position = UDim2Value.new(1, -38, 0, 6)
    close.BackgroundColor3 = Color3Value.fromRGB(51, 56, 68)
    close.BorderSizePixel = 0
    close.Text = "X"
    close.TextColor3 = Color3Value.fromRGB(238, 241, 247)
    close.TextSize = 16
    close.Font = EnumValue.Font.SourceSansBold
    close.Parent = frame

    local status = InstanceValue.new("TextLabel")
    status.Name = "Status"
    status.Size = UDim2Value.new(1, -24, 0, 30)
    status.Position = UDim2Value.new(0, 12, 0, 42)
    status.BackgroundTransparency = 1
    status.Text = "Logger starting..."
    status.TextColor3 = Color3Value.fromRGB(169, 178, 195)
    status.TextSize = 14
    status.TextWrapped = true
    status.TextXAlignment = EnumValue.TextXAlignment.Left
    status.Font = EnumValue.Font.SourceSans
    status.Parent = frame

    local copy = InstanceValue.new("TextButton")
    copy.Name = "Copy"
    copy.Size = UDim2Value.new(1, -96, 0, 48)
    copy.Position = UDim2Value.new(0, 12, 1, -60)
    copy.BackgroundColor3 = Color3Value.fromRGB(55, 112, 232)
    copy.BorderSizePixel = 0
    copy.Text = "Copy captured log"
    copy.TextColor3 = Color3Value.fromRGB(255, 255, 255)
    copy.TextSize = 17
    copy.Font = EnumValue.Font.SourceSansBold
    copy.Parent = frame

    local clear = InstanceValue.new("TextButton")
    clear.Name = "Clear"
    clear.Size = UDim2Value.new(0, 64, 0, 48)
    clear.Position = UDim2Value.new(1, -76, 1, -60)
    clear.BackgroundColor3 = Color3Value.fromRGB(51, 56, 68)
    clear.BorderSizePixel = 0
    clear.Text = "Clear"
    clear.TextColor3 = Color3Value.fromRGB(238, 241, 247)
    clear.TextSize = 15
    clear.Font = EnumValue.Font.SourceSansBold
    clear.Parent = frame

    screenGui.Parent = Parent
    return screenGui, frame, title, status, copy, clear, close
end)

if not guiOK then
    NativePCall(NativePrint, "IB2LOGGER|FAIL|GUI creation failed: " .. safeText(Gui))
    return
end

StatusLabel = Status
local State = {
    gui = Gui,
    stopped = false,
    bindings = {},
    connections = {}
}

local function addTarget(targets, candidate)
    if NativeType(candidate) ~= "table" then return end
    for index = 1, #targets do
        if NativeRawEqual(targets[index], candidate) then return end
    end
    targets[#targets + 1] = candidate
end

local Targets = {}
addTarget(Targets, CapabilityEnvironment)
addTarget(Targets, BaseEnvironment)
addTarget(Targets, _G)

local WrappedPrint
local WrappedWarn
WrappedPrint = function(...)
    append("PRINT", ...)
    return NativePrint(...)
end
WrappedWarn = function(...)
    append("WARN", ...)
    if NativeType(NativeWarn) == "function" then return NativeWarn(...) end
    return NativePrint(...)
end

local function bind(target, key, replacement)
    local oldValue, readOK = safeRawGet(target, key)
    local writeOK = NativePCall(NativeRawSet, target, key, replacement)
    if writeOK then
        State.bindings[#State.bindings + 1] = {
            target = target,
            key = key,
            oldValue = oldValue,
            hadRawValue = readOK and oldValue ~= nil,
            replacement = replacement
        }
    end
end

for index = 1, #Targets do
    bind(Targets[index], "print", WrappedPrint)
    if NativeType(NativeWarn) == "function" then bind(Targets[index], "warn", WrappedWarn) end
end

local function restoreBindings()
    for index = #State.bindings, 1, -1 do
        local item = State.bindings[index]
        local current = safeRawGet(item.target, item.key)
        if current == item.replacement then
            NativePCall(NativeRawSet, item.target, item.key,
                item.hadRawValue and item.oldValue or nil)
        end
    end
    State.bindings = {}
end

State.stop = function()
    if State.stopped then return end
    State.stopped = true
    restoreBindings()
    for index = 1, #State.connections do
        NativePCall(function() State.connections[index]:Disconnect() end)
    end
    State.connections = {}
    NativePCall(function() Gui:Destroy() end)
    if NativeType(InstallEnvironment) == "table" then
        local current = safeRawGet(InstallEnvironment, LOGGER_KEY)
        if current == State then NativePCall(NativeRawSet, InstallEnvironment, LOGGER_KEY, nil) end
    end
end

if NativeType(InstallEnvironment) == "table" then
    NativePCall(NativeRawSet, InstallEnvironment, LOGGER_KEY, State)
end

local copyConnection = CopyButton.MouseButton1Click:Connect(function()
    local reportOK, report = NativePCall(buildReport)
    if not reportOK then
        updateStatus("Could not build report: " .. safeText(report))
        return
    end

    local Clipboard = resolve("setclipboard")
        or resolve("toclipboard")
        or resolve("set_clipboard")
    if NativeType(Clipboard) ~= "function" then
        updateStatus("Clipboard API unavailable")
        CopyButton.Text = "Clipboard unavailable"
        return
    end

    local copied, copyError = NativePCall(Clipboard, report)
    if copied then
        updateStatus("Copied " .. #report .. " bytes / " .. LineCount .. " lines")
        CopyButton.Text = "Copied - paste into chat"
    else
        updateStatus("Copy failed: " .. safeText(copyError))
        CopyButton.Text = "Copy failed"
    end
end)
State.connections[#State.connections + 1] = copyConnection

local clearConnection = ClearButton.MouseButton1Click:Connect(function()
    Lines = {}
    Head = 1
    LineCount = 0
    ByteCount = 0
    Sequence = 0
    updateStatus("Log cleared")
    CopyButton.Text = "Copy captured log"
end)
State.connections[#State.connections + 1] = clearConnection

local closeConnection = CloseButton.MouseButton1Click:Connect(function()
    State.stop()
end)
State.connections[#State.connections + 1] = closeConnection

append("LOGGER", "ready; parent=" .. ParentKind .. "; run the probe now")
NativePCall(NativePrint, "IB2LOGGER|OK|GUI ready; run the probe, then click Copy captured log")
