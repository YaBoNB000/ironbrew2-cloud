local function first()
    local marker = 7
    local function second()
        return marker + missing_value
    end
    return second()
end

first()
