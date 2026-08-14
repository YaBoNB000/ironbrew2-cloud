namespace IronBrew2.Obfuscator.VM_Generation
{
	public static class VMStrings
	{
		public static string VMP1 = @"
local BitXOR = bit and bit.bxor or bit32 and bit32.bxor or function(a,b)
    local p,c=1,0
    while a>0 and b>0 do
        local ra,rb=a%2,b%2
        if ra~=rb then c=c+p end
        a,b,p=(a-ra)/2,(b-rb)/2,p*2
    end
    if a<b then a=b end
    while a>0 do
        local ra=a%2
        if ra>0 then c=c+p end
        a,p=(a-ra)/2,p*2
    end
    return c
end

local function gBit(Bit, Start, End)
	if End then
		local Res = (Bit / 2 ^ (Start - 1)) % 2 ^ ((End - 1) - (Start - 1) + 1);
		return Res - Res % 1;
	else
		local Plc = 2 ^ (Start - 1);
        return (Bit % (Plc + Plc) >= Plc) and 1 or 0;
	end;
end;

-- DEFLATE(RFC 1951)解压器,与 C# 端 DeflateStream / Python zlib / Java Deflater 兼容
local function inflate(d)
	local p = 1;
	local function rd() local b = Byte(d, p); p = p + 1; return b; end;
	local bb, bc = 0, 0;
	local function gb(n)
		while bc < n do bb = bb + rd() * 2^bc; bc = bc + 8; end;
		local v = bb % 2^n;
		bb = (bb - bb % 2^n) / 2^n;
		bc = bc - n;
		return v;
	end;
	local out = {};
	local function em(c) out[#out + 1] = c; end;
	-- MSB-first 读 n 位:Huffman 码是 MSB-first 打包(fixed 距离码用),extra bits 是 LSB-first(用 gb)
	local function gbr(n) local v = 0; for i = 1, n do v = v * 2 + gb(1); end; return v; end;
	local LB = {3,4,5,6,7,8,9,10,11,13,15,17,19,23,27,31,35,43,51,59,67,83,99,115,131,163,195,227,258};
	local LE = {0,0,0,0,0,0,0,0,1,1,1,1,2,2,2,2,3,3,3,3,4,4,4,4,5,5,5,5,0};
	local DB = {1,2,3,4,5,7,9,13,17,25,33,49,65,97,129,193,257,385,513,769,1025,1537,2049,3073,4097,6145,8193,12289,16385,24577};
	local DE = {0,0,0,0,1,1,2,2,3,3,4,4,5,5,6,6,7,7,8,8,9,9,10,10,11,11,12,12,13,13};
	local function build(lens, n)
		local cnt = {};
		for i = 0, n - 1 do local l = lens[i] or 0; if l > 0 then cnt[l] = (cnt[l] or 0) + 1; end; end;
		local nxt = {};
		local code = 0;
		for l = 1, 15 do code = (code + (cnt[l - 1] or 0)) * 2; nxt[l] = code; end;
		local tbl = {};
		for s = 0, n - 1 do
			local l = lens[s];
			if l and l > 0 then tbl[l] = tbl[l] or {}; tbl[l][nxt[l]] = s; nxt[l] = nxt[l] + 1; end;
		end;
		return tbl;
	end;
	local function dec(tbl)
		local code = 0;
		for l = 1, 15 do
			code = code * 2 + gb(1);
			local row = tbl[l];
			if row then local s = row[code]; if s ~= nil then return s; end; end;
		end;
	end;
	local function fxl()
		local lens = {};
		for i = 0, 287 do lens[i] = 8; end;
		for i = 144, 255 do lens[i] = 9; end;
		for i = 256, 279 do lens[i] = 7; end;
		for i = 280, 287 do lens[i] = 8; end;
		return lens;
	end;
	local FXT = build(fxl(), 288);
	local function blk(ltbl)
		while true do
			local s = dec(ltbl);
			if s < 256 then em(s);
			elseif s == 256 then return;
			else
				local idx = s - 257;
				local len = LB[idx + 1] + gb(LE[idx + 1]);
				local ds = gbr(5);
				local dist = DB[ds + 1] + gb(DE[ds + 1]);
				local st = #out - dist;
				for i = 0, len - 1 do em(out[st + (i % dist) + 1]); end;
			end;
		end;
	end;
	while true do
		local bf = gb(1);
		local bt = gb(2);
		if bt == 0 then
			if bc > 0 then gb(bc); end;
			local len = rd() + rd() * 256;
			rd(); rd();
			for i = 1, len do em(rd()); end;
		elseif bt == 1 then
			blk(FXT);
		else
			local hl = 257 + gb(5);
			local hd = 1 + gb(5);
			local hc = 4 + gb(4);
			local order = {16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15};
			local clens = {};
			for i = 0, hc - 1 do clens[order[i + 1]] = gb(3); end;
			local ctbl = build(clens, 19);
			local all = {};
			local i = 0;
			while i < hl + hd do
				local s = dec(ctbl);
				if s < 16 then all[i] = s; i = i + 1;
				elseif s == 16 then
					local r = 3 + gb(2);
					local prev = all[i - 1] or 0;
					for j = 1, r do all[i] = prev; i = i + 1; end;
				elseif s == 17 then
					local r = 3 + gb(3);
					for j = 1, r do all[i] = 0; i = i + 1; end;
				else
					local r = 11 + gb(7);
					for j = 1, r do all[i] = 0; i = i + 1; end;
				end;
			end;
			local ll, dl = {}, {};
			for j = 0, hl - 1 do ll[j] = all[j]; end;
			for j = 0, hd - 1 do dl[j] = all[hl + j]; end;
			local ltbl = build(ll, hl);
			local dtbl = build(dl, hd);
			while true do
				local s = dec(ltbl);
				if s < 256 then em(s);
				elseif s == 256 then break;
				else
					local idx = s - 257;
					local len = LB[idx + 1] + gb(LE[idx + 1]);
					local dc = dec(dtbl);
					local dist = DB[dc + 1] + gb(DE[dc + 1]);
					local st = #out - dist;
					for i = 0, len - 1 do em(out[st + (i % dist) + 1]); end;
				end;
			end;
		end;
		if bf == 1 then break; end;
	end;
	local res = {};
	for i = 1, #out do res[i] = Char(out[i]); end;
	return Concat(res);
end;

-- Read the 4-byte header value (little-endian). With EnvironmentLock it is the
-- salt; otherwise it is the seed itself. The real XOR seed Xs is derived right
-- after this block by the Generator-injected code.
local __ib2Head = Byte(ByteString, 1, 1)
         + Byte(ByteString, 2, 2) * 256
         + Byte(ByteString, 3, 3) * 65536
         + Byte(ByteString, 4, 4) * 16777216;
__IB2_SEED__
-- 指令流加密密钥 K1/K2(16 位),主循环按 InstrPoint 派生密钥逐条解密 opcode
local K1 = Byte(ByteString, 5, 5) + Byte(ByteString, 6, 6) * 256;
local K2 = Byte(ByteString, 7, 7) + Byte(ByteString, 8, 8) * 256;
-- 压缩标志(第 9 字节):1 = body 经 DEFLATE 压缩,0 = 明文
local __ib2Flag = Byte(ByteString, 9, 9);

-- 整体流式 XOR 解密(第 10 字节起) → body
local __ib2Dec = {};
for __ib2i = 10, #ByteString do
	local __ib2b = Byte(ByteString, __ib2i, __ib2i);
	local __ib2k = (Xs - Xs % 16777216) / 16777216;
	Xs = (Xs * 1664525 + 1013904223) % 4294967296;
	__ib2Dec[__ib2i - 9] = Char(BitXOR(__ib2b, __ib2k));
end
ByteString = Concat(__ib2Dec);
-- DEFLATE 解压(若压缩) → 明文字节码
if __ib2Flag ~= 0 then
	ByteString = inflate(ByteString);
end
local Pos = 1;

local function gBits32()
    local W, X, Y, Z = Byte(ByteString, Pos, Pos + 3);
    Pos	= Pos + 4;
    return (Z*16777216) + (Y*65536) + (X*256) + W;
end;

local function gBits8()
    local F = Byte(ByteString, Pos, Pos);
    Pos = Pos + 1;
    return F;
end;

local function gBits16()
    local W, X = Byte(ByteString, Pos, Pos + 2);
    Pos	= Pos + 2;
    return (X*256) + W;
end;

local function gFloat()
	local Left = gBits32();
	local Right = gBits32();
	local IsNormal = 1;
	local Mantissa = (gBit(Right, 1, 20) * (2 ^ 32))
					+ Left;
	local Exponent = gBit(Right, 21, 31);
	local Sign = ((-1) ^ gBit(Right, 32));
	if (Exponent == 0) then
		if (Mantissa == 0) then
			return Sign * 0; -- +-0
		else
			Exponent = 1;
			IsNormal = 0;
		end;
	elseif (Exponent == 2047) then
        return (Mantissa == 0) and (Sign * (1 / 0)) or (Sign * (0 / 0));
	end;
	return LDExp(Sign, Exponent - 1023) * (IsNormal + (Mantissa / (2 ^ 52)));
end;

local gSizet = gBits32;
local function gString(Len)
    local Str;
    if (not Len) then
        Len = gSizet();
        if (Len == 0) then
            return '';
        end;
    end;

    Str	= Sub(ByteString, Pos, Pos + Len - 1);
    Pos = Pos + Len;
    return Str;
end;

local gInt = gBits32;
local function _R(...) return {...}, Select('#', ...) end

local function Deserialize()
    local Instrs = {};
    local Functions = {};
	local Lines = {};
    local Chunk = 
	{
		Instrs,
		Functions,
		nil,
		Lines
	};
	local ConstCount = gBits32()
    local Consts = {}

	for Idx=1, ConstCount do 
		local Type =gBits8();
		local Cons;
	
		if(Type==CONST_BOOL) then Cons = (gBits8() ~= 0);
		elseif(Type==CONST_FLOAT) then Cons = gFloat();
		elseif(Type==CONST_STRING) then Cons = gString();
		end;
		
		Consts[Idx] = Cons;
	end;
";
		
		public static string VMP2 = @"
local function Wrap(Chunk, Upvalues, Env)
	local Instr  = Chunk[1];
	local Proto  = Chunk[2];
	local Params = Chunk[3];

	return function(...)
		local Instr  = Instr; 
		local Proto  = Proto; 
		local Params = Params;

		local _R = _R
		local InstrPoint = 1;
		local Top = -1;

		local Vararg = {};
		local Args	= {...};

		local PCount = Select('#', ...) - 1;

		local Lupvals	= {};
		local Stk		= {};

		for Idx = 0, PCount do
			if (Idx >= Params) then
				Vararg[Idx - Params] = Args[Idx + 1];
			else
				Stk[Idx] = Args[Idx + 1];
			end;
		end;

		local Varargsz = PCount - Params + 1

		local Inst;
		local Enum;	

		while true do
			Inst		= Instr[InstrPoint];
			Enum		= BitXOR(Inst[OP_ENUM], (InstrPoint * K1 + K2) % 65536);";

		public static string VMP2_R = @"
local function Wrap(Chunk, Upvalues, Env)
	local Instr  = Chunk[1];
	local Proto  = Chunk[2];
	local Params = Chunk[3];

	return function(...)
		local Instr  = Instr; 
		local Proto  = Proto; 
		local Params = Params;

		local _R = _R
		local InstrPoint = 1;
		local Top = -1;

		local Vararg = {};
		local Args	= {...};

		local PCount = Select('#', ...) - 1;

		local Lupvals	= {};
		local Stk		= {};

		for Idx = 0, PCount do
			if (Idx >= Params) then
				Vararg[Idx - Params] = Args[Idx + 1];
			else
				Stk[Idx] = Args[Idx + 1];
			end;
		end;

		local Varargsz = PCount - Params + 1

		local Inst;
		local Enum;	

		repeat
			Inst		= Instr[InstrPoint];
			Enum		= BitXOR(Inst[OP_ENUM], (InstrPoint * K1 + K2) % 65536);";

		public static string VMP3 = @"
			InstrPoint	= InstrPoint + 1;
		end;
    end;
end;	
return Wrap(Deserialize(), {}, GetFEnv());
end)()(...);
";
		public static string VMP3_R = @"
			InstrPoint	= InstrPoint + 1;
		until false;
    end;
end;	
return Wrap(Deserialize(), {}, GetFEnv());
end)()(...);
";
		public static string VMP2_LI = @"
local PCall = pcall
local function Wrap(Chunk, Upvalues, Env)
	local Instr = Chunk[1];
	local Proto = Chunk[2];
	local Params = Chunk[3];

	return function(...)
		local InstrPoint = 1;
		local Top = -1;

		local Args = {...};
		local PCount = Select('#', ...) - 1;

		local function Loop()
			local Instr  = Instr; 
			local Const  = Const; 
			local Proto  = Proto; 
			local Params = Params;

			local _R = _R
			local Vararg = {};

			local Lupvals	= {};
			local Stk		= {};
	
			for Idx = 0, PCount do
				if (Idx >= Params) then
					Vararg[Idx - Params] = Args[Idx + 1];
				else
					Stk[Idx] = Args[Idx + 1];
				end;
			end;
	
			local Varargsz = PCount - Params + 1

			local Inst;
			local Enum;	

			while true do
				Inst		= Instr[InstrPoint];
				Enum		= BitXOR(Inst[OP_ENUM], (InstrPoint * K1 + K2) % 65536);";
		
		public static string VMP2_LI_R = @"
local PCall = pcall
local function Wrap(Chunk, Upvalues, Env)
	local Instr = Chunk[1];
	local Proto = Chunk[2];
	local Params = Chunk[3];

	return function(...)
		local InstrPoint = 1;
		local Top = -1;

		local Args = {...};
		local PCount = Select('#', ...) - 1;

		local function Loop()
			local Instr  = Instr; 
			local Const  = Const; 
			local Proto  = Proto; 
			local Params = Params;

			local _R = _R
			local Vararg = {};

			local Lupvals	= {};
			local Stk		= {};
	
			for Idx = 0, PCount do
				if (Idx >= Params) then
					Vararg[Idx - Params] = Args[Idx + 1];
				else
					Stk[Idx] = Args[Idx + 1];
				end;
			end;
	
			local Varargsz = PCount - Params + 1

			local Inst;
			local Enum;	

			repeat
				Inst		= Instr[InstrPoint];
				Enum		= BitXOR(Inst[OP_ENUM], (InstrPoint * K1 + K2) % 65536);";
		
		public static string VMP3_LI = @"
				InstrPoint	= InstrPoint + 1;
			end;
		end;

		local A, B = _R(PCall(Loop))
		if not A[1] then
			local line = Chunk[7][InstrPoint] or '?'
			error('ERROR IN IRONBREW SCRIPT [LINE ' .. line .. ']:' .. A[2])
		else
			return Unpack(A, 2, B)
		end;
	end;
end;	
return Wrap(Deserialize(), {}, GetFEnv());
end)()(...);
";
		public static string VMP3_LI_R = @"
				InstrPoint	= InstrPoint + 1;
			until false;
		end;

		local A, B = _R(PCall(Loop))
		if not A[1] then
			local line = Chunk[7][InstrPoint] or '?'
			error('ERROR IN IRONBREW SCRIPT [LINE ' .. line .. ']:' .. A[2])
		else
			return Unpack(A, 2, B)
		end;
	end;
end;	
return Wrap(Deserialize(), {}, GetFEnv());
end)()(...);
";
	}
}