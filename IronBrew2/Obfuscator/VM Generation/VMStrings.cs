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
local function inflate(d, expected)
	local p = 1;
	local function rd() if p > #d then error('invalid protected payload', 0); end; local b = Byte(d, p); p = p + 1; return b; end;
	local bb, bc = 0, 0;
	local function gb(n)
		while bc < n do bb = bb + rd() * 2^bc; bc = bc + 8; end;
		local v = bb % 2^n;
		bb = (bb - bb % 2^n) / 2^n;
		bc = bc - n;
		return v;
	end;
	local out = {};
	local function em(c) if #out >= expected then error('invalid protected payload', 0); end; out[#out + 1] = c; end;
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
	if #out ~= expected then error('invalid protected payload', 0); end;
	local res = {};
	for i = 1, #out do res[i] = Char(out[i]); end;
	return Concat(res);
end;

-- v5 Build-local outer grammar. The field positions are generated into this VM
-- rather than carried by a generic format selector in the payload.
if PayloadLength < 41 then error('invalid protected payload', 0); end;
local function PayloadByteAt(Index)
    if Index < 1 or Index > PayloadLength then error('invalid protected payload', 0); end;
    local ZeroIndex = Index - 1;
    local PayloadChunkIndex = (ZeroIndex - ZeroIndex % 2048) / 2048 + 1;
    local PayloadChunkOffset = ZeroIndex % 2048 + 1;
    local PayloadChunk = PayloadCiphertext[PayloadChunkIndex];
    if PayloadChunk == nil then error('invalid protected payload', 0); end;
    return Byte(PayloadChunk, PayloadChunkOffset, PayloadChunkOffset);
end;
local PayloadHead = PayloadByteAt(__IB2_OUTER_HEAD_OFFSET__)
         + PayloadByteAt(__IB2_OUTER_HEAD_OFFSET__ + 1) * 256
         + PayloadByteAt(__IB2_OUTER_HEAD_OFFSET__ + 2) * 65536
         + PayloadByteAt(__IB2_OUTER_HEAD_OFFSET__ + 3) * 16777216;
local PayloadTag = PayloadByteAt(__IB2_OUTER_TAG_OFFSET__)
         + PayloadByteAt(__IB2_OUTER_TAG_OFFSET__ + 1) * 256
         + PayloadByteAt(__IB2_OUTER_TAG_OFFSET__ + 2) * 65536
         + PayloadByteAt(__IB2_OUTER_TAG_OFFSET__ + 3) * 16777216;
local PayloadFlags = PayloadByteAt(__IB2_OUTER_FLAGS_OFFSET__);
local PayloadFeatures = PayloadFlags % 16;
local PayloadVersion = (PayloadFlags - PayloadFeatures) / 16;
if PayloadVersion ~= 5 or PayloadFeatures < 14 or PayloadFeatures > 15 then error('invalid protected payload', 0); end;
__IB2_SEED__
local OuterSeed = Xs;
local PayloadAttestation = __IB2_PAYLOAD_ATTESTATION__;

-- v4's polynomial tag was directly reversible because every public byte was
-- absorbed with multiplication by 31. v5 derives Xi separately from OuterSeed,
-- uses two coupled lanes and emits only their final compression, so the outer
-- tag no longer discloses the envelope stream seed via a backwards O(n) recurrence.
local function PayloadRotate16(Value)
    local PayloadLow = Value % 65536;
    return (PayloadLow * 65536 + (Value - PayloadLow) / 65536) % 4294967296;
end;
local PayloadAuthA = (BitXOR(Xi, __IB2_DOMAIN_INTEGRITY__) + 2781082087 + PayloadFlags * 257) % 4294967296;
local PayloadAuthB = (Xi + PayloadRotate16(__IB2_DOMAIN_INTEGRITY__) + 2135587861
    + (PayloadLength - 9) * 17) % 4294967296;
for PayloadIndex = 10, PayloadLength do
    local PayloadByte = PayloadByteAt(PayloadIndex);
    local PayloadMix = (PayloadByte + (PayloadIndex - 9) * 257 + PayloadFlags * 17) % 4294967296;
    PayloadAuthA = (BitXOR(PayloadAuthA, PayloadMix) * 65599 + 2654435769) % 4294967296;
    PayloadAuthB = ((PayloadAuthB + PayloadMix + (PayloadAuthA - PayloadAuthA % 65536) / 65536)
        * 48271 + 1831565813) % 4294967296;
    PayloadAuthA = BitXOR(PayloadAuthA, PayloadRotate16(PayloadAuthB)) % 4294967296;
end;
PayloadAuthA = (BitXOR(BitXOR(PayloadAuthA, PayloadAuthB), PayloadLength - 9)
    * 65599 + __IB2_DOMAIN_INTEGRITY__) % 4294967296;
PayloadAuthB = (BitXOR(BitXOR(PayloadAuthB, PayloadRotate16(PayloadAuthA)), PayloadFlags)
    * 48271 + 3302136427) % 4294967296;
local PayloadHash = BitXOR(PayloadAuthA, PayloadRotate16(PayloadAuthB)) % 4294967296;
if PayloadHash ~= PayloadTag then error('invalid protected payload', 0); end;

-- The outer XOR stream is consumed once to authenticate envelope framing. Record
-- bodies are discarded immediately; descriptors retain only ciphertext offset,
-- length, and the outer PRNG state at the first record byte.
local EnvelopeCipherPos = 10;
local EnvelopeCipherState = Xs;
local EnvelopePlainPos = 0;
local EnvelopeHash = (BitXOR(OuterSeed, __IB2_DOMAIN_ENVELOPE_INTEGRITY__) * 31) % 4294967296;
local function EnvelopeRead8()
    if EnvelopeCipherPos > PayloadLength then error('invalid protected payload', 0); end;
    local CipherByte = PayloadByteAt(EnvelopeCipherPos);
    local KeyByte = (EnvelopeCipherState - EnvelopeCipherState % 16777216) / 16777216;
    local PlainByte = BitXOR(CipherByte, KeyByte);
    EnvelopeCipherState = (EnvelopeCipherState * __IB2_STREAM_MULTIPLIER__ + __IB2_STREAM_INCREMENT__) % 4294967296;
    EnvelopeCipherPos = EnvelopeCipherPos + 1;
    EnvelopePlainPos = EnvelopePlainPos + 1;
    if EnvelopePlainPos < __IB2_ENVELOPE_INTEGRITY_START__ or EnvelopePlainPos > __IB2_ENVELOPE_INTEGRITY_END__ then
        EnvelopeHash = (EnvelopeHash * 31 + PlainByte) % 4294967296;
    end;
    return PlainByte;
end;
local function EnvelopeRead32()
    local W, X, Y, Z = EnvelopeRead8(), EnvelopeRead8(), EnvelopeRead8(), EnvelopeRead8();
    return W + X * 256 + Y * 65536 + Z * 16777216;
end;
local EnvelopeRealLength, EnvelopeEntropyLength, EnvelopeRecordCount, EnvelopeDataCount;
local EnvelopeEntropyCount, EnvelopeNonce, EnvelopeDigest, EnvelopeTag;
__IB2_ENVELOPE_HEADER_READS__
local EnvelopeExpected = 32 + EnvelopeRecordCount * __IB2_RECORD_HEADER_WIDTH__ + EnvelopeRealLength + EnvelopeEntropyLength;
if EnvelopeRealLength < 5 or EnvelopeRealLength > 83886080
or EnvelopeEntropyLength < 65536 or EnvelopeEntropyLength > 98304
or EnvelopeDataCount < 1 or EnvelopeDataCount > 65535
or EnvelopeEntropyCount < 8 or EnvelopeEntropyCount > 64
or EnvelopeRecordCount ~= EnvelopeDataCount + EnvelopeEntropyCount
or EnvelopeNonce == 0 or EnvelopeExpected ~= PayloadLength - 9 then error('invalid protected payload', 0); end;

local PayloadPageDescriptors = {};
local EntropyDescriptors = {};
local EnvelopeDataLength = 0;
local EnvelopeEntropySeenLength = 0;
local function EnvelopeReadWidth(Width)
    local Value, Multiplier = 0, 1;
    for FieldIndex = 1, Width do
        Value = Value + EnvelopeRead8() * Multiplier;
        Multiplier = Multiplier * 256;
    end;
    return Value;
end;
for EnvelopeIndex = 1, EnvelopeRecordCount do
    local EnvelopeKind, EnvelopeOrdinal, EnvelopeLength;
    __IB2_RECORD_FIELD_READS__
    if EnvelopeLength < 1 or EnvelopeCipherPos + EnvelopeLength - 1 > PayloadLength then error('invalid protected payload', 0); end;
    local Descriptor = {EnvelopeCipherPos, EnvelopeLength, EnvelopeCipherState};
    if EnvelopeKind == __IB2_DATA_RECORD_KIND__ then
        if EnvelopeOrdinal < 1 or EnvelopeOrdinal > EnvelopeDataCount or PayloadPageDescriptors[EnvelopeOrdinal] ~= nil then error('invalid protected payload', 0); end;
        PayloadPageDescriptors[EnvelopeOrdinal] = Descriptor;
        EnvelopeDataLength = EnvelopeDataLength + EnvelopeLength;
    elseif EnvelopeKind == __IB2_ENTROPY_RECORD_KIND__ then
        if EnvelopeOrdinal < 1 or EnvelopeOrdinal > EnvelopeEntropyCount or EntropyDescriptors[EnvelopeOrdinal] ~= nil then error('invalid protected payload', 0); end;
        EntropyDescriptors[EnvelopeOrdinal] = Descriptor;
        EnvelopeEntropySeenLength = EnvelopeEntropySeenLength + EnvelopeLength;
    else
        error('invalid protected payload', 0);
    end;
    for EnvelopeByteIndex = 1, EnvelopeLength do EnvelopeRead8(); end;
end;
if EnvelopeCipherPos ~= PayloadLength + 1 or EnvelopeDataLength ~= EnvelopeRealLength
or EnvelopeEntropySeenLength ~= EnvelopeEntropyLength or EnvelopeHash ~= EnvelopeTag then error('invalid protected payload', 0); end;

-- Entropy is authenticated in logical order without retaining any entropy record.
local EntropyHash = (BitXOR(OuterSeed, __IB2_DOMAIN_ENTROPY_DIGEST__) * 31 + EnvelopeNonce) % 4294967296;
EntropyHash = (EntropyHash * 31 + EnvelopeEntropyLength) % 4294967296;
EntropyHash = (EntropyHash * 31 + EnvelopeEntropyCount) % 4294967296;
for EnvelopeIndex = 1, EnvelopeEntropyCount do
    local Descriptor = EntropyDescriptors[EnvelopeIndex];
    if Descriptor == nil then error('invalid protected payload', 0); end;
    EntropyHash = (EntropyHash * 31 + EnvelopeIndex) % 4294967296;
    EntropyHash = (EntropyHash * 31 + Descriptor[2]) % 4294967296;
    local DescriptorState = Descriptor[3];
    for DescriptorOffset = 0, Descriptor[2] - 1 do
        local KeyByte = (DescriptorState - DescriptorState % 16777216) / 16777216;
        local PlainByte = BitXOR(PayloadByteAt(Descriptor[1] + DescriptorOffset), KeyByte);
        EntropyHash = (EntropyHash * 31 + PlainByte) % 4294967296;
        DescriptorState = (DescriptorState * __IB2_STREAM_MULTIPLIER__ + __IB2_STREAM_INCREMENT__) % 4294967296;
    end;
end;
EntropyDescriptors = nil;
if EntropyHash ~= EnvelopeDigest then error('invalid protected payload', 0); end;

-- Assign each logical page its inner mask state and authenticate its bounded raw
-- length. No page content is retained until the source reader requests it.
local EnvelopeMaskState = BitXOR(BitXOR(BitXOR(BitXOR(BitXOR(BitXOR(OuterSeed, EnvelopeNonce), EnvelopeDigest), __IB2_DOMAIN_ENVELOPE_MASK__), __IB2_DOMAIN_PAYLOAD_FORMAT__), __IB2_DOMAIN_DECODE_PIPELINE__), EnvelopeRealLength) % 4294967296;
local PayloadSourceLength = 0;
for PageOrdinal = 1, EnvelopeDataCount do
    local Descriptor = PayloadPageDescriptors[PageOrdinal];
    if Descriptor == nil or Descriptor[2] < __IB2_PAGE_MIN_FRAME__ or Descriptor[2] > 16384 then error('invalid protected payload', 0); end;
    Descriptor[4] = EnvelopeMaskState;
    local DescriptorState = Descriptor[3];
    local RawLength = 0;
    local Multiplier = 1;
    local LengthOffset = __IB2_PAGE_LENGTH_OFFSET__;
    for PageByteIndex = 0, Descriptor[2] - 1 do
        local OuterKey = (DescriptorState - DescriptorState % 16777216) / 16777216;
        local InnerKey = (EnvelopeMaskState - EnvelopeMaskState % 16777216) / 16777216;
        if PageByteIndex >= LengthOffset and PageByteIndex < LengthOffset + __IB2_PAGE_LENGTH_WIDTH__ then
            local NestedByte = BitXOR(PayloadByteAt(Descriptor[1] + PageByteIndex), OuterKey);
            RawLength = RawLength + BitXOR(NestedByte, InnerKey) * Multiplier;
            Multiplier = Multiplier * 256;
        end;
        DescriptorState = (DescriptorState * __IB2_STREAM_MULTIPLIER__ + __IB2_STREAM_INCREMENT__) % 4294967296;
        EnvelopeMaskState = (EnvelopeMaskState * __IB2_STREAM_MULTIPLIER__ + __IB2_STREAM_INCREMENT__) % 4294967296;
    end;
    if RawLength < 1 or RawLength > 6144 then error('invalid protected payload', 0); end;
    Descriptor[5] = RawLength;
    PayloadSourceLength = PayloadSourceLength + RawLength;
    if PayloadSourceLength > 67108864 then error('invalid protected payload', 0); end;
end;

local PayloadPageOrdinal = 0;
local PayloadPage = nil;
local PayloadPagePosition = 1;
local function LoadPayloadPage()
    PayloadPage = nil;
    PayloadPageOrdinal = PayloadPageOrdinal + 1;
    local Descriptor = PayloadPageDescriptors[PayloadPageOrdinal];
    if Descriptor == nil then error('invalid protected payload', 0); end;
    local DescriptorState = Descriptor[3];
    local MaskState = Descriptor[4];
    local EncodedParts = {};
    local FramedLength = 0;
    local Multiplier = 1;
    local EncodedIndex = 1;
    local LengthOffset = __IB2_PAGE_LENGTH_OFFSET__;
    for PageByteIndex = 0, Descriptor[2] - 1 do
        local OuterKey = (DescriptorState - DescriptorState % 16777216) / 16777216;
        local InnerKey = (MaskState - MaskState % 16777216) / 16777216;
        local NestedByte = BitXOR(PayloadByteAt(Descriptor[1] + PageByteIndex), OuterKey);
        local PlainByte = BitXOR(NestedByte, InnerKey);
        if PageByteIndex >= LengthOffset and PageByteIndex < LengthOffset + __IB2_PAGE_LENGTH_WIDTH__ then
            FramedLength = FramedLength + PlainByte * Multiplier;
            Multiplier = Multiplier * 256;
        else
            EncodedParts[EncodedIndex] = PlainByte;
            EncodedIndex = EncodedIndex + 1;
        end;
        DescriptorState = (DescriptorState * __IB2_STREAM_MULTIPLIER__ + __IB2_STREAM_INCREMENT__) % 4294967296;
        MaskState = (MaskState * __IB2_STREAM_MULTIPLIER__ + __IB2_STREAM_INCREMENT__) % 4294967296;
    end;
    if FramedLength ~= Descriptor[5] then error('invalid protected payload', 0); end;
    if __IB2_PAGE_PIPELINE__ == 1 then
        local Left, Right = 1, #EncodedParts;
        while Left < Right do
            EncodedParts[Left], EncodedParts[Right] = EncodedParts[Right], EncodedParts[Left];
            Left, Right = Left + 1, Right - 1;
        end;
    elseif __IB2_PAGE_PIPELINE__ == 2 then
        local PipelineState = BitXOR(BitXOR(BitXOR(BitXOR(OuterSeed, EnvelopeNonce), EnvelopeDigest), __IB2_DOMAIN_DECODE_PIPELINE__), (PayloadPageOrdinal * 2654435769) % 4294967296) % 4294967296;
        for PipelineIndex = 1, #EncodedParts do
            local TransformedByte = EncodedParts[PipelineIndex];
            local PlainByte = BitXOR(TransformedByte, (PipelineState - PipelineState % 16777216) / 16777216);
            EncodedParts[PipelineIndex] = PlainByte;
            PipelineState = (PipelineState * __IB2_STREAM_MULTIPLIER__ + __IB2_STREAM_INCREMENT__ + PlainByte + PipelineIndex - 1) % 4294967296;
        end;
    end;
    if __IB2_PAGE_BYTE_TRANSFORM__ == 1 then
        for EncodedPartIndex = 1, #EncodedParts do
            local PlainByte = EncodedParts[EncodedPartIndex];
            EncodedParts[EncodedPartIndex] = (PlainByte % 16) * 16 + (PlainByte - PlainByte % 16) / 16;
        end;
    elseif __IB2_PAGE_BYTE_TRANSFORM__ == 2 then
        local PageByteMask = (__IB2_PAGE_BYTE_PARAMETER__ + PayloadPageOrdinal * 29) % 256;
        for EncodedPartIndex = 1, #EncodedParts do EncodedParts[EncodedPartIndex] = BitXOR(EncodedParts[EncodedPartIndex], PageByteMask); end;
    elseif __IB2_PAGE_BYTE_TRANSFORM__ == 3 then
        local RotateDivisor = 2 ^ __IB2_PAGE_BYTE_PARAMETER__;
        local RotateFactor = 2 ^ (8 - __IB2_PAGE_BYTE_PARAMETER__);
        for EncodedPartIndex = 1, #EncodedParts do
            local PlainByte = EncodedParts[EncodedPartIndex];
            EncodedParts[EncodedPartIndex] = (PlainByte - PlainByte % RotateDivisor) / RotateDivisor + (PlainByte % RotateDivisor) * RotateFactor;
        end;
    end;
    for EncodedPartIndex = 1, #EncodedParts do EncodedParts[EncodedPartIndex] = Char(EncodedParts[EncodedPartIndex]); end;
    local EncodedPage = Concat(EncodedParts);
    EncodedParts = nil;
    if gBit(PayloadFeatures, 1, 1) == 1 then
        PayloadPage = inflate(EncodedPage, FramedLength);
    else
        if #EncodedPage ~= FramedLength then error('invalid protected payload', 0); end;
        PayloadPage = EncodedPage;
    end;
    EncodedPage = nil;
    PayloadPagePosition = 1;
end;

-- Source abstraction: root reads bounded pages; child prototypes and opaque block
-- or capsule slices use the same readers over a local string source.
local ByteString = nil;
local Pos = 1;
local ActiveSourceLength = PayloadSourceLength;
local SourceIsPaged = true;
local ActivePrototypeHash = nil;
local function TrackPrototypeByte(Value)
    if ActivePrototypeHash ~= nil then ActivePrototypeHash = (ActivePrototypeHash * 31 + Value) % 4294967296; end;
end;
local function SourceRead8()
    local Value;
    if SourceIsPaged then
        if Pos > PayloadSourceLength then error('invalid protected payload', 0); end;
        if PayloadPage == nil or PayloadPagePosition > #PayloadPage then LoadPayloadPage(); end;
        Value = Byte(PayloadPage, PayloadPagePosition, PayloadPagePosition);
        PayloadPagePosition = PayloadPagePosition + 1;
    else
        if Pos > ActiveSourceLength then error('invalid protected payload', 0); end;
        Value = Byte(ByteString, Pos, Pos);
    end;
    Pos = Pos + 1;
    TrackPrototypeByte(Value);
    return Value;
end;
local function SourceReadBytes(Length)
    if Length < 0 or Pos + Length - 1 > ActiveSourceLength then error('invalid protected payload', 0); end;
    local Parts = {};
    for Index = 1, Length do Parts[Index] = Char(SourceRead8()); end;
    return Concat(Parts);
end;

local function gBits32()
    local W, X, Y, Z = SourceRead8(), SourceRead8(), SourceRead8(), SourceRead8();
    return Z * 16777216 + Y * 65536 + X * 256 + W;
end;
local function gBits8() return SourceRead8(); end;
local function gBits16()
    local W, X = SourceRead8(), SourceRead8();
    return X * 256 + W;
end;

local function gFloat()
    local Left = gBits32();
    local Right = gBits32();
    local IsNormal = 1;
    local Mantissa = (gBit(Right, 1, 20) * (2 ^ 32)) + Left;
    local Exponent = gBit(Right, 21, 31);
    local Sign = ((-1) ^ gBit(Right, 32));
    if Exponent == 0 then
        if Mantissa == 0 then return Sign * 0; else Exponent = 1; IsNormal = 0; end;
    elseif Exponent == 2047 then
        return (Mantissa == 0) and (Sign * (1 / 0)) or (Sign * (0 / 0));
    end;
    return LDExp(Sign, Exponent - 1023) * (IsNormal + (Mantissa / (2 ^ 52)));
end;

local gSizet = gBits32;
local function gString(Len, Idx, K1, K2, K3)
    if not Len then Len = gSizet(); end;
    if Len == 0 then return ''; end;
    local Enc = SourceReadBytes(Len);
    local State = (K1 + K2 + K3 + Idx * 257) % 65536;
    local Out = {};
    for I = 1, Len do
        Out[I] = Char(BitXOR(Byte(Enc, I, I), State % 256));
        State = (State * 251 + K3 + Idx) % 65536;
    end;
    return Concat(Out);
end;

local function U32(V)
    if V < 0 then return V + 4294967296; end;
    return V;
end;

-- Exact uint32 multiplication for stock Lua 5.1 doubles. Direct products by
-- the chunk-chain multipliers exceed the 53-bit exact-integer range.
local function U32Mul(A, B)
    local ALow, BLow = A % 65536, B % 65536;
    local AHigh, BHigh = (A - ALow) / 65536, (B - BLow) / 65536;
    return (ALow * BLow + ((ALow * BHigh + AHigh * BLow) % 65536) * 65536) % 4294967296;
end;

local function OpcodeKey(I, K1, K2, K3)
    local V = (I * K1 + K2) % 65536;
    return (V * ((I % 251) + 1) + K3) % 65536;
end;

local function FieldKey(I, Slot, K1, K2, K3)
    return OpcodeKey(I + Slot * 257, K2, K3, K1);
end;

local function FieldKey32(I, Slot, K1, K2, K3)
    return FieldKey(I, Slot, K1, K2, K3)
        + FieldKey(I, Slot + 4, K1, K2, K3) * 65536;
end;

local function InitialFlowKey(K1, K2, K3)
    local Value = (K1 * 65537 + K2 * 257 + K3 + __IB2_DOMAIN_FLOW__ + OuterSeed) % 4294967296;
    return (Value * 1664525 + 1013904223) % 4294967296;
end;

local function FlowKey(EntryState, FromPC, ToPC, K1, K2, K3)
    local Value = (EntryState * 1664525 + FromPC * 257 + ToPC * 65537
        + K1 * 251 + K2 * 17 + K3 + __IB2_DOMAIN_FLOW__ + OuterSeed) % 4294967296;
    return (Value * 1664525 + 1013904223) % 4294967296;
end;

local function FlowVerifier(EntryState, BlockStart, K1, K2, K3)
    return FlowKey(EntryState, BlockStart, BitXOR(BlockStart, __IB2_FLOW_VERIFIER_MASK__), K1, K2, K3);
end;

local function ChunkState(EntryState, BlockStart, Count, K1, K2, K3)
    local Value = (U32Mul(EntryState, 22695477) + BlockStart * 65537 + Count * 257
        + K1 * 251 + K2 * 17 + K3 + __IB2_DOMAIN_CHUNK_STATE__ + OuterSeed + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 1664525) + 1013904223) % 4294967296;
end;

local function InitialChunkKey(K1, K2, K3)
    local Value = (K1 * 65537 + K2 * 257 + K3 + __IB2_DOMAIN_CHUNK_STATE__
        + OuterSeed + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 22695477) + 1) % 4294967296;
end;

local function ChunkChainKey(SourceChunkState, SourceEntryState, FromPC, ToPC, K1, K2, K3)
    local Value = (U32Mul(SourceChunkState, 1664525) + U32Mul(SourceEntryState, 22695477)
        + FromPC * 257 + ToPC * 65537 + K1 * 251 + K2 * 17 + K3
        + __IB2_DOMAIN_CHUNK_STATE__ + OuterSeed + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 1664525) + 1013904223) % 4294967296;
end;

local function BlockFieldKey(EntryState, I, Slot, K1, K2, K3)
    local Low = EntryState % 65536;
    local High = (EntryState - Low) / 65536;
    return (Low * (((I + Slot * 29) % 251) + 1) + High * 17
        + K1 * 13 + K2 * 7 + K3 + Slot * __IB2_BLOCK_FIELD_STRIDE__) % 65536;
end;

local function BlockFieldKey32(EntryState, I, Slot, K1, K2, K3)
    return BlockFieldKey(EntryState, I, Slot, K1, K2, K3)
        + BlockFieldKey(EntryState, I, Slot + 4, K1, K2, K3) * 65536;
end;

local function ConstantMaskState(Index, EntryState, CurrentChunkState, BlockStart, K1, K2, K3)
    local Value = (Index * 65537 + U32Mul(EntryState, 22695477)
        + U32Mul(CurrentChunkState, 1664525) + BlockStart * 257
        + K1 * 257 + K2 * 17 + K3 + __IB2_DOMAIN_CONSTANT_MASK__) % 4294967296;
    return (U32Mul(Value, 1664525) + 1013904223) % 4294967296;
end;

local function ComputeConstantIntegrity(EncodedBody, Index, EntryState, CurrentChunkState, BlockStart, K1, K2, K3)
    local Keyed = (K1 * 65537 + K2 * 257 + K3) % 4294967296;
    local Hash = (BitXOR(BitXOR(BitXOR(Keyed, __IB2_DOMAIN_CONSTANT_INTEGRITY__), EntryState), CurrentChunkState) * 31 + BlockStart) % 4294967296;
    Hash = (Hash * 31 + Index) % 4294967296;
    Hash = (Hash * 31 + #EncodedBody) % 4294967296;
    for I = 1, #EncodedBody do Hash = (Hash * 31 + Byte(EncodedBody, I, I)) % 4294967296; end;
    return Hash;
end;

local function InstructionDigest(Record, Index, K1, K2, K3)
    local Hash = (BitXOR(__IB2_DOMAIN_INSTRUCTION_STATE__, Index) * 31 + K1) % 4294967296;
    Hash = (Hash * 31 + K2) % 4294967296;
    Hash = (Hash * 31 + K3) % 4294967296;
    Hash = (Hash * 31 + #Record) % 4294967296;
    for I = 1, #Record do Hash = (Hash * 31 + Byte(Record, I, I)) % 4294967296; end;
    return Hash;
end;

local function BeginInstructionState(CurrentChunkState, EntryState, BlockStart, BlockTag, K1, K2, K3)
    local Value = (U32Mul(CurrentChunkState, 22695477) + U32Mul(EntryState, 1664525)
        + BlockStart * 65537 + BlockTag + K1 * 251 + K2 * 17 + K3
        + __IB2_DOMAIN_INSTRUCTION_STATE__ + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 1664525) + 1013904223) % 4294967296;
end;

local function AdvanceInstructionState(State, Digest, Index, CurrentChunkState, EntryState)
    local Value = (U32Mul(State, 1664525) + Digest + Index * 65537
        + U32Mul(CurrentChunkState, 257) + EntryState
        + __IB2_DOMAIN_INSTRUCTION_STATE__ + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 22695477) + 1) % 4294967296;
end;

local function InstructionStateSeal(State, Index, CurrentChunkState, EntryState, BlockTag)
    local Value = (U32Mul(State, 22695477) + Index * 257 + CurrentChunkState
        + U32Mul(EntryState, 1664525) + BlockTag
        + __IB2_DOMAIN_INSTRUCTION_STATE__ + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 1664525) + 1013904223) % 4294967296;
end;

local function BeginOpcodeState(CurrentChunkState, EntryState, BlockStart, K1, K2, K3)
    local Value = (U32Mul(CurrentChunkState, 22695477) + U32Mul(EntryState, 1664525)
        + BlockStart * 65537 + K1 * 251 + K2 * 17 + K3
        + __IB2_DOMAIN_OPCODE_STATE__ + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 1664525) + 1013904223) % 4294967296;
end;

local function AdvanceOpcodeState(State, Digest, Index, CurrentChunkState, EntryState)
    local Value = (U32Mul(State, 1664525) + Digest + Index * 257
        + CurrentChunkState * 17 + EntryState + __IB2_DOMAIN_OPCODE_STATE__ + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 22695477) + 1) % 4294967296;
end;

local function OpcodeStateKey(State, Index)
    local Low = State % 65536;
    local High = (State - Low) / 65536;
    return (Low * ((Index % 251) + 1) + High * 17 + (__IB2_DOMAIN_OPCODE_STATE__ % 65536)) % 65536;
end;

local function OpcodeStateSeal(State, Index, CurrentChunkState, EntryState, BlockTag)
    local Value = (U32Mul(State, 22695477) + Index * 65537 + CurrentChunkState
        + U32Mul(EntryState, 1664525) + BlockTag + __IB2_DOMAIN_OPCODE_STATE__ + PayloadAttestation) % 4294967296;
    return (U32Mul(Value, 1664525) + 1013904223) % 4294967296;
end;

local function BeginPrototypeIntegrity(Length, K1, K2, K3)
    local Keyed = (K1 * 65537 + K2 * 257 + K3) % 4294967296;
    local Hash = (BitXOR(Keyed, __IB2_DOMAIN_PROTOTYPE_INTEGRITY__) * 31 + Length) % 4294967296;
    local Words = {K1, K2, K3};
    for WordIndex = 1, 3 do
        local Word = Words[WordIndex];
        Hash = (Hash * 31 + Word % 256) % 4294967296;
        Hash = (Hash * 31 + (Word - Word % 256) / 256) % 4294967296;
    end;
    ActivePrototypeHash = Hash;
end;

local function ComputeBlockIntegrity(Body, EntryState, BlockStart, Count, RouteToken, References, Verifier, SuccessorRecords, K1, K2, K3)
    local Hash = (BitXOR(BitXOR(EntryState, __IB2_DOMAIN_BLOCK_INTEGRITY__), OuterSeed) * 31 + BlockStart) % 4294967296;
    Hash = (Hash * 31 + Count) % 4294967296;
    Hash = (Hash * 31 + K1) % 4294967296;
    Hash = (Hash * 31 + K2) % 4294967296;
    Hash = (Hash * 31 + K3) % 4294967296;
    Hash = (Hash * 31 + RouteToken) % 4294967296;
    Hash = (Hash * 31 + #References) % 4294967296;
    for ReferenceIndex = 1, #References do
        Hash = (Hash * 31 + References[ReferenceIndex]) % 4294967296;
    end;
    Hash = (Hash * 31 + Verifier) % 4294967296;
    Hash = (Hash * 31 + #SuccessorRecords) % 4294967296;
    for SuccessorIndex = 1, #SuccessorRecords do
        local SuccessorRecord = SuccessorRecords[SuccessorIndex];
        Hash = (Hash * 31 + SuccessorRecord[1]) % 4294967296;
        Hash = (Hash * 31 + SuccessorRecord[2]) % 4294967296;
        Hash = (Hash * 31 + SuccessorRecord[3]) % 4294967296;
    end;
    Hash = (Hash * 31 + #Body) % 4294967296;
    for I = 1, #Body do Hash = (Hash * 31 + Byte(Body, I, I)) % 4294967296; end;
    return Hash;
end;

local gInt = gBits32;
local function _R(...) return {...}, Select('#', ...) end

-- 与 C# serializer 相同的 prototype-local Fisher-Yates。
-- 不同 domain 分离字段 schema 与常量类型 tag。
local function DerivePermutation(Count, K1, K2, K3, Domain)
    local Values = {};
    for I = 1, Count do Values[I] = I - 1; end;
    local State = (K1 * 251 + K2 * 17 + K3 + Domain) % 65536;
    for I = Count, 2, -1 do
        State = (State * 251 + K3 + I * K1 + K2 + Domain) % 65536;
        local J = (State % I) + 1;
        Values[I], Values[J] = Values[J], Values[I];
    end;
    return Values;
end;

-- Block-local column role permutation. Values[physical page] is the zero-based
-- logical descriptor/opcode/A/B/C role stored in that framed page.
local function DeriveBlockPermutation(Count, EntryState, K1, K2, K3, Domain)
    local Values = {};
    for I = 1, Count do Values[I] = I - 1; end;
    local Low = EntryState % 65536;
    local High = (EntryState - Low) / 65536;
    local State = (Low * 251 + High * 17 + K1 * 13 + K2 * 7 + K3 + Domain) % 65536;
    for I = Count, 2, -1 do
        State = (State * 251 + K3 + I * (K1 + Low) + K2 + High + Domain) % 65536;
        local J = (State % I) + 1;
        Values[I], Values[J] = Values[J], Values[I];
    end;
    local Identity = true;
    for I = 1, Count do if Values[I] ~= I - 1 then Identity = false; break; end; end;
    if Identity and Count > 1 then Values[1], Values[2] = Values[2], Values[1]; end;
    return Values;
end;

local function DeriveCodeDataPermutation(InstructionCount, ConstantCount, StateValue, K1, K2, K3, Domain)
    local Values = DeriveBlockPermutation(InstructionCount + ConstantCount, StateValue, K1, K2, K3, Domain);
    if InstructionCount == 0 or ConstantCount == 0 or #Values <= 2 then return Values; end;
    local SawData = Values[1] >= InstructionCount;
    local Interleaved = 0;
    local TargetSlot = 0;
    for PhysicalSlot = 2, #Values do
        local StateValue = Values[PhysicalSlot] >= InstructionCount;
        if StateValue ~= SawData then
            Interleaved = Interleaved + 1;
            if TargetSlot == 0 then TargetSlot = PhysicalSlot; end;
        end;
        SawData = StateValue;
    end;
    if Interleaved < 2 then
        Values[TargetSlot - 1], Values[TargetSlot] = Values[TargetSlot], Values[TargetSlot - 1];
    end;
    return Values;
end;

local function Deserialize()
    local PrototypeLength = ActiveSourceLength;
    ActivePrototypeHash = nil;
    local Instrs = {};
    local Functions = {};
		local Lines = {};
    local Chunk = {};
    Chunk[1] = Instrs;
    Chunk[2] = Functions;
    Chunk[4] = Lines;
    local K1 = gBits16();
    local K2 = gBits16();
    local K3 = gBits16();
    local PrototypeTag = gBits32();
    BeginPrototypeIntegrity(PrototypeLength, K1, K2, K3);
    Chunk[5], Chunk[6], Chunk[7] = K1, K2, K3;
    local OpcodeBank = DerivePermutation(__IB2_OPCODE_COUNT__, K1, K2, K3, __IB2_DOMAIN_OPCODE_PERMUTATION__);
    Chunk[8] = OpcodeBank;
    local ConstCount = 0;
    Chunk[15] = ConstCount;
    local InstrCount = 0;
    local Blocks = {};
    local BlockMap = {};
    local BlockCount = 0;
    local Dispatcher = {};
    local RouteCount = 0;
    local InitialRouteToken = 0;
    Chunk[9], Chunk[10] = Blocks, BlockMap;
";
		
		public static string VMP2 = @"
local function Wrap(Chunk, Upvalues, Env)
	local Instr  = Chunk[1];
	local Proto  = Chunk[2];
	local Params = Chunk[3];
	local K1 = Chunk[5];
	local K2 = Chunk[6];
	local K3 = Chunk[7];
	local OpcodeBank = Chunk[8];

	return function(...)
		local Instr  = Instr; 
		local Proto  = Proto; 
		local Params = Params;

		local _R = _R
		local InstrPoint = Chunk[14] or 1;
		local Flow = {};
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
					__IB2_GUARD_CHECK__
					InstrPoint = ResolveInstructionPoint(Chunk, InstrPoint, Flow);
			Inst, Enum	= GetInstruction(Chunk, InstrPoint, Flow, true);
			if Enum == nil then
				Enum = OpcodeBank[BitXOR(BitXOR(Inst[OP_ENUM], OpcodeKey(InstrPoint, K1, K2, K3)), BlockFieldKey(Flow[3], InstrPoint, 0, K1, K2, K3)) + 1];
			end;";

		public static string VMP2_R = @"
local function Wrap(Chunk, Upvalues, Env)
	local Instr  = Chunk[1];
	local Proto  = Chunk[2];
	local Params = Chunk[3];
	local K1 = Chunk[5];
	local K2 = Chunk[6];
	local K3 = Chunk[7];
	local OpcodeBank = Chunk[8];

	return function(...)
		local Instr  = Instr; 
		local Proto  = Proto; 
		local Params = Params;

		local _R = _R
		local InstrPoint = Chunk[14] or 1;
		local Flow = {};
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
					__IB2_GUARD_CHECK__
					InstrPoint = ResolveInstructionPoint(Chunk, InstrPoint, Flow);
			Inst, Enum	= GetInstruction(Chunk, InstrPoint, Flow, true);
			if Enum == nil then
				Enum = OpcodeBank[BitXOR(BitXOR(Inst[OP_ENUM], OpcodeKey(InstrPoint, K1, K2, K3)), BlockFieldKey(Flow[3], InstrPoint, 0, K1, K2, K3)) + 1];
			end;";

		public static string VMP3 = @"
			InstrPoint	= InstrPoint + 1;
			InstrPoint = NextInstructionPoint(Chunk, InstrPoint, Flow);
		end;
    end;
end;	
local Root = Deserialize();
ByteString, PayloadPage, PayloadPageDescriptors, PayloadCiphertext, PayloadByteAt, PayloadLength = nil, nil, nil, nil, nil, nil;
return Wrap(Root, {}, GetFEnv());
end)()(...);
";
		public static string VMP3_R = @"
			InstrPoint	= InstrPoint + 1;
			InstrPoint = NextInstructionPoint(Chunk, InstrPoint, Flow);
		until false;
    end;
end;	
local Root = Deserialize();
ByteString, PayloadPage, PayloadPageDescriptors, PayloadCiphertext, PayloadByteAt, PayloadLength = nil, nil, nil, nil, nil, nil;
return Wrap(Root, {}, GetFEnv());
end)()(...);
";
		public static string VMP2_LI = @"
local function Wrap(Chunk, Upvalues, Env)
	local Instr = Chunk[1];
	local Proto = Chunk[2];
	local Params = Chunk[3];
	local K1 = Chunk[5];
	local K2 = Chunk[6];
	local K3 = Chunk[7];
	local OpcodeBank = Chunk[8];

	return function(...)
		local InstrPoint = Chunk[14] or 1;
		local Flow = {};
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
				__IB2_GUARD_CHECK__
				InstrPoint = ResolveInstructionPoint(Chunk, InstrPoint, Flow);
				Inst, Enum	= GetInstruction(Chunk, InstrPoint, Flow, true);
				if Enum == nil then
					Enum = OpcodeBank[BitXOR(BitXOR(Inst[OP_ENUM], OpcodeKey(InstrPoint, K1, K2, K3)), BlockFieldKey(Flow[3], InstrPoint, 0, K1, K2, K3)) + 1];
				end;";
		
		public static string VMP2_LI_R = @"
local function Wrap(Chunk, Upvalues, Env)
	local Instr = Chunk[1];
	local Proto = Chunk[2];
	local Params = Chunk[3];
	local K1 = Chunk[5];
	local K2 = Chunk[6];
	local K3 = Chunk[7];
	local OpcodeBank = Chunk[8];

	return function(...)
		local InstrPoint = Chunk[14] or 1;
		local Flow = {};
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
				__IB2_GUARD_CHECK__
				InstrPoint = ResolveInstructionPoint(Chunk, InstrPoint, Flow);
				Inst, Enum	= GetInstruction(Chunk, InstrPoint, Flow, true);
				if Enum == nil then
					Enum = OpcodeBank[BitXOR(BitXOR(Inst[OP_ENUM], OpcodeKey(InstrPoint, K1, K2, K3)), BlockFieldKey(Flow[3], InstrPoint, 0, K1, K2, K3)) + 1];
				end;";
		
		public static string VMP3_LI = @"
				InstrPoint	= InstrPoint + 1;
				InstrPoint = NextInstructionPoint(Chunk, InstrPoint, Flow);
			end;
		end;

		local A, B = _R(PCall(Loop))
		if not A[1] then
			local line = Chunk[4][InstrPoint] or '?'
			error('ERROR IN IRONBREW SCRIPT [LINE ' .. line .. ']:' .. A[2])
		else
			return Unpack(A, 2, B)
		end;
	end;
end;	
local Root = Deserialize();
ByteString, PayloadPage, PayloadPageDescriptors, PayloadCiphertext, PayloadByteAt, PayloadLength = nil, nil, nil, nil, nil, nil;
return Wrap(Root, {}, GetFEnv());
end)()(...);
";
		public static string VMP3_LI_R = @"
				InstrPoint	= InstrPoint + 1;
				InstrPoint = NextInstructionPoint(Chunk, InstrPoint, Flow);
			until false;
		end;

		local A, B = _R(PCall(Loop))
		if not A[1] then
			local line = Chunk[4][InstrPoint] or '?'
			error('ERROR IN IRONBREW SCRIPT [LINE ' .. line .. ']:' .. A[2])
		else
			return Unpack(A, 2, B)
		end;
	end;
end;	
local Root = Deserialize();
ByteString, PayloadPage, PayloadPageDescriptors, PayloadCiphertext, PayloadByteAt, PayloadLength = nil, nil, nil, nil, nil, nil;
return Wrap(Root, {}, GetFEnv());
end)()(...);
";
	}
}