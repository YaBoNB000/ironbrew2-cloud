using System;

namespace IronBrew2.Obfuscator
{
    /// <summary>
    /// Couples the serialized payload seed to the VM-integrated executor attestation.
    /// The strict guard produces AttestationToken only after every required Roblox,
    /// executor, closure and debug-behavior challenge succeeds. A missing or forged
    /// environment therefore cannot derive the serializer's stream seed merely from
    /// the four-byte payload header.
    ///
    /// This remains a client-side cost amplifier, not a remote trust root: the token,
    /// probes and derivation code are all delivered to the client and can be patched by
    /// a sufficiently capable analyst.
    /// </summary>
    public class EnvBinder
    {
        private readonly PayloadDerivationProfile _profile;

        public uint Salt { get; private set; }
        public uint AttestationToken { get; private set; }
        public uint PayloadBinding { get; private set; }
        public string SeedDeriveLua { get; private set; }

        /// <summary>EnvironmentLock-disabled compatibility path for library callers.</summary>
        public const string PlainSeedLua = "local Xs = PayloadHead; local Xi = Xs; local GuardPayloadBinding = Xs;";

        public EnvBinder(BuildRandom random, PayloadDerivationProfile profile)
        {
            if (random == null) throw new ArgumentNullException(nameof(random));
            _profile = profile ?? throw new ArgumentNullException(nameof(profile));
            Salt = NextNonZeroUInt32(random);
            do
            {
                AttestationToken = NextNonZeroUInt32(random);
            } while (DeriveSeed(AttestationToken) == 0);
            PayloadBinding = _profile.DerivePayloadBinding(Salt, AttestationToken);

            SeedDeriveLua = $@"
local SeedText = ToString(PayloadHead) .. Char(124) .. ToString(GuardAttestation);
local GuardKeyA = {_profile.BinderInitial};
local GuardKeyB = BitXOR({_profile.BinderInitial}, 2781082087) % 4294967296;
local GuardKeyC = BitXOR({_profile.BinderFinalXor}, 1831565813) % 4294967296;
local GuardKeyD = BitXOR(BitXOR(PayloadHead, GuardAttestation), 2654435769) % 4294967296;
for SeedIndex = 1, #SeedText do
    local SeedByte = Byte(SeedText, SeedIndex);
    GuardKeyA = (GuardKeyA * {_profile.BinderMultiplier} + SeedByte + {_profile.BinderIncrement}) % 4294967296;
    GuardKeyB = (GuardKeyB * {_profile.BinderMultiplier + 2u} + SeedByte + {_profile.BinderIncrement} + SeedIndex * 17) % 4294967296;
    GuardKeyC = (GuardKeyC * 65599 + SeedByte + (GuardKeyA - GuardKeyA % 65536) / 65536) % 4294967296;
    GuardKeyD = (GuardKeyD * 48271 + SeedByte + GuardKeyB % 65536 + SeedIndex) % 4294967296;
end;
local function BinderRotate16(Value)
    local Low = Value % 65536;
    return (Low * 65536 + (Value - Low) / 65536) % 4294967296;
end;
local Xs = BitXOR(BitXOR(GuardKeyA, BinderRotate16(GuardKeyB)), BitXOR(GuardKeyC, GuardKeyD));
Xs = BitXOR(Xs, {_profile.BinderFinalXor}) % 4294967296;
local Xi = BitXOR(BitXOR(GuardKeyB, BinderRotate16(GuardKeyC)), GuardKeyD);
Xi = BitXOR(BitXOR(Xi, {_profile.BinderFinalXor}), 3302136427) % 4294967296;
if Xi == 0 then Xi = 3302136427; end;
local GuardPayloadBinding = (BitXOR(GuardKeyA, GuardKeyB) + BitXOR(GuardKeyC, GuardKeyD) + 3266489909) % 4294967296;
";
        }

        private static uint NextNonZeroUInt32(BuildRandom random)
        {
            uint value;
            do value = random.NextUInt32(); while (value == 0);
            return value;
        }

        public uint DeriveSeed(uint attestationToken) =>
            _profile.DeriveEnvironmentSeed(Salt, attestationToken);

        public uint DeriveIntegrityKey(uint attestationToken) =>
            _profile.DeriveOuterIntegrityKey(Salt, attestationToken);

        public uint DerivePayloadBinding(uint attestationToken) =>
            _profile.DerivePayloadBinding(Salt, attestationToken);
    }
}
