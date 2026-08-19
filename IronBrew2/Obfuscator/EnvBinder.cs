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
        public string SeedDeriveLua { get; private set; }

        /// <summary>EnvironmentLock-disabled compatibility path for library callers.</summary>
        public const string PlainSeedLua = "local Xs = PayloadHead; local Xi = Xs;";

        public EnvBinder(BuildRandom random, PayloadDerivationProfile profile)
        {
            if (random == null) throw new ArgumentNullException(nameof(random));
            _profile = profile ?? throw new ArgumentNullException(nameof(profile));
            Salt = NextNonZeroUInt32(random);
            do
            {
                AttestationToken = NextNonZeroUInt32(random);
            } while (DeriveSeed(AttestationToken) == 0);

            SeedDeriveLua = $@"
local SeedText = ToString(PayloadHead) .. Char(124) .. ToString(GuardAttestation);
local SeedMix = {_profile.BinderInitial};
for SeedIndex = 1, #SeedText do
    SeedMix = (SeedMix * {_profile.BinderMultiplier} + Byte(SeedText, SeedIndex) + {_profile.BinderIncrement}) % 4294967296;
end;
local Xs = BitXOR(SeedMix, {_profile.BinderFinalXor}) % 4294967296;
local OuterIntegrityText = ToString(GuardAttestation) .. Char(35) .. ToString(PayloadHead);
local OuterIntegrityState = BitXOR({_profile.BinderInitial}, 2781082087) % 4294967296;
for OuterIntegrityIndex = 1, #OuterIntegrityText do
    OuterIntegrityState = (OuterIntegrityState * {_profile.BinderMultiplier} + Byte(OuterIntegrityText, OuterIntegrityIndex)
        + {_profile.BinderIncrement} + OuterIntegrityIndex * 257) % 4294967296;
end;
local Xi = BitXOR(BitXOR(OuterIntegrityState, {_profile.BinderFinalXor}), 3302136427) % 4294967296;
if Xi == 0 then Xi = 3302136427; end;
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
    }
}
