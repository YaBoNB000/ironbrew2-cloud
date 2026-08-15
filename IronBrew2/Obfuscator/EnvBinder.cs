using System;
using System.Security.Cryptography;
using System.Text;

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
        public uint Salt { get; private set; }
        public uint AttestationToken { get; private set; }
        public string SeedDeriveLua { get; private set; }

        /// <summary>EnvironmentLock-disabled compatibility path for library callers.</summary>
        public const string PlainSeedLua = "local Xs = PayloadHead;";

        public EnvBinder()
        {
            Salt = NextNonZeroUInt32();
            do
            {
                AttestationToken = NextNonZeroUInt32();
            } while (DeriveSeed(AttestationToken) == 0);

            SeedDeriveLua = @"
local SeedText = ToString(PayloadHead) .. Char(124) .. ToString(GuardAttestation);
local Xs = 0;
for SeedIndex = 1, #SeedText do
    Xs = (Xs * 31 + Byte(SeedText, SeedIndex)) % 4294967296;
end;
";
        }

        private static uint NextNonZeroUInt32()
        {
            uint value;
            do
            {
                value = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(sizeof(uint)), 0);
            } while (value == 0);
            return value;
        }

        public static uint Hash(string value)
        {
            uint hash = 0;
            foreach (byte item in Encoding.UTF8.GetBytes(value))
                hash = unchecked(hash * 31u + item);
            return hash;
        }

        public uint DeriveSeed(uint attestationToken) =>
            Hash(Salt.ToString() + "|" + attestationToken.ToString());
    }
}
