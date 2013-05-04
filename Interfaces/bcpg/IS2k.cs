namespace Org.BouncyCastle.Bcpg
{
    public interface IS2k : IBcpgObject
    {
        int Type { get; }

        /// <summary>The hash algorithm.</summary>
        HashAlgorithmTag HashAlgorithm { get; }

        /// <summary>The iteration count</summary>
        long IterationCount { get; }

        /// <summary>The protection mode - only if GnuDummyS2K</summary>
        int ProtectionMode { get; }

        /// <summary>The IV for the key generation algorithm.</summary>
        byte[] GetIV();
    }
}