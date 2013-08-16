using System;

namespace Org.BouncyCastle.Bcpg
{
    public interface IPublicKeyPacket : IContainedPacket
    {
        int Version { get; }
        PublicKeyAlgorithmTag Algorithm { get; }
        int ValidDays { get; }
        IBcpgPublicKey Key { get; }
        DateTime GetTime();
        byte[] GetEncodedContents();
    }
}