using System;

namespace Org.BouncyCastle.Bcpg
{
    public interface IPublicKeyPacket : IContainedPacket
    {
        int Version { get; }
        PublicKeyAlgorithmTag Algorithm { get; }
        int ValidDays { get; }
        IBcpgKey Key { get; }
        DateTime GetTime();
        byte[] GetEncodedContents();
    }
}