using System;
using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public interface IUserAttributeSubpacket
    {
        UserAttributeSubpacketTag SubpacketType { get; }

        [Obsolete("Use Data property")]
        byte[] GetData();

        byte[] Data { get; }

        void Encode(Stream os);

        bool Equals(object obj);

        int GetHashCode();
    }
}