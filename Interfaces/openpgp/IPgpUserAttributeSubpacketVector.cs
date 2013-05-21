using System.Collections.Generic;
using Org.BouncyCastle.Bcpg.Attr;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpUserAttributeSubpacketVector
    {
        IUserAttributeSubpacket GetSubpacket(UserAttributeSubpacketTag type);

        IEnumerable<IUserAttributeSubpacket> GetSubpackets(UserAttributeSubpacketTag type);

        IImageAttribute GetImageAttribute();

        bool Equals(object obj);

        int GetHashCode();

        IUserAttributeSubpacket[] ToSubpacketArray();
    }
}