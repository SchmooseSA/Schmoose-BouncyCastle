using Org.BouncyCastle.Bcpg.Attr;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpUserAttributeSubpacketVector
    {
        IUserAttributeSubpacket GetSubpacket(UserAttributeSubpacketTag type);

        IImageAttribute GetImageAttribute();

        bool Equals(object obj);

        int GetHashCode();

        IUserAttributeSubpacket[] ToSubpacketArray();
    }
}