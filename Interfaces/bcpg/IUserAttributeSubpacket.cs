using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public interface IUserAttributeSubpacket
    {
        UserAttributeSubpacketTag SubpacketType { get; }
        byte[] GetData();

        void Encode(
            Stream os);

        bool Equals(
            object obj);

        int GetHashCode();
    }
}