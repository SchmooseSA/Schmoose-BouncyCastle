using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    public interface ISignatureSubpacket
    {
        SignatureSubpacketTag SubpacketType { get; }

        bool IsCritical();

        /// <summary>Return the generic data making up the packet.</summary>
        byte[] GetData();

        void Encode(Stream os);
    }
}