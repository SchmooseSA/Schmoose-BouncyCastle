using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg
{
    public interface IBcpgOutputStream : IBaseOutputStream
    {
        void WritePacket(
            IContainedPacket p);

        void WriteObject(
            IBcpgObject bcpgObject);

        void WriteObjects(
            params IBcpgObject[] v);

        /// <summary>Finish writing out the current packet without closing the underlying stream.</summary>
        void Finish();

        void WritePacket(
            PacketTag	tag,
            byte[]		body,
            bool		oldFormat);

        void WriteShort(
            short n);

        void WriteInt(
            int n);

        void WriteLong(
            long n);
    }
}