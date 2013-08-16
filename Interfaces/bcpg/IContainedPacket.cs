namespace Org.BouncyCastle.Bcpg
{
    public interface IContainedPacket
    {
        byte[] GetEncoded();
        void Encode(IBcpgOutputStream bcpgOut);
    }
}