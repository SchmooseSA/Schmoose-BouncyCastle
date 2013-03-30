namespace Org.BouncyCastle.Bcpg
{
    public interface IBcpgObject
    {
        byte[] GetEncoded();
        void Encode(IBcpgOutputStream bcpgOut);
    }
}