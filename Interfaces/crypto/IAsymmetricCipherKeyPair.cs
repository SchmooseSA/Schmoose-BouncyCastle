namespace Org.BouncyCastle.Crypto
{
    public interface IAsymmetricCipherKeyPair
    {
        IAsymmetricKeyParameter Public { get; }
        IAsymmetricKeyParameter Private { get; }
    }
}