namespace Org.BouncyCastle.Crypto
{
    public interface IAsymmetricKeyParameter : ICipherParameters
    {
        bool IsPrivate { get; }

        bool Equals(
            object obj);

        int GetHashCode();
    }
}