using Org.BouncyCastle.Crypto;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpPrivateKey
    {
        /// <summary>The keyId associated with the contained private key.</summary>
        long KeyId { get; }

        /// <summary>The contained private key.</summary>
        IAsymmetricKeyParameter Key { get; }
    }
}