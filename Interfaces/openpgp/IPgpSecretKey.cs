using System.Collections;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpSecretKey
    {
        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for use with signing.
        /// </returns>
        bool IsSigningKey { get; }

        /// <summary>True, if this is a master key.</summary>
        bool IsMasterKey { get; }

        /// <summary>The algorithm the key is encrypted with.</summary>
        SymmetricKeyAlgorithmTag KeyEncryptionAlgorithm { get; }

        /// <summary>The key ID of the public key associated with this key.</summary>
        long KeyId { get; }

        /// <summary>The public key associated with this key.</summary>
        IPgpPublicKey PublicKey { get; }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        IEnumerable UserIds { get; }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        IEnumerable UserAttributes { get; }

        /// <summary>Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.</summary>
        IPgpPrivateKey ExtractPrivateKey(
            char[] passPhrase);

        byte[] GetEncoded();

        void Encode(
            Stream outStr);
    }
}