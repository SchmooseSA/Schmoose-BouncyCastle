using System.Collections;
using System.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    public interface IPgpSecretKey
    {
        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance is signing key; otherwise, <c>false</c>.
        /// </value>
        /// <returns>
        ///   <c>true</c> if this key algorithm is suitable for use with signing.
        ///   </returns>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        bool IsSigningKey { get; }

        /// <summary>
        /// True, if this is a master key.
        /// </summary>
        /// <value>
        /// <c>true</c> if this instance is master key; otherwise, <c>false</c>.
        /// </value>
        bool IsMasterKey { get; }

        /// <summary>
        /// The algorithm the key is encrypted with.
        /// </summary>
        /// <value>
        /// The key encryption algorithm.
        /// </value>
        SymmetricKeyAlgorithmTag KeyEncryptionAlgorithm { get; }

        /// <summary>
        /// The key ID of the public key associated with this key.
        /// </summary>
        /// <value>
        /// The key id.
        /// </value>
        long KeyId { get; }

        /// <summary>
        /// The public key associated with this key.
        /// </summary>
        /// <value>
        /// The public key.
        /// </value>
        IPgpPublicKey PublicKey { get; }

        /// <summary>
        /// Gets the secret key packet.
        /// </summary>
        /// <value>
        /// The secret key packet.
        /// </value>
        ISecretKeyPacket SecretPacket { get; }

        /// <summary>
        /// Allows enumeration of any user IDs associated with the key.
        /// </summary>
        /// <value>
        /// The user ids.
        /// </value>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        IEnumerable UserIds { get; }

        /// <summary>
        /// Allows enumeration of any user attribute vectors associated with the key.
        /// </summary>
        /// <value>
        /// The user attributes.
        /// </value>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        IEnumerable UserAttributes { get; }

        /// <summary>
        /// Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.
        /// </summary>
        /// <param name="passPhrase">The pass phrase.</param>
        /// <returns></returns>
        IPgpPrivateKey ExtractPrivateKey(char[] passPhrase);

        /// <summary>
        /// Extracts the key data.
        /// </summary>
        /// <param name="passPhrase">The pass phrase.</param>
        /// <returns></returns>
        byte[] ExtractKeyData(char[] passPhrase);

        /// <summary>
        /// Gets the encoded version of this key.
        /// </summary>
        /// <returns></returns>
        byte[] GetEncoded();

        /// <summary>
        /// Encodes this key to the stream.
        /// </summary>
        /// <param name="outStr">The out STR.</param>
        void Encode(Stream outStr);
    }
}