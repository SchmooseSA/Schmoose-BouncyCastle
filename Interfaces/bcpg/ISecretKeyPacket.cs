namespace Org.BouncyCastle.Bcpg
{
    public interface ISecretKeyPacket
    {
        /// <summary>
        /// Gets the enc algorithm.
        /// </summary>
        /// <value>
        /// The enc algorithm.
        /// </value>
        SymmetricKeyAlgorithmTag EncAlgorithm { get; }

        /// <summary>
        /// Gets the s2 K usage.
        /// </summary>
        /// <value>
        /// The s2 K usage.
        /// </value>
        int S2KUsage { get; }

        /// <summary>
        /// Gets the s2 K.
        /// </summary>
        /// <value>
        /// The s2 K.
        /// </value>
        IS2k S2K { get; }

        /// <summary>
        /// Gets the public key packet.
        /// </summary>
        /// <value>
        /// The public key packet.
        /// </value>
        IPublicKeyPacket PublicKeyPacket { get; }

        /// <summary>
        /// Gets the IV.
        /// </summary>
        /// <returns></returns>
        byte[] GetIV();

        /// <summary>
        /// Gets the secret key data.
        /// </summary>
        /// <returns></returns>
        byte[] GetSecretKeyData();

        /// <summary>
        /// Gets the encoded contents.
        /// </summary>
        /// <returns></returns>
        byte[] GetEncodedContents();

        /// <summary>
        /// Encodes this instance to the given stream.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        void Encode(IBcpgOutputStream bcpgOut);

        /// <summary>
        /// Gets the encoded version of this instance.
        /// </summary>
        /// <returns></returns>
        byte[] GetEncoded();
    }
}