namespace Org.BouncyCastle.Bcpg
{
    /// <summary>
    /// Basic packet for a PGP secret subkey.
    /// </summary>
    public class SecretSubkeyPacket : SecretKeyPacket
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SecretSubkeyPacket"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        internal SecretSubkeyPacket(BcpgInputStream bcpgIn)
            : base(bcpgIn)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretSubkeyPacket"/> class.
        /// </summary>
        /// <param name="pubKeyPacket">The pub key packet.</param>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="s2K">The s2 K.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, S2k s2K, byte[] iv, byte[] secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2K, iv, secKeyData)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretSubkeyPacket"/> class.
        /// </summary>
        /// <param name="pubKeyPacket">The pub key packet.</param>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="s2KUsage">The s2 K usage.</param>
        /// <param name="s2K">The s2 K.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SecretSubkeyPacket(PublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, int s2KUsage, S2k s2K, byte[] iv, byte[] secKeyData)
            : base(pubKeyPacket, encAlgorithm, s2KUsage, s2K, iv, secKeyData)
        {
        }

        /// <summary>
        /// Encodes this instance to the given stream.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.SecretSubkey, GetEncodedContents(), true);
        }
    }
}
