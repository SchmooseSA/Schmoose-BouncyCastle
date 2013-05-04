using System.IO;

using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP secret key.</remarks>
    public class SecretKeyPacket : ContainedPacket, ISecretKeyPacket //, PublicKeyAlgorithmTag
    {
        public const int UsageNone = 0x00;
        public const int UsageChecksum = 0xff;
        public const int UsageSha1 = 0xfe;

        private readonly byte[] _secKeyData;
        private readonly byte[] _iv;

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretKeyPacket"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        internal SecretKeyPacket(BcpgInputStream bcpgIn)
        {
            if (this is SecretSubkeyPacket)
            {
                this.PublicKeyPacket = new PublicSubkeyPacket(bcpgIn);
            }
            else
            {
                this.PublicKeyPacket = new PublicKeyPacket(bcpgIn);
            }

            this.S2KUsage = bcpgIn.ReadByte();

            if (this.S2KUsage == UsageChecksum || this.S2KUsage == UsageSha1)
            {
                this.EncAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.ReadByte();
                this.S2K = new S2k(bcpgIn);
            }
            else
            {
                this.EncAlgorithm = (SymmetricKeyAlgorithmTag)this.S2KUsage;
            }

            if (!(this.S2K != null && this.S2K.Type == S2k.GnuDummyS2K && this.S2K.ProtectionMode == 0x01))
            {
                if (this.S2KUsage != 0)
                {
                    _iv = ((int)EncAlgorithm) < 7 ? new byte[8] : new byte[16];
                    bcpgIn.ReadFully(_iv);
                }
            }

            _secKeyData = bcpgIn.ReadAll();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretKeyPacket"/> class.
        /// </summary>
        /// <param name="pubKeyPacket">The pub key packet.</param>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="s2K">The s2 K.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SecretKeyPacket(IPublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, S2k s2K, byte[] iv, byte[] secKeyData)
        {
            this.PublicKeyPacket = pubKeyPacket;
            this.EncAlgorithm = encAlgorithm;

            this.S2KUsage = encAlgorithm != SymmetricKeyAlgorithmTag.Null ? UsageChecksum : UsageNone;

            this.S2K = s2K;
            _iv = Arrays.Clone(iv);
            _secKeyData = secKeyData;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SecretKeyPacket"/> class.
        /// </summary>
        /// <param name="pubKeyPacket">The pub key packet.</param>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="s2KUsage">The s2 K usage.</param>
        /// <param name="s2K">The s2 K.</param>
        /// <param name="iv">The iv.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SecretKeyPacket(IPublicKeyPacket pubKeyPacket, SymmetricKeyAlgorithmTag encAlgorithm, int s2KUsage, S2k s2K, byte[] iv, byte[] secKeyData)
        {
            this.PublicKeyPacket = pubKeyPacket;
            this.EncAlgorithm = encAlgorithm;
            this.S2KUsage = s2KUsage;
            this.S2K = s2K;
            _iv = Arrays.Clone(iv);
            _secKeyData = secKeyData;
        }

        /// <summary>
        /// Gets the enc algorithm.
        /// </summary>
        /// <value>
        /// The enc algorithm.
        /// </value>
        public SymmetricKeyAlgorithmTag EncAlgorithm { get; private set; }

        /// <summary>
        /// Gets the s2 K usage.
        /// </summary>
        /// <value>
        /// The s2 K usage.
        /// </value>
        public int S2KUsage { get; private set; }

        /// <summary>
        /// Gets the IV.
        /// </summary>
        /// <returns></returns>
        public byte[] GetIV()
        {
            return Arrays.Clone(_iv);
        }

        /// <summary>
        /// Gets the s2 K.
        /// </summary>
        /// <value>
        /// The s2 K.
        /// </value>
        public IS2k S2K { get; private set; }

        /// <summary>
        /// Gets the public key packet.
        /// </summary>
        /// <value>
        /// The public key packet.
        /// </value>
        public IPublicKeyPacket PublicKeyPacket { get; private set; }

        /// <summary>
        /// Gets the secret key data.
        /// </summary>
        /// <returns></returns>
        public byte[] GetSecretKeyData()
        {
            return _secKeyData;
        }

        /// <summary>
        /// Gets the encoded contents.
        /// </summary>
        /// <returns></returns>
        public byte[] GetEncodedContents()
        {
            using (var bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {
                    pOut.Write(PublicKeyPacket.GetEncodedContents());
                    pOut.WriteByte((byte) this.S2KUsage);

                    if (this.S2KUsage == UsageChecksum || this.S2KUsage == UsageSha1)
                    {
                        pOut.WriteByte((byte)this.EncAlgorithm);
                        pOut.WriteObject(this.S2K);
                    }

                    if (_iv != null)
                    {
                        pOut.Write(_iv);
                    }

                    if (_secKeyData != null && _secKeyData.Length > 0)
                    {
                        pOut.Write(_secKeyData);
                    }

                    return bOut.ToArray();
                }
            }
        }

        /// <summary>
        /// Encodes this instance to the given stream.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.SecretKey, this.GetEncodedContents(), true);
        }
    }
}
