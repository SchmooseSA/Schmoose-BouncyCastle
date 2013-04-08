using System.IO;

namespace Org.BouncyCastle.Bcpg
{
    /**
    * Basic type for a symmetric encrypted session key packet
    */
    public class SymmetricKeyEncSessionPacket : ContainedPacket
    {
        private readonly byte[] _secKeyData;

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyEncSessionPacket"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        public SymmetricKeyEncSessionPacket(BcpgInputStream bcpgIn)
        {
            Version = bcpgIn.ReadByte();
            EncAlgorithm = (SymmetricKeyAlgorithmTag)bcpgIn.ReadByte();

            S2K = new S2k(bcpgIn);

            _secKeyData = bcpgIn.ReadAll();
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SymmetricKeyEncSessionPacket"/> class.
        /// </summary>
        /// <param name="encAlgorithm">The enc algorithm.</param>
        /// <param name="s2k">The S2K.</param>
        /// <param name="secKeyData">The sec key data.</param>
        public SymmetricKeyEncSessionPacket(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2k, byte[] secKeyData)
        {
            this.Version = 4;
            this.EncAlgorithm = encAlgorithm;
            this.S2K = s2k;
            this._secKeyData = secKeyData;
        }

        /// <summary>
        /// Gets the enc algorithm.
        /// </summary>
        /// <value>
        /// The enc algorithm.
        /// </value>
        public SymmetricKeyAlgorithmTag EncAlgorithm { get; private set; }

        /// <summary>
        /// Gets the s2 K.
        /// </summary>
        /// <value>
        /// The s2 K.
        /// </value>
        public S2k S2K { get; private set; }

        /// <summary>
        /// Gets the sec key data.
        /// </summary>
        /// <returns></returns>
        public byte[] GetSecKeyData()
        {
            return _secKeyData;
        }

        /// <summary>
        /// Gets the version.
        /// </summary>
        /// <value>
        /// The version.
        /// </value>
        public int Version { get; private set; }

        /// <summary>
        /// Encodes this instance to the given stream.
        /// </summary>
        /// <param name="bcpgOut">The BCPG out.</param>
        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            using (var bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {

                    pOut.Write(
                        (byte)Version,
                        (byte)EncAlgorithm);

                    pOut.WriteObject(S2K);

                    if (_secKeyData != null && _secKeyData.Length > 0)
                    {
                        pOut.Write(_secKeyData);
                    }

                    bcpgOut.WritePacket(PacketTag.SymmetricKeyEncryptedSessionKey, bOut.ToArray(), true);
                }
            }
        }
    }
}
