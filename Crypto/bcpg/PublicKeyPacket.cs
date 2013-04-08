using System;
using System.IO;

using Org.BouncyCastle.Utilities.Date;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyPacket
        : ContainedPacket, IPublicKeyPacket //, PublicKeyAlgorithmTag
    {
        private readonly int _version;
        private readonly long _time;
        private readonly int _validDays;
        private readonly PublicKeyAlgorithmTag _algorithm;
        private readonly IBcpgKey _key;

        /// <summary>
        /// Initializes a new instance of the <see cref="PublicKeyPacket"/> class.
        /// </summary>
        /// <param name="bcpgIn">The BCPG in.</param>
        /// <exception cref="System.IO.IOException">unknown PGP public key algorithm encountered</exception>
        internal PublicKeyPacket(BcpgInputStream bcpgIn)
        {
            _version = bcpgIn.ReadByte();

            _time = ((uint)bcpgIn.ReadByte() << 24) | ((uint)bcpgIn.ReadByte() << 16)
                | ((uint)bcpgIn.ReadByte() << 8) | (uint)bcpgIn.ReadByte();

            if (_version <= 3)
            {
                _validDays = (bcpgIn.ReadByte() << 8) | bcpgIn.ReadByte();
            }

            _algorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();

            switch (_algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaSign:
                    _key = new RsaPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    _key = new DsaPublicBcpgKey(bcpgIn);
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    _key = new ElGamalPublicBcpgKey(bcpgIn);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        /// <summary>
        /// Construct a version 4 public key packet.
        /// </summary>
        /// <param name="algorithm">The algorithm.</param>
        /// <param name="time">The time.</param>
        /// <param name="key">The key.</param>
        public PublicKeyPacket(PublicKeyAlgorithmTag algorithm, DateTime time, IBcpgKey key)
        {
            _version = 4;
            _time = DateTimeUtilities.DateTimeToUnixMs(time) / 1000L;
            _algorithm = algorithm;
            _key = key;
        }

        /// <summary>
        /// Gets the version.
        /// </summary>
        /// <value>
        /// The version.
        /// </value>
        public int Version
        {
            get { return _version; }
        }

        /// <summary>
        /// Gets the algorithm.
        /// </summary>
        /// <value>
        /// The algorithm.
        /// </value>
        public PublicKeyAlgorithmTag Algorithm
        {
            get { return _algorithm; }
        }

        /// <summary>
        /// Gets the valid days.
        /// </summary>
        /// <value>
        /// The valid days.
        /// </value>
        public int ValidDays
        {
            get { return _validDays; }
        }

        /// <summary>
        /// Gets the time.
        /// </summary>
        /// <returns></returns>
        public DateTime GetTime()
        {
            return DateTimeUtilities.UnixMsToDateTime(_time * 1000L);
        }

        /// <summary>
        /// Gets the key.
        /// </summary>
        /// <value>
        /// The key.
        /// </value>
        public IBcpgKey Key
        {
            get { return _key; }
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

                    pOut.WriteByte((byte)_version);
                    pOut.WriteInt((int)_time);

                    if (_version <= 3)
                    {
                        pOut.WriteShort((short)_validDays);
                    }

                    pOut.WriteByte((byte)_algorithm);

                    pOut.WriteObject((BcpgObject)_key);

                    return bOut.ToArray();
                }
            }
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            bcpgOut.WritePacket(PacketTag.PublicKey, GetEncodedContents(), true);
        }
    }
}
