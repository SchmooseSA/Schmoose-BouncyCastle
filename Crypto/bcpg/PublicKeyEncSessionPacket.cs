using System.IO;
using System.Linq;
using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg
{
    /// <remarks>Basic packet for a PGP public key.</remarks>
    public class PublicKeyEncSessionPacket : ContainedPacket //, PublicKeyAlgorithmTag
    {
        private readonly int _version;
        private readonly long _keyId;
        private readonly PublicKeyAlgorithmTag _algorithm;
        private readonly IBigInteger[] _data;
        private readonly byte[] _extraData;

        internal PublicKeyEncSessionPacket(BcpgInputStream bcpgIn)
        {
            _version = bcpgIn.ReadByte();

            _keyId |= (long)bcpgIn.ReadByte() << 56;
            _keyId |= (long)bcpgIn.ReadByte() << 48;
            _keyId |= (long)bcpgIn.ReadByte() << 40;
            _keyId |= (long)bcpgIn.ReadByte() << 32;
            _keyId |= (long)bcpgIn.ReadByte() << 24;
            _keyId |= (long)bcpgIn.ReadByte() << 16;
            _keyId |= (long)bcpgIn.ReadByte() << 8;
            _keyId |= (uint)bcpgIn.ReadByte();

            _algorithm = (PublicKeyAlgorithmTag)bcpgIn.ReadByte();

            switch (_algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    _data = new[] { new MPInteger(bcpgIn).Value };
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:                
                    _data = new[]
					{
						new MPInteger(bcpgIn).Value,
						new MPInteger(bcpgIn).Value
					};
                    break;

                case PublicKeyAlgorithmTag.Ecdh:
                    _data = new[] { new MPInteger(bcpgIn).Value };
                    var length = bcpgIn.ReadByte();
                    if (length > 0xFF)
                        throw new IOException("EC DH symmetric key data is too long.");
                    _extraData = new byte[length];
                    bcpgIn.ReadFully(_extraData, 0, length);
                    break;
                default:
                    throw new IOException("unknown PGP public key algorithm encountered");
            }
        }

        public PublicKeyEncSessionPacket(long keyId, PublicKeyAlgorithmTag algorithm, BigInteger[] data)
            : this(keyId, algorithm, data, null) { }

        public PublicKeyEncSessionPacket(long keyId, PublicKeyAlgorithmTag algorithm, BigInteger[] data, byte[] extraData)
        {
            _version = 3;
            _keyId = keyId;
            _algorithm = algorithm;
            _data = (IBigInteger[])data.Clone();
            _extraData = extraData != null ? (byte[])extraData.Clone() : null;
        }

        public int Version
        {
            get { return _version; }
        }

        public long KeyId
        {
            get { return _keyId; }
        }

        public PublicKeyAlgorithmTag Algorithm
        {
            get { return _algorithm; }
        }

        public IBigInteger[] GetEncSessionKey()
        {
            var sessionKey = Platform.CreateArrayList<IBigInteger>();
            foreach (var integer in _data)
            {
                sessionKey.Add(integer);    
            }            
            if(_extraData != null)
                sessionKey.Add(new BigInteger(_extraData));
            return sessionKey.ToArray();
        }

        public byte[] ExtraData
        {
            get { return _extraData != null ? (byte[])_extraData.Clone() : null; }
        }

        public override void Encode(IBcpgOutputStream bcpgOut)
        {
            using (var bOut = new MemoryStream())
            {
                using (var pOut = new BcpgOutputStream(bOut))
                {

                    pOut.WriteByte((byte)_version);

                    pOut.WriteLong(_keyId);

                    pOut.WriteByte((byte)_algorithm);

                    for (var i = 0; i != _data.Length; i++)
                    {
                        MPInteger.EncodeInteger(pOut, _data[i]);
                    }

                    if (_extraData != null)
                    {
                        if (_extraData.Length > 0xFF)
                            throw new PgpException("Extra Data is too large.");
                        pOut.WriteByte((byte)_extraData.Length);
                        pOut.Write(_extraData, 0, _extraData.Length);
                    }

                    bcpgOut.WritePacket(PacketTag.PublicKeyEncryptedSession, bOut.ToArray(), true);
                }
            }
        }
    }
}
