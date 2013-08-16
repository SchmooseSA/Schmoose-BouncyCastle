using System;
using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    public class DHKdfParameters : IDerivationParameters
    {
        private readonly DerObjectIdentifier _algorithm;
        private readonly int _keySize;
        private readonly byte[] _z;
        private readonly byte[] _extraInfo;

        public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z)
            : this(algorithm, keySize, z, null)
        {
        }

        public DHKdfParameters(DerObjectIdentifier algorithm, int keySize, byte[] z, byte[] extraInfo)
        {
            _algorithm = algorithm;
            _keySize = keySize;
            _z = z; // TODO Clone?
            _extraInfo = extraInfo;
        }

        public DerObjectIdentifier Algorithm
        {
            get { return _algorithm; }
        }

        public int KeySize
        {
            get { return _keySize; }
        }

        public byte[] GetZ()
        {
            return (byte[])_z.Clone();
        }

        public byte[] GetExtraInfo()
        {
            return _extraInfo != null ? (byte[])_extraInfo.Clone() : null;
        }
    }
}
