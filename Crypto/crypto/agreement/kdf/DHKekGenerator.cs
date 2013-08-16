using System;

using Org.BouncyCastle.Asn1;

namespace Org.BouncyCastle.Crypto.Agreement.Kdf
{
    /**
    * RFC 2631 Diffie-hellman KEK derivation function.
    */
    public class DHKekGenerator : IDerivationFunction
    {
        private readonly IDigest _digest;

        private DerObjectIdentifier _algorithm;
        private int _keySize;
        private byte[] _z;
        private byte[] _partyAInfo;

        public DHKekGenerator(IDigest digest)
        {
            _digest = digest;
        }

        public void Init(IDerivationParameters param)
        {
            var parameters = (DHKdfParameters)param;

            _algorithm = parameters.Algorithm;
            _keySize = parameters.KeySize;
            _z = parameters.GetZ(); // TODO Clone?
            _partyAInfo = parameters.GetExtraInfo(); // TODO Clone?
        }

        public IDigest Digest
        {
            get { return _digest; }
        }

        public int GenerateBytes(byte[] outBytes, int outOff, int len)
        {
            if ((outBytes.Length - len) < outOff)
            {
                throw new DataLengthException("output buffer too small");
            }

            long oBytes = len;
            var outLen = _digest.GetDigestSize();

            //
            // this is at odds with the standard implementation, the
            // maximum value should be hBits * (2^32 - 1) where hBits
            // is the digest output size in bits. We can't have an
            // array with a long index at the moment...
            //
            if (oBytes > ((2L << 32) - 1))
            {
                throw new ArgumentException("Output length too large");
            }

            var cThreshold = (int)((oBytes + outLen - 1) / outLen);

            var dig = new byte[_digest.GetDigestSize()];

            var counter = 1;

            for (var i = 0; i < cThreshold; i++)
            {
                _digest.BlockUpdate(_z, 0, _z.Length);

                // KeySpecificInfo
                var keyInfo = new DerSequence(_algorithm, new DerOctetString(IntegerToBytes(counter)));

                // OtherInfo
                var v1 = new Asn1EncodableVector(keyInfo);

                if (_partyAInfo != null)
                {
                    v1.Add(new DerTaggedObject(true, 0, new DerOctetString(_partyAInfo)));
                }

                v1.Add(new DerTaggedObject(true, 2, new DerOctetString(IntegerToBytes(_keySize))));

                var other = new DerSequence(v1).GetDerEncoded();
                _digest.BlockUpdate(other, 0, other.Length);
                _digest.DoFinal(dig, 0);

                if (len > outLen)
                {
                    Array.Copy(dig, 0, outBytes, outOff, outLen);
                    outOff += outLen;
                    len -= outLen;
                }
                else
                {
                    Array.Copy(dig, 0, outBytes, outOff, len);
                }

                counter++;
            }

            _digest.Reset();

            return len;
        }

        private static byte[] IntegerToBytes(int keySize)
        {
            var val = new byte[4];

            val[0] = (byte)(keySize >> 24);
            val[1] = (byte)(keySize >> 16);
            val[2] = (byte)(keySize >> 8);
            val[3] = (byte)keySize;

            return val;
        }
    }
}
