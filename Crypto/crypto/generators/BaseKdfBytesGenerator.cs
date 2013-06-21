using System;
using Org.BouncyCastle.Crypto.Parameters;

namespace Org.BouncyCastle.Crypto.Generators
{
    /**
    * Basic KDF generator for derived keys and ivs as defined by IEEE P1363a/ISO 18033
    * <br/>
    * This implementation is based on ISO 18033/P1363a.
    */
    public class BaseKdfBytesGenerator : IDerivationFunction
    {
        private readonly int _counterStart;
        private readonly IDigest _digest;
        private byte[] _shared;
        private byte[] _iv;

        /**
        * Construct a KDF Parameters generator.
        *
        * @param counterStart value of counter.
        * @param digest the digest to be used as the source of derived keys.
        */
        protected BaseKdfBytesGenerator(int counterStart, IDigest digest)
        {
            _counterStart = counterStart;
            _digest = digest;
        }

        public void Init(IDerivationParameters parameters)
        {
            var kdfParameters = parameters as KdfParameters;
            if (kdfParameters != null)
            {
                _shared = kdfParameters.GetSharedSecret();
                _iv = kdfParameters.GetIV();
            }
            else if (parameters is Iso18033KdfParameters)
            {
                var p = (Iso18033KdfParameters)parameters;

                _shared = p.GetSeed();
                _iv = null;
            }
            else
            {
                throw new ArgumentException("KDF parameters required for KDF Generator");
            }
        }

        /**
        * return the underlying digest.
        */
        public IDigest Digest
        {
            get
            {
                return _digest;
            }
        }

        /**
        * fill len bytes of the output buffer with bytes generated from
        * the derivation function.
        *
        * @throws ArgumentException if the size of the request will cause an overflow.
        * @throws DataLengthException if the out buffer is too small.
        */
        public int GenerateBytes(byte[] output, int outOff, int length)
        {
            if ((output.Length - length) < outOff)
            {
                throw new DataLengthException("output buffer too small");
            }

            long oBytes = length;
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

            var counter = _counterStart;

            for (var i = 0; i < cThreshold; i++)
            {
                _digest.BlockUpdate(_shared, 0, _shared.Length);

                _digest.Update((byte)(counter >> 24));
                _digest.Update((byte)(counter >> 16));
                _digest.Update((byte)(counter >> 8));
                _digest.Update((byte)counter);

                if (_iv != null)
                {
                    _digest.BlockUpdate(_iv, 0, _iv.Length);
                }

                _digest.DoFinal(dig, 0);

                if (length > outLen)
                {
                    Array.Copy(dig, 0, output, outOff, outLen);
                    outOff += outLen;
                    length -= outLen;
                }
                else
                {
                    Array.Copy(dig, 0, output, outOff, length);
                }

                counter++;
            }

            _digest.Reset();

            return (int)oBytes;
        }
    }
}