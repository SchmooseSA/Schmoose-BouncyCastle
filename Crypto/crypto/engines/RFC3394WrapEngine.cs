using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Engines
{
    /// <remarks>
    /// An implementation of the AES Key Wrapper from the NIST Key Wrap
    /// Specification as described in RFC 3394.
    /// <p/>
    /// For further details see: <a href="http://www.ietf.org/rfc/rfc3394.txt">http://www.ietf.org/rfc/rfc3394.txt</a>
    /// and  <a href="http://csrc.nist.gov/encryption/kms/key-wrap.pdf">http://csrc.nist.gov/encryption/kms/key-wrap.pdf</a>.
    /// </remarks>
    public class Rfc3394WrapEngine : IWrapper
    {
        private readonly IBlockCipher _engine;

        private KeyParameter _param;
        private bool _forWrapping;

        private byte[] _iv =
		{
			0xa6, 0xa6, 0xa6, 0xa6,
			0xa6, 0xa6, 0xa6, 0xa6
		};

        public Rfc3394WrapEngine(IBlockCipher engine)
        {
            _engine = engine;
        }

        public void Init(bool forWrapping, ICipherParameters parameters)
        {
            _forWrapping = forWrapping;

            if (parameters is ParametersWithRandom)
            {
                parameters = ((ParametersWithRandom)parameters).Parameters;
            }

            _param = parameters as KeyParameter;
            if (_param != null)
                return;

            var parametersWithIV = parameters as ParametersWithIV;
            if (parametersWithIV == null)
                throw new ArgumentException("Bad parameters.", "parameters");

            var iv = parametersWithIV.GetIV();
            if (iv.Length != 8)
                throw new ArgumentException("IV length not equal to 8", "parameters");

            _iv = iv;
            _param = (KeyParameter)parametersWithIV.Parameters;
        }

        public string AlgorithmName
        {
            get { return _engine.AlgorithmName; }
        }

        public byte[] Wrap(byte[] input, int inOff, int inLen)
        {
            if (!_forWrapping)
                throw new InvalidOperationException("not set for wrapping");

            var n = inLen / 8;
            if ((n * 8) != inLen)
            {
                throw new DataLengthException("wrap data must be a multiple of 8 bytes");
            }

            var block = new byte[inLen + _iv.Length];
            var buf = new byte[8 + _iv.Length];

            Array.Copy(_iv, 0, block, 0, _iv.Length);
            Array.Copy(input, 0, block, _iv.Length, inLen);

            _engine.Init(true, _param);

            for (var j = 0; j != 6; j++)
            {
                for (var i = 1; i <= n; i++)
                {
                    Array.Copy(block, 0, buf, 0, _iv.Length);
                    Array.Copy(block, 8 * i, buf, _iv.Length, 8);
                    _engine.ProcessBlock(buf, 0, buf, 0);

                    var t = n * j + i;
                    for (var k = 1; t != 0; k++)
                    {
                        var v = (byte)t;

                        buf[_iv.Length - k] ^= v;
                        t = (int)((uint)t >> 8);
                    }

                    Array.Copy(buf, 0, block, 0, 8);
                    Array.Copy(buf, 8, block, 8 * i, 8);
                }
            }

            return block;
        }

        public byte[] Unwrap(byte[] input, int inOff, int inLen)
        {
            if (_forWrapping)
            {
                throw new InvalidOperationException("not set for unwrapping");
            }

            var n = inLen / 8;

            if ((n * 8) != inLen)
            {
                throw new InvalidCipherTextException("unwrap data must be a multiple of 8 bytes");
            }

            var block = new byte[inLen - _iv.Length];
            var a = new byte[_iv.Length];
            var buf = new byte[8 + _iv.Length];

            Array.Copy(input, 0, a, 0, _iv.Length);
            Array.Copy(input, _iv.Length, block, 0, inLen - _iv.Length);

            _engine.Init(false, _param);

            n = n - 1;

            for (var j = 5; j >= 0; j--)
            {
                for (var i = n; i >= 1; i--)
                {
                    Array.Copy(a, 0, buf, 0, _iv.Length);
                    Array.Copy(block, 8 * (i - 1), buf, _iv.Length, 8);

                    var t = n * j + i;
                    for (var k = 1; t != 0; k++)
                    {
                        var v = (byte)t;

                        buf[_iv.Length - k] ^= v;
                        t = (int)((uint)t >> 8);
                    }

                    _engine.ProcessBlock(buf, 0, buf, 0);
                    Array.Copy(buf, 0, a, 0, 8);
                    Array.Copy(buf, 8, block, 8 * (i - 1), 8);
                }
            }

            if (!Arrays.ConstantTimeAreEqual(a, _iv))
                throw new InvalidCipherTextException("checksum failed");

            return block;
        }
    }
}
