using System;

using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Crypto.Encodings
{
    /**
    * this does your basic Pkcs 1 v1.5 padding - whether or not you should be using this
    * depends on your application - see Pkcs1 Version 2 for details.
    */
    public class Pkcs1Encoding : IAsymmetricBlockCipher
    {
        /**
         * some providers fail to include the leading zero in PKCS1 encoded blocks. If you need to
         * work with one of these set the system property Org.BouncyCastle.Pkcs1.Strict to false.
         */
        public const string StrictLengthEnabledProperty = "Org.BouncyCastle.Pkcs1.Strict";

        private const int HeaderLength = 10;

        /**
         * The same effect can be achieved by setting the static property directly
         * <p>
         * The static property is checked during construction of the encoding object, it is set to
         * true by default.
         * </p>
         */
        public static bool StrictLengthEnabled
        {
            get { return _strictLengthEnabled[0]; }
            set { _strictLengthEnabled[0] = value; }
        }

        private static readonly bool[] _strictLengthEnabled;

        static Pkcs1Encoding()
        {
            var strictProperty = Platform.GetEnvironmentVariable(StrictLengthEnabledProperty);

            _strictLengthEnabled = new[] { strictProperty == null || strictProperty.Equals("true") };
        }


        private ISecureRandom _random;
        private readonly IAsymmetricBlockCipher _engine;
        private bool _forEncryption;
        private bool _forPrivateKey;
        private readonly bool _useStrictLength;

        /**
         * Basic constructor.
         * @param cipher
         */
        public Pkcs1Encoding(IAsymmetricBlockCipher cipher)
        {
            _engine = cipher;
            _useStrictLength = StrictLengthEnabled;
        }

        public IAsymmetricBlockCipher GetUnderlyingCipher()
        {
            return _engine;
        }

        public string AlgorithmName
        {
            get { return _engine.AlgorithmName + "/PKCS1Padding"; }
        }

        public void Init(bool forEncryption, ICipherParameters parameters)
        {
            IAsymmetricKeyParameter kParam;

            var rParam = parameters as ParametersWithRandom;
            if (rParam != null)
            {
                _random = rParam.Random;
                kParam = (AsymmetricKeyParameter)rParam.Parameters;
            }
            else
            {
                _random = new SecureRandom();
                kParam = (AsymmetricKeyParameter)parameters;
            }

            _engine.Init(forEncryption, parameters);
            _forPrivateKey = kParam.IsPrivate;
            _forEncryption = forEncryption;
        }

        public int GetInputBlockSize()
        {
            var baseBlockSize = _engine.GetInputBlockSize();

            return _forEncryption
                ? baseBlockSize - HeaderLength
                : baseBlockSize;
        }

        public int GetOutputBlockSize()
        {
            var baseBlockSize = _engine.GetOutputBlockSize();

            return _forEncryption
                ? baseBlockSize
                : baseBlockSize - HeaderLength;
        }

        public byte[] ProcessBlock(byte[] input, int inOff, int length)
        {
            return _forEncryption
                ? EncodeBlock(input, inOff, length)
                : DecodeBlock(input, inOff, length);
        }

        private byte[] EncodeBlock(byte[] input, int inOff, int inLen)
        {
            if (inLen > GetInputBlockSize())
                throw new ArgumentException("input data too large", "inLen");

            var block = new byte[_engine.GetInputBlockSize()];

            if (_forPrivateKey)
            {
                block[0] = 0x01;                        // type code 1

                for (var i = 1; i != block.Length - inLen - 1; i++)
                {
                    block[i] = (byte)0xFF;
                }
            }
            else
            {
                _random.NextBytes(block);                // random fill

                block[0] = 0x02;                        // type code 2

                //
                // a zero byte marks the end of the padding, so all
                // the pad bytes must be non-zero.
                //
                for (var i = 1; i != block.Length - inLen - 1; i++)
                {
                    while (block[i] == 0)
                    {
                        block[i] = (byte)_random.NextInt();
                    }
                }
            }

            block[block.Length - inLen - 1] = 0x00;       // mark the end of the padding
            Array.Copy(input, inOff, block, block.Length - inLen, inLen);

            return _engine.ProcessBlock(block, 0, block.Length);
        }

        /**
        * @exception InvalidCipherTextException if the decrypted block is not in Pkcs1 format.
        */
        private byte[] DecodeBlock(byte[] input, int inOff, int inLen)
        {
            var block = _engine.ProcessBlock(input, inOff, inLen);

            if (block.Length < GetOutputBlockSize())
            {
                throw new InvalidCipherTextException("block truncated");
            }

            var type = block[0];

            if (type != 1 && type != 2)
            {
                throw new InvalidCipherTextException("unknown block type");
            }

            if (_useStrictLength && block.Length != _engine.GetOutputBlockSize())
            {
                throw new InvalidCipherTextException("block incorrect size");
            }

            //
            // find and extract the message block.
            //
            int start;
            for (start = 1; start != block.Length; start++)
            {
                var pad = block[start];

                if (pad == 0)
                {
                    break;
                }

                if (type == 1 && pad != (byte)0xff)
                {
                    throw new InvalidCipherTextException("block padding incorrect");
                }
            }

            start++;           // data should start at the next byte

            if (start > block.Length || start < HeaderLength)
            {
                throw new InvalidCipherTextException("no data in block");
            }

            var result = new byte[block.Length - start];

            Array.Copy(block, start, result, 0, result.Length);

            return result;
        }
    }

}
