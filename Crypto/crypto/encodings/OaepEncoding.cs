using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Encodings
{
    /**
    * Optimal Asymmetric Encryption Padding (OAEP) - see PKCS 1 V 2.
    */
    public class OaepEncoding : IAsymmetricBlockCipher
    {
        private readonly byte[] _defHash;
        private readonly IDigest _hash;
        private readonly IDigest _mgf1Hash;

        private readonly IAsymmetricBlockCipher _engine;
        private ISecureRandom _random;
        private bool _forEncryption;

        public OaepEncoding(IAsymmetricBlockCipher cipher)
            : this(cipher, new Sha1Digest(), null)
        {
        }

        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash)
            : this(cipher, hash, null)
        {
        }

        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash, byte[] encodingParams)
            : this(cipher, hash, hash, encodingParams)
        {
        }

        public OaepEncoding(IAsymmetricBlockCipher cipher, IDigest hash, IDigest mgf1Hash, byte[] encodingParams)
        {
            _engine = cipher;
            _hash = hash;
            _mgf1Hash = mgf1Hash;
            _defHash = new byte[hash.GetDigestSize()];

            if (encodingParams != null)
            {
                hash.BlockUpdate(encodingParams, 0, encodingParams.Length);
            }

            hash.DoFinal(_defHash, 0);
        }

        public IAsymmetricBlockCipher GetUnderlyingCipher()
        {
            return _engine;
        }

        public string AlgorithmName
        {
            get { return _engine.AlgorithmName + "/OAEPPadding"; }
        }

        public void Init(bool forEncryption, ICipherParameters param)
        {
            var rParam = param as ParametersWithRandom;

            _random = rParam != null ? rParam.Random : new SecureRandom();
            _engine.Init(forEncryption, param);
            _forEncryption = forEncryption;
        }

        public int GetInputBlockSize()
        {
            var baseBlockSize = _engine.GetInputBlockSize();

            if (_forEncryption)
            {
                return baseBlockSize - 1 - 2 * _defHash.Length;
            }
            return baseBlockSize;
        }

        public int GetOutputBlockSize()
        {
            var baseBlockSize = _engine.GetOutputBlockSize();

            if (_forEncryption)
            {
                return baseBlockSize;
            }
            return baseBlockSize - 1 - 2 * _defHash.Length;
        }

        public byte[] ProcessBlock(
            byte[] inBytes,
            int inOff,
            int inLen)
        {
            return _forEncryption ? EncodeBlock(inBytes, inOff, inLen) : DecodeBlock(inBytes, inOff, inLen);
        }

        private byte[] EncodeBlock(byte[] inBytes, int inOff, int inLen)
        {
            var block = new byte[GetInputBlockSize() + 1 + 2 * _defHash.Length];

            //
            // copy in the message
            //
            Array.Copy(inBytes, inOff, block, block.Length - inLen, inLen);

            //
            // add sentinel
            //
            block[block.Length - inLen - 1] = 0x01;

            //
            // as the block is already zeroed - there's no need to add PS (the >= 0 pad of 0)
            //

            //
            // add the hash of the encoding params.
            //
            Array.Copy(_defHash, 0, block, _defHash.Length, _defHash.Length);

            //
            // generate the seed.
            //
            var seed = _random.GenerateSeed(_defHash.Length);

            //
            // mask the message block.
            //
            var mask = MaskGeneratorFunction1(seed, 0, seed.Length, block.Length - _defHash.Length);

            for (var i = _defHash.Length; i != block.Length; i++)
            {
                block[i] ^= mask[i - _defHash.Length];
            }

            //
            // add in the seed
            //
            Array.Copy(seed, 0, block, 0, _defHash.Length);

            //
            // mask the seed.
            //
            mask = MaskGeneratorFunction1(
                block, _defHash.Length, block.Length - _defHash.Length, _defHash.Length);

            for (var i = 0; i != _defHash.Length; i++)
            {
                block[i] ^= mask[i];
            }

            return _engine.ProcessBlock(block, 0, block.Length);
        }

        /**
        * @exception InvalidCipherTextException if the decrypted block turns out to
        * be badly formatted.
        */
        private byte[] DecodeBlock(byte[] inBytes, int inOff, int inLen)
        {
            var data = _engine.ProcessBlock(inBytes, inOff, inLen);
            byte[] block;

            //
            // as we may have zeros in our leading bytes for the block we produced
            // on encryption, we need to make sure our decrypted block comes back
            // the same size.
            //
            if (data.Length < _engine.GetOutputBlockSize())
            {
                block = new byte[_engine.GetOutputBlockSize()];

                Array.Copy(data, 0, block, block.Length - data.Length, data.Length);
            }
            else
            {
                block = data;
            }

            if (block.Length < (2 * _defHash.Length) + 1)
            {
                throw new InvalidCipherTextException("data too short");
            }

            //
            // unmask the seed.
            //
            var mask = MaskGeneratorFunction1(
                block, _defHash.Length, block.Length - _defHash.Length, _defHash.Length);

            for (var i = 0; i != _defHash.Length; i++)
            {
                block[i] ^= mask[i];
            }

            //
            // unmask the message block.
            //
            mask = MaskGeneratorFunction1(block, 0, _defHash.Length, block.Length - _defHash.Length);

            for (var i = _defHash.Length; i != block.Length; i++)
            {
                block[i] ^= mask[i - _defHash.Length];
            }

            //
            // check the hash of the encoding params.
            //
            for (var i = 0; i != _defHash.Length; i++)
            {
                if (_defHash[i] != block[_defHash.Length + i])
                {
                    throw new InvalidCipherTextException("data hash wrong");
                }
            }

            //
            // find the data block
            //
            int start;
            for (start = 2 * _defHash.Length; start != block.Length; start++)
            {
                if (block[start] != 0)
                {
                    break;
                }
            }

            if (start >= (block.Length - 1) || block[start] != 1)
            {
                throw new InvalidCipherTextException("data start wrong " + start);
            }

            start++;

            //
            // extract the data block
            //
            var output = new byte[block.Length - start];

            Array.Copy(block, start, output, 0, output.Length);

            return output;
        }

        /**
        * int to octet string.
        */
        private static void ItoOsp(int i, byte[] sp)
        {
            sp[0] = (byte)((uint)i >> 24);
            sp[1] = (byte)((uint)i >> 16);
            sp[2] = (byte)((uint)i >> 8);
            sp[3] = (byte)((uint)i >> 0);
        }

        /**
        * mask generator function, as described in PKCS1v2.
        */
        private byte[] MaskGeneratorFunction1(byte[] z,int zOff,int zLen,int length)
        {
            var mask = new byte[length];
            var hashBuf = new byte[_mgf1Hash.GetDigestSize()];
            var C = new byte[4];
            var counter = 0;

            _hash.Reset();

            do
            {
                ItoOsp(counter, C);

                _mgf1Hash.BlockUpdate(z, zOff, zLen);
                _mgf1Hash.BlockUpdate(C, 0, C.Length);
                _mgf1Hash.DoFinal(hashBuf, 0);

                Array.Copy(hashBuf, 0, mask, counter * hashBuf.Length, hashBuf.Length);
            }
            while (++counter < (length / hashBuf.Length));

            if ((counter * hashBuf.Length) < length)
            {
                ItoOsp(counter, C);

                _mgf1Hash.BlockUpdate(z, zOff, zLen);
                _mgf1Hash.BlockUpdate(C, 0, C.Length);
                _mgf1Hash.DoFinal(hashBuf, 0);

                Array.Copy(hashBuf, 0, mask, counter * hashBuf.Length, mask.Length - (counter * hashBuf.Length));
            }

            return mask;
        }
    }
}

