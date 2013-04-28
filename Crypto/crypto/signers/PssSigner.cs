using System;

using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Crypto.Signers
{
    /// <summary> RSA-PSS as described in Pkcs# 1 v 2.1.
    /// <p>
    /// Note: the usual value for the salt length is the number of
    /// bytes in the hash function.</p>
    /// </summary>
    public class PssSigner : ISigner
    {
        public const byte TrailerImplicit = (byte)0xBC;

        private readonly IDigest _contentDigest1, _contentDigest2;
        private readonly IDigest _mgfDigest;
        private readonly IAsymmetricBlockCipher _cipher;

        private ISecureRandom _random;

        private readonly int _hLen;
        private readonly int _mgfhLen;
        private readonly int _sLen;
        private int _emBits;
        private readonly byte[] _salt;
        private readonly byte[] _mDash;
        private byte[] _block;
        private readonly byte _trailer;

        public static PssSigner CreateRawSigner(IAsymmetricBlockCipher cipher, IDigest digest)
        {
            return new PssSigner(cipher, new NullDigest(), digest, digest, digest.GetDigestSize(), TrailerImplicit);
        }

        public static PssSigner CreateRawSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest, int saltLen, byte trailer)
        {
            return new PssSigner(cipher, new NullDigest(), contentDigest, mgfDigest, saltLen, trailer);
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest digest)
            : this(cipher, digest, digest.GetDigestSize())
        {
        }

        /// <summary>Basic constructor</summary>
        /// <param name="cipher">the asymmetric cipher to use.</param>
        /// <param name="digest">the digest to use.</param>
        /// <param name="saltLen">the length of the salt to use (in bytes).</param>
        public PssSigner(IAsymmetricBlockCipher cipher, IDigest digest, int saltLen)
            : this(cipher, digest, saltLen, TrailerImplicit)
        {
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest, int saltLen)
            : this(cipher, contentDigest, mgfDigest, saltLen, TrailerImplicit)
        {
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest digest, int saltLen, byte trailer)
            : this(cipher, digest, digest, saltLen, TrailerImplicit)
        {
        }

        public PssSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest, IDigest mgfDigest, int saltLen, byte trailer)
            : this(cipher, contentDigest, contentDigest, mgfDigest, saltLen, trailer)
        {
        }

        private PssSigner(IAsymmetricBlockCipher cipher, IDigest contentDigest1, IDigest contentDigest2, IDigest mgfDigest, int saltLen, byte trailer)
        {
            _cipher = cipher;
            _contentDigest1 = contentDigest1;
            _contentDigest2 = contentDigest2;
            _mgfDigest = mgfDigest;
            _hLen = contentDigest2.GetDigestSize();
            _mgfhLen = mgfDigest.GetDigestSize();
            _sLen = saltLen;
            _salt = new byte[saltLen];
            _mDash = new byte[8 + saltLen + _hLen];
            _trailer = trailer;
        }

        public string AlgorithmName
        {
            get { return _mgfDigest.AlgorithmName + "withRSAandMGF1"; }
        }

        public virtual void Init(bool forSigning, ICipherParameters parameters)
        {
            var p = parameters as ParametersWithRandom;
            if (p != null)
            {
                parameters = p.Parameters;
                _random = p.Random;
            }
            else
            {
                if (forSigning)
                {
                    _random = new SecureRandom();
                }
            }

            _cipher.Init(forSigning, parameters);

            RsaKeyParameters kParam;
            if (parameters is RsaBlindingParameters)
            {
                kParam = ((RsaBlindingParameters)parameters).PublicKey;
            }
            else
            {
                kParam = (RsaKeyParameters)parameters;
            }

            _emBits = kParam.Modulus.BitLength - 1;

            if (_emBits < (8 * _hLen + 8 * _sLen + 9))
                throw new ArgumentException("key too small for specified hash and salt lengths");

            _block = new byte[(_emBits + 7) / 8];
        }

        /// <summary> clear possible sensitive data</summary>
        private void ClearBlock(
            byte[] block)
        {
            Array.Clear(block, 0, block.Length);
        }

        /// <summary> update the internal digest with the byte b</summary>
        public virtual void Update(
            byte input)
        {
            _contentDigest1.Update(input);
        }

        /// <summary> update the internal digest with the byte array in</summary>
        public virtual void BlockUpdate(
            byte[] input,
            int inOff,
            int length)
        {
            _contentDigest1.BlockUpdate(input, inOff, length);
        }

        /// <summary> reset the internal state</summary>
        public virtual void Reset()
        {
            _contentDigest1.Reset();
        }

        /// <summary> Generate a signature for the message we've been loaded with using
        /// the key we were initialised with.
        /// </summary>
        public virtual byte[] GenerateSignature()
        {
            _contentDigest1.DoFinal(_mDash, _mDash.Length - _hLen - _sLen);

            if (_sLen != 0)
            {
                _random.NextBytes(_salt);
                _salt.CopyTo(_mDash, _mDash.Length - _sLen);
            }

            var h = new byte[_hLen];

            _contentDigest2.BlockUpdate(_mDash, 0, _mDash.Length);

            _contentDigest2.DoFinal(h, 0);

            _block[_block.Length - _sLen - 1 - _hLen - 1] = (byte)(0x01);
            _salt.CopyTo(_block, _block.Length - _sLen - _hLen - 1);

            byte[] dbMask = MaskGeneratorFunction1(h, 0, h.Length, _block.Length - _hLen - 1);
            for (int i = 0; i != dbMask.Length; i++)
            {
                _block[i] ^= dbMask[i];
            }

            _block[0] &= (byte)((0xff >> ((_block.Length * 8) - _emBits)));

            h.CopyTo(_block, _block.Length - _hLen - 1);

            _block[_block.Length - 1] = _trailer;

            byte[] b = _cipher.ProcessBlock(_block, 0, _block.Length);

            ClearBlock(_block);

            return b;
        }

        /// <summary> return true if the internal state represents the signature described
        /// in the passed in array.
        /// </summary>
        public virtual bool VerifySignature(
            byte[] signature)
        {
            _contentDigest1.DoFinal(_mDash, _mDash.Length - _hLen - _sLen);

            byte[] b = _cipher.ProcessBlock(signature, 0, signature.Length);
            b.CopyTo(_block, _block.Length - b.Length);

            if (_block[_block.Length - 1] != _trailer)
            {
                ClearBlock(_block);
                return false;
            }

            byte[] dbMask = MaskGeneratorFunction1(_block, _block.Length - _hLen - 1, _hLen, _block.Length - _hLen - 1);

            for (int i = 0; i != dbMask.Length; i++)
            {
                _block[i] ^= dbMask[i];
            }

            _block[0] &= (byte)((0xff >> ((_block.Length * 8) - _emBits)));

            for (int i = 0; i != _block.Length - _hLen - _sLen - 2; i++)
            {
                if (_block[i] != 0)
                {
                    ClearBlock(_block);
                    return false;
                }
            }

            if (_block[_block.Length - _hLen - _sLen - 2] != 0x01)
            {
                ClearBlock(_block);
                return false;
            }

            Array.Copy(_block, _block.Length - _sLen - _hLen - 1, _mDash, _mDash.Length - _sLen, _sLen);

            _contentDigest2.BlockUpdate(_mDash, 0, _mDash.Length);
            _contentDigest2.DoFinal(_mDash, _mDash.Length - _hLen);

            for (int i = _block.Length - _hLen - 1, j = _mDash.Length - _hLen; j != _mDash.Length; i++, j++)
            {
                if ((_block[i] ^ _mDash[j]) != 0)
                {
                    ClearBlock(_mDash);
                    ClearBlock(_block);
                    return false;
                }
            }

            ClearBlock(_mDash);
            ClearBlock(_block);

            return true;
        }

        /// <summary> int to octet string.</summary>
        private static void ItoOsp(int i, byte[] sp)
        {
            sp[0] = (byte)((uint)i >> 24);
            sp[1] = (byte)((uint)i >> 16);
            sp[2] = (byte)((uint)i >> 8);
            sp[3] = (byte)((uint)i >> 0);
        }

        /// <summary> mask generator function, as described in Pkcs1v2.</summary>
        private byte[] MaskGeneratorFunction1(byte[] z, int zOff, int zLen, int length)
        {
            var mask = new byte[length];
            var hashBuf = new byte[_mgfhLen];
            var C = new byte[4];
            var counter = 0;

            _mgfDigest.Reset();

            while (counter < (length / _mgfhLen))
            {
                ItoOsp(counter, C);

                _mgfDigest.BlockUpdate(z, zOff, zLen);
                _mgfDigest.BlockUpdate(C, 0, C.Length);
                _mgfDigest.DoFinal(hashBuf, 0);

                hashBuf.CopyTo(mask, counter * _mgfhLen);
                ++counter;
            }

            if ((counter * _mgfhLen) < length)
            {
                ItoOsp(counter, C);

                _mgfDigest.BlockUpdate(z, zOff, zLen);
                _mgfDigest.BlockUpdate(C, 0, C.Length);
                _mgfDigest.DoFinal(hashBuf, 0);

                Array.Copy(hashBuf, 0, mask, counter * _mgfhLen, mask.Length - (counter * _mgfhLen));
            }

            return mask;
        }
    }
}
