using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.crypto.engines
{
    public class RFC6637ECDHEngine
    {
        private static readonly byte[] _anonymousSender = Encoding.UTF8.GetBytes("Anonymous Sender    ");

        private ECDHPrivateKeyParameters _privateKey;
        private ECDHPublicKeyParameters _publicKey;
        private bool _forEncryption;

        /// <summary>
        /// Inits the instance.
        /// </summary>
        /// <param name="forEncryption">if set to <c>true</c> [for encryption].</param>
        /// <param name="privateKey">The private key.</param>
        /// <param name="publicKey">The public key.</param>
        public void Init(bool forEncryption, ECDHPrivateKeyParameters privateKey, ECDHPublicKeyParameters publicKey)
        {
            _privateKey = privateKey;
            _publicKey = publicKey;
            _forEncryption = forEncryption;
        }

        /// <summary>
        /// Processes the block.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="offset">The offset.</param>
        /// <param name="size">The size.</param>
        /// <returns></returns>
        public byte[] ProcessBlock(byte[] input, int offset, int size)
        {
            return _forEncryption ? this.Encrypt(input, offset, size) : this.Decrypt(input, offset, size);
        }

        /// <summary>
        /// Decrypts the specified input.
        /// </summary>
        /// <param name="input">The input.</param>
        /// <param name="offset">The offset.</param>
        /// <param name="size">The size.</param>
        /// <returns></returns>
        private byte[] Decrypt(byte[] input, int offset, int size)
        {
            var wrapper = this.InitializeWrapper();
            var padded = wrapper.Unwrap(input, offset, size);

            var resultSize = padded.Length;
            while (padded[resultSize - 1] == 0x05)
                --resultSize;

            var result = new byte[resultSize];
            Buffer.BlockCopy(padded, 0, result, 0, resultSize);
            return result;
        }

        private byte[] Encrypt(byte[] input, int offset, int size)
        {
            return null;
        }



        /// <summary>
        /// Generates the KDF parameters.
        /// Sess Sections 7 & 8 of RFC 6637 (http://tools.ietf.org/html/rfc6637) for more details
        /// </summary>
        /// <returns></returns>
        private byte[] GenerateKDFParameters()
        {
            using (var kdfParams = new MemoryStream())
            {
                var agreement = new ECDHBasicAgreement();
                agreement.Init(_privateKey);
                var zb = agreement.CalculateAgreement(_publicKey).ToByteArrayUnsigned();

                kdfParams.WriteByte(0x00);
                kdfParams.WriteByte(0x00);
                kdfParams.WriteByte(0x00);
                kdfParams.WriteByte(0x01);
                kdfParams.Write(zb, 0, zb.Length);

                var oid = _publicKey.PublicKeyParamSet.ToBytes();
                kdfParams.WriteByte((byte)oid.Length);
                kdfParams.Write(oid, 0, oid.Length);
                kdfParams.WriteByte((byte)PublicKeyAlgorithmTag.Ecdh);
                kdfParams.WriteByte(0x3);
                kdfParams.WriteByte(0x1);
                kdfParams.WriteByte((byte)_publicKey.HashAlgorithm);
                kdfParams.WriteByte((byte)_publicKey.SymmetricKeyAlgorithm);
                kdfParams.Write(_anonymousSender, 0, _anonymousSender.Length);
                kdfParams.Write(_privateKey.FingerPrint, 0, _privateKey.FingerPrint.Length);

                return kdfParams.ToArray();
            }
        }

        /// <summary>
        /// Initializes the wrapper.
        /// </summary>
        /// <returns></returns>
        private AesWrapEngine InitializeWrapper()
        {
            var kdfParams = this.GenerateKDFParameters();
            var digest = DigestUtilities.GetDigest(_publicKey.HashAlgorithm.ToString());
            digest.BlockUpdate(kdfParams, 0, kdfParams.Length);
            var hash = DigestUtilities.DoFinal(digest);
            var size = _publicKey.SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.Aes256
                ? 32 : _publicKey.SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.Aes192
                ? 24 : _publicKey.SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.Aes128
                ? 16 : 0;

            var wrap = new AesWrapEngine();
            wrap.Init(_forEncryption, new KeyParameter(hash, 0, size));
            return wrap;
        }
    }
}
