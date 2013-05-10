using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.Encoders;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A public key encrypted data object.</remarks>
    public class PgpPublicKeyEncryptedData : PgpEncryptedData
    {
        private readonly PublicKeyEncSessionPacket _keyData;

        internal PgpPublicKeyEncryptedData(PublicKeyEncSessionPacket keyData, InputStreamPacket encData)
            : base(encData)
        {
            _keyData = keyData;
        }

        private static IBufferedCipher GetKeyCipher(PublicKeyAlgorithmTag algorithm)
        {
            try
            {
                switch (algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        return CipherUtilities.GetCipher("RSA//PKCS1Padding");
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        return CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                    case PublicKeyAlgorithmTag.Ecdh:
                        return CipherUtilities.GetCipher("ECCCDHIES");                        
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + algorithm);
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        private static bool ConfirmCheckSum(byte[] sessionInfo)
        {
            var check = 0;
            for (var i = 1; i != sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i] & 0xff;
            }

            return (sessionInfo[sessionInfo.Length - 2] == (byte)(check >> 8))
                && (sessionInfo[sessionInfo.Length - 1] == (byte)(check));
        }

        /// <summary>
        /// Gets the key algorithm.
        /// </summary>
        /// <value>
        /// The key algorithm.
        /// </value>
        public PublicKeyAlgorithmTag KeyAlgorithm
        {
            get { return _keyData.Algorithm; }
        }

        /// <summary>
        /// The key ID for the key used to encrypt the data.
        /// </summary>
        /// <value>
        /// The key id.
        /// </value>
        public long KeyId
        {
            get { return _keyData.KeyId; }
        }

        /// <summary>
        /// Return the algorithm code for the symmetric algorithm used to encrypt the data.
        /// </summary>
        /// <param name="privKey">The priv key.</param>
        /// <returns></returns>
        public SymmetricKeyAlgorithmTag GetSymmetricAlgorithm(IPgpPrivateKey privKey)
        {
            var plain = FetchSymmetricKeyData(privKey);

            return (SymmetricKeyAlgorithmTag)plain[0];
        }

        /// <summary>
        /// Return the decrypted data stream for the packet.
        /// </summary>
        /// <param name="privKey">The priv key.</param>
        /// <returns></returns>
        /// <exception cref="PgpException">
        /// exception creating cipher
        /// or
        /// Exception starting decryption
        /// </exception>
        /// <exception cref="System.IO.EndOfStreamException">
        /// unexpected end of stream.
        /// or
        /// unexpected end of stream.
        /// </exception>
        public Stream GetDataStream(IPgpPrivateKey privKey)
        {
            SymmetricKeyAlgorithmTag encryptionAlgorithm;
            return this.GetDataStream(privKey, out encryptionAlgorithm);
        }

        /// <summary>
        /// Gets the data stream.
        /// </summary>
        /// <param name="privKey">The priv key.</param>
        /// <param name="encryptionAlgorithm">The encryption algorithm.</param>
        /// <returns></returns>
        /// <exception cref="Org.BouncyCastle.Bcpg.OpenPgp.PgpException">
        /// exception creating cipher
        /// or
        /// Exception starting decryption
        /// </exception>
        /// <exception cref="System.IO.EndOfStreamException">
        /// unexpected end of stream.
        /// or
        /// unexpected end of stream.
        /// </exception>
        public Stream GetDataStream(IPgpPrivateKey privKey, out SymmetricKeyAlgorithmTag encryptionAlgorithm)
        {
            var plain = this.FetchSymmetricKeyData(privKey);

            encryptionAlgorithm = (SymmetricKeyAlgorithmTag)plain[0];

            IBufferedCipher c2;
            var cipherName = PgpUtilities.GetSymmetricCipherName(encryptionAlgorithm);
            var cName = cipherName;

            try
            {
                if (EncData is SymmetricEncIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                c2 = CipherUtilities.GetCipher(cName);
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("exception creating cipher", e);
            }

            if (c2 == null)
                return EncData.GetInputStream();

            try
            {
                var key = ParameterUtilities.CreateKeyParameter(cipherName, plain, 1, plain.Length - 3);
                var iv = new byte[c2.GetBlockSize()];
                
                c2.Init(false, new ParametersWithIV(key, iv));

                this.EncStream = BcpgInputStream.Wrap(new CipherStream(EncData.GetInputStream(), c2, null));
                if (this.EncData is SymmetricEncIntegrityPacket)
                {
                    this.TruncStream = new TruncatedStream(this.EncStream);

                    var digest = DigestUtilities.GetDigest(PgpUtilities.GetDigestName(HashAlgorithmTag.Sha1));
                    EncStream = new DigestStream(TruncStream, digest, null);
                }

                if (Streams.ReadFully(EncStream, iv, 0, iv.Length) < iv.Length)
                    throw new EndOfStreamException("unexpected end of stream.");

                var v1 = this.EncStream.ReadByte();
                var v2 = this.EncStream.ReadByte();

                if (v1 < 0 || v2 < 0)
                    throw new EndOfStreamException("unexpected end of stream.");

                // Note: the oracle attack on the "quick check" bytes is deemed
                // a security risk for typical public key encryption usages,
                // therefore we do not perform the check.

                //				bool repeatCheckPassed =
                //					iv[iv.Length - 2] == (byte)v1
                //					&&	iv[iv.Length - 1] == (byte)v2;
                //
                //				// Note: some versions of PGP appear to produce 0 for the extra
                //				// bytes rather than repeating the two previous bytes
                //				bool zeroesCheckPassed =
                //					v1 == 0
                //					&&	v2 == 0;
                //
                //				if (!repeatCheckPassed && !zeroesCheckPassed)
                //				{
                //					throw new PgpDataValidationException("quick check failed.");
                //				}

                return this.EncStream;
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception starting decryption", e);
            }
        }

        private void ProcessSymmetricKeyDataForRsa(IBufferedCipher cipher, IList<IBigInteger> symmetricKeyData)
        {
            cipher.ProcessBytes(symmetricKeyData[0].ToByteArrayUnsigned());
        }

        private void ProcessSymmetricKeyDataForElGamal(IPgpPrivateKey privateKey, IBufferedCipher cipher, IList<IBigInteger> symmetricKeyData)
        {
            var k = (ElGamalPrivateKeyParameters)privateKey.Key;
            var size = (k.Parameters.P.BitLength + 7) / 8;

            var bi = symmetricKeyData[0].ToByteArray();

            var diff = bi.Length - size;
            if (diff >= 0)
            {
                cipher.ProcessBytes(bi, diff, size);
            }
            else
            {
                var zeros = new byte[-diff];
                cipher.ProcessBytes(zeros);
                cipher.ProcessBytes(bi);
            }

            bi = symmetricKeyData[1].ToByteArray();

            diff = bi.Length - size;
            if (diff >= 0)
            {
                cipher.ProcessBytes(bi, diff, size);
            }
            else
            {
                var zeros = new byte[-diff];
                cipher.ProcessBytes(zeros);
                cipher.ProcessBytes(bi);
            }
        }

        private static readonly byte[] _anonymousSender = Encoding.UTF8.GetBytes("Anonymous Sender    ");

        private void ProcessSymmetricKeyDataForEcdh(IPgpPrivateKey privateKey, IBufferedCipher cipher, IList<IBigInteger> symmetricKeyData)
        {
            
            var encSymKey = symmetricKeyData[1].ToByteArrayUnsigned();
            var ecParam = (ECDHPrivateKeyParameters)privateKey.Key;
            using (var keyParams = new MemoryStream())
            {
                var zb = ecParam.PublicKeyParameters.Q.GetEncodedX();
                keyParams.WriteByte(0x00);
                keyParams.WriteByte(0x00);
                keyParams.WriteByte(0x00);
                keyParams.WriteByte(0x01);
                keyParams.Write(zb, 0, zb.Length);

                var oid = ecParam.PublicKeyParamSet.ToBytes();                
                keyParams.WriteByte((byte)oid.Length);
                keyParams.Write(oid, 0, oid.Length);
                keyParams.WriteByte((byte)PublicKeyAlgorithmTag.Ecdh);
                keyParams.WriteByte(0x3);
                keyParams.WriteByte(0x1);
                keyParams.WriteByte((byte)ecParam.PublicKeyParameters.HashAlgorithm);
                keyParams.WriteByte((byte)ecParam.PublicKeyParameters.SymmetricKeyAlgorithm);
                keyParams.Write(_anonymousSender, 0, _anonymousSender.Length);
                keyParams.Write(ecParam.FingerPrint, 0, ecParam.FingerPrint.Length);

                var kBytes = keyParams.ToArray();
                var digest = DigestUtilities.GetDigest(ecParam.PublicKeyParameters.HashAlgorithm.ToString());
                digest.BlockUpdate(kBytes, 0, kBytes.Length);
                var hash = DigestUtilities.DoFinal(digest);
                var size = ecParam.PublicKeyParameters.SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.Aes256
                    ? 32 : ecParam.PublicKeyParameters.SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.Aes192
                    ? 24 : ecParam.PublicKeyParameters.SymmetricKeyAlgorithm == SymmetricKeyAlgorithmTag.Aes128
                    ? 16 : 0;                

                var wrap = new AesWrapEngine();
                wrap.Init(false, new KeyParameter(hash, 0, size));
                var symKey = wrap.Unwrap(encSymKey, 0, encSymKey.Length);
            }
        }

        private byte[] FetchSymmetricKeyData(IPgpPrivateKey privKey)
        {
            var c1 = GetKeyCipher(_keyData.Algorithm);

            try
            {
                c1.Init(false, privKey.Key);
            }
            catch (InvalidKeyException e)
            {
                throw new PgpException("error setting asymmetric cipher", e);
            }

            var keyD = _keyData.GetEncSessionKey();
            switch (_keyData.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaGeneral:
                case PublicKeyAlgorithmTag.RsaEncrypt:
                    this.ProcessSymmetricKeyDataForRsa(c1, keyD);
                    break;
                case PublicKeyAlgorithmTag.Ecdh:
                    this.ProcessSymmetricKeyDataForEcdh(privKey, c1, keyD);
                    break;
                default:
                    this.ProcessSymmetricKeyDataForElGamal(privKey, c1, keyD);
                    break;
            }

            byte[] plain;
            try
            {
                plain = c1.DoFinal();
            }
            catch (Exception e)
            {
                throw new PgpException("exception decrypting secret key", e);
            }

            if (!ConfirmCheckSum(plain))
                throw new PgpKeyValidationException("key checksum failed");

            return plain;
        }
    }
}
