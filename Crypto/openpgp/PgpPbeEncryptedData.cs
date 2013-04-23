using System;
using System.IO;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>A password based encryption object.</remarks>
    public class PgpPbeEncryptedData : PgpEncryptedData
    {
        private readonly SymmetricKeyEncSessionPacket _keyData;

        internal PgpPbeEncryptedData(SymmetricKeyEncSessionPacket keyData, InputStreamPacket encData)
            : base(encData)
        {
            _keyData = keyData;
        }

        /// <summary>Return the raw input stream for the data stream.</summary>
        public override Stream GetInputStream()
        {
            return EncData.GetInputStream();
        }

        /// <summary>Return the decrypted input stream, using the passed in passphrase.</summary>
        public Stream GetDataStream(char[] passPhrase)
        {
            try
            {
                var keyAlgorithm = _keyData.EncAlgorithm;

                var key = PgpUtilities.MakeKeyFromPassPhrase(
                    keyAlgorithm, _keyData.S2K, passPhrase);


                var secKeyData = _keyData.GetSecKeyData();
                if (secKeyData != null && secKeyData.Length > 0)
                {
                    var keyCipher = CipherUtilities.GetCipher(
                        PgpUtilities.GetSymmetricCipherName(keyAlgorithm) + "/CFB/NoPadding");

                    keyCipher.Init(false,
                        new ParametersWithIV(key, new byte[keyCipher.GetBlockSize()]));

                    var keyBytes = keyCipher.DoFinal(secKeyData);

                    keyAlgorithm = (SymmetricKeyAlgorithmTag)keyBytes[0];

                    key = ParameterUtilities.CreateKeyParameter(
                        PgpUtilities.GetSymmetricCipherName(keyAlgorithm),
                        keyBytes, 1, keyBytes.Length - 1);
                }


                var c = CreateStreamCipher(keyAlgorithm);

                var iv = new byte[c.GetBlockSize()];

                c.Init(false, new ParametersWithIV(key, iv));

                EncStream = BcpgInputStream.Wrap(new CipherStream(EncData.GetInputStream(), c, null));

                if (EncData is SymmetricEncIntegrityPacket)
                {
                    TruncStream = new TruncatedStream(EncStream);

                    var digestName = PgpUtilities.GetDigestName(HashAlgorithmTag.Sha1);
                    var digest = DigestUtilities.GetDigest(digestName);

                    EncStream = new DigestStream(TruncStream, digest, null);
                }

                if (Streams.ReadFully(EncStream, iv, 0, iv.Length) < iv.Length)
                    throw new EndOfStreamException("unexpected end of stream.");

                var v1 = EncStream.ReadByte();
                var v2 = EncStream.ReadByte();

                if (v1 < 0 || v2 < 0)
                    throw new EndOfStreamException("unexpected end of stream.");


                // Note: the oracle attack on the "quick check" bytes is not deemed
                // a security risk for PBE (see PgpPublicKeyEncryptedData)

                var repeatCheckPassed =
                        iv[iv.Length - 2] == (byte)v1
                    && iv[iv.Length - 1] == (byte)v2;

                // Note: some versions of PGP appear to produce 0 for the extra
                // bytes rather than repeating the two previous bytes
                var zeroesCheckPassed = v1 == 0 && v2 == 0;
                if (!repeatCheckPassed && !zeroesCheckPassed)
                {
                    throw new PgpDataValidationException("quick check failed.");
                }


                return EncStream;
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

        private IBufferedCipher CreateStreamCipher(SymmetricKeyAlgorithmTag keyAlgorithm)
        {
            var mode = (EncData is SymmetricEncIntegrityPacket)
                ? "CFB"
                : "OpenPGPCFB";
            return CipherUtilities.GetCipher(PgpUtilities.GetSymmetricCipherName(keyAlgorithm) + "/" + mode + "/NoPadding");
        }
    }
}
