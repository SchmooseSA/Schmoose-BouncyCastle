using System;
using System.Collections;
using System.Diagnostics;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>Generator for encrypted objects.</remarks>
    public class PgpEncryptedDataGenerator : IStreamGenerator
    {
        private readonly SymmetricKeyAlgorithmTag _defAlgorithm;
        private readonly IList _methods = Platform.CreateArrayList();
        private readonly bool _oldFormat;
        private readonly SecureRandom _rand;
        private readonly bool _withIntegrityPacket;
        private IBufferedCipher _c;
        private CipherStream _cOut;
        private DigestStream _digestOut;
        private BcpgOutputStream _pOut;

        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm)
        {
            _defAlgorithm = encAlgorithm;
            _rand = new SecureRandom();
        }

        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            bool withIntegrityPacket)
        {
            _defAlgorithm = encAlgorithm;
            this._withIntegrityPacket = withIntegrityPacket;
            _rand = new SecureRandom();
        }

        /// <summary>Existing SecureRandom constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="rand">Source of randomness.</param>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            SecureRandom rand)
        {
            _defAlgorithm = encAlgorithm;
            this._rand = rand;
        }

        /// <summary>Creates a cipher stream which will have an integrity packet associated with it.</summary>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            bool withIntegrityPacket,
            SecureRandom rand)
        {
            _defAlgorithm = encAlgorithm;
            this._rand = rand;
            this._withIntegrityPacket = withIntegrityPacket;
        }

        /// <summary>Base constructor.</summary>
        /// <param name="encAlgorithm">The symmetric algorithm to use.</param>
        /// <param name="rand">Source of randomness.</param>
        /// <param name="oldFormat">PGP 2.6.x compatibility required.</param>
        public PgpEncryptedDataGenerator(
            SymmetricKeyAlgorithmTag encAlgorithm,
            SecureRandom rand,
            bool oldFormat)
        {
            _defAlgorithm = encAlgorithm;
            this._rand = rand;
            this._oldFormat = oldFormat;
        }

        /// <summary>
        ///     <p>
        ///         Close off the encrypted object - this is equivalent to calling Close() on the stream
        ///         returned by the Open() method.
        ///     </p>
        ///     <p>
        ///         <b>Note</b>: This does not close the underlying output stream, only the stream on top of
        ///         it created by the Open() method.
        ///     </p>
        /// </summary>
        public void Close()
        {
            if (_cOut != null)
            {
                // TODO Should this all be under the try/catch block?
                if (_digestOut != null)
                {
                    //
                    // hand code a mod detection packet
                    //
                    var bOut = new BcpgOutputStream(
                        _digestOut, PacketTag.ModificationDetectionCode, 20);

                    bOut.Flush();
                    _digestOut.Flush();

                    // TODO
                    byte[] dig = DigestUtilities.DoFinal(_digestOut.WriteDigest());
                    _cOut.Write(dig, 0, dig.Length);
                }

                _cOut.Flush();

                try
                {
                    _pOut.Write(_c.DoFinal());
                    _pOut.Finish();
                }
                catch (Exception e)
                {
                    throw new IOException(e.Message, e);
                }

                _cOut = null;
                _pOut = null;
            }
        }

        /// <summary>
        ///     Add a PBE encryption method to the encrypted object using the default algorithm (S2K_SHA1).
        /// </summary>
        public void AddMethod(char[] passPhrase)
        {
            AddMethod(passPhrase, HashAlgorithmTag.Sha1);
        }

        /// <summary>Add a PBE encryption method to the encrypted object.</summary>
        public void AddMethod(char[] passPhrase, HashAlgorithmTag s2KDigest)
        {
            var iv = new byte[8];
            _rand.NextBytes(iv);

            var s2K = new S2k(s2KDigest, iv, 0x60);
            _methods.Add(new PbeMethod(_defAlgorithm, s2K, PgpUtilities.MakeKeyFromPassPhrase(_defAlgorithm, s2K, passPhrase)));
        }

        /// <summary>Add a public key encrypted session key to the encrypted object.</summary>
        public void AddMethod(IPgpPublicKey key)
        {
            if (!key.IsEncryptionKey)
            {
                throw new ArgumentException("passed in key not an encryption key!");
            }

            _methods.Add(new PubMethod(key));
        }

        private static void AddCheckSum(byte[] sessionInfo)
        {
            Debug.Assert(sessionInfo != null);
            Debug.Assert(sessionInfo.Length >= 3);

            int check = 0;

            for (int i = 1; i < sessionInfo.Length - 2; i++)
            {
                check += sessionInfo[i];
            }

            sessionInfo[sessionInfo.Length - 2] = (byte)(check >> 8);
            sessionInfo[sessionInfo.Length - 1] = (byte)(check);
        }

        private byte[] CreateSessionInfo(
            SymmetricKeyAlgorithmTag algorithm,
            KeyParameter key)
        {
            byte[] keyBytes = key.GetKey();
            var sessionInfo = new byte[keyBytes.Length + 3];
            sessionInfo[0] = (byte)algorithm;
            keyBytes.CopyTo(sessionInfo, 1);
            AddCheckSum(sessionInfo);
            return sessionInfo;
        }

        /// <summary>
        ///     <p>
        ///         If buffer is non null stream assumed to be partial, otherwise the length will be used
        ///         to output a fixed length packet.
        ///     </p>
        ///     <p>
        ///         The stream created can be closed off by either calling Close()
        ///         on the stream or Close() on the generator. Closing the returned
        ///         stream does not close off the Stream parameter <c>outStr</c>.
        ///     </p>
        /// </summary>
        private Stream Open(
            Stream outStr,
            long length,
            byte[] buffer)
        {
            if (_cOut != null)
                throw new InvalidOperationException("generator already in open state");
            if (_methods.Count == 0)
                throw new InvalidOperationException("No encryption methods specified");
            if (outStr == null)
                throw new ArgumentNullException("outStr");

            _pOut = new BcpgOutputStream(outStr);

            KeyParameter key;

            if (_methods.Count == 1)
            {
                var pbeMethod = _methods[0] as PbeMethod;
                if (pbeMethod != null)
                {
                    key = pbeMethod.GetKey();
                }
                else
                {
                    key = PgpUtilities.MakeRandomKey(_defAlgorithm, _rand);

                    var sessionInfo = CreateSessionInfo(_defAlgorithm, key);
                    var pubMethod = (PubMethod)_methods[0];

                    try
                    {
                        pubMethod.AddSessionInfo(sessionInfo, _rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }
                }

                _pOut.WritePacket((ContainedPacket)_methods[0]);
            }
            else // multiple methods
            {
                key = PgpUtilities.MakeRandomKey(_defAlgorithm, _rand);
                byte[] sessionInfo = CreateSessionInfo(_defAlgorithm, key);

                for (int i = 0; i != _methods.Count; i++)
                {
                    var m = (EncMethod)_methods[i];

                    try
                    {
                        m.AddSessionInfo(sessionInfo, _rand);
                    }
                    catch (Exception e)
                    {
                        throw new PgpException("exception encrypting session key", e);
                    }

                    _pOut.WritePacket(m);
                }
            }

            string cName = PgpUtilities.GetSymmetricCipherName(_defAlgorithm);
            if (cName == null)
            {
                throw new PgpException("null cipher specified");
            }

            try
            {
                if (_withIntegrityPacket)
                {
                    cName += "/CFB/NoPadding";
                }
                else
                {
                    cName += "/OpenPGPCFB/NoPadding";
                }

                _c = CipherUtilities.GetCipher(cName);

                // TODO Confirm the IV should be all zero bytes (not inLineIv - see below)
                var iv = new byte[_c.GetBlockSize()];
                _c.Init(true, new ParametersWithRandom(new ParametersWithIV(key, iv), _rand));

                if (buffer == null)
                {
                    //
                    // we have to Add block size + 2 for the Generated IV and + 1 + 22 if integrity protected
                    //
                    if (_withIntegrityPacket)
                    {
                        _pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected,
                                                    length + _c.GetBlockSize() + 2 + 1 + 22);
                        _pOut.WriteByte(1); // version number
                    }
                    else
                    {
                        _pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted,
                                                    length + _c.GetBlockSize() + 2, _oldFormat);
                    }
                }
                else
                {
                    if (_withIntegrityPacket)
                    {
                        _pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricEncryptedIntegrityProtected, buffer);
                        _pOut.WriteByte(1); // version number
                    }
                    else
                    {
                        _pOut = new BcpgOutputStream(outStr, PacketTag.SymmetricKeyEncrypted, buffer);
                    }
                }

                int blockSize = _c.GetBlockSize();
                var inLineIv = new byte[blockSize + 2];
                _rand.NextBytes(inLineIv, 0, blockSize);
                Array.Copy(inLineIv, inLineIv.Length - 4, inLineIv, inLineIv.Length - 2, 2);

                Stream myOut = _cOut = new CipherStream(_pOut, null, _c);

                if (_withIntegrityPacket)
                {
                    string digestName = PgpUtilities.GetDigestName(HashAlgorithmTag.Sha1);
                    IDigest digest = DigestUtilities.GetDigest(digestName);
                    myOut = _digestOut = new DigestStream(myOut, null, digest);
                }

                myOut.Write(inLineIv, 0, inLineIv.Length);

                return new WrappedGeneratorStream(this, myOut);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }
        }

        /// <summary>
        ///     <p>
        ///         Return an output stream which will encrypt the data as it is written to it.
        ///     </p>
        ///     <p>
        ///         The stream created can be closed off by either calling Close()
        ///         on the stream or Close() on the generator. Closing the returned
        ///         stream does not close off the Stream parameter <c>outStr</c>.
        ///     </p>
        /// </summary>
        public Stream Open(
            Stream outStr,
            long length)
        {
            return Open(outStr, length, null);
        }

        /// <summary>
        ///     <p>
        ///         Return an output stream which will encrypt the data as it is written to it.
        ///         The stream will be written out in chunks according to the size of the passed in buffer.
        ///     </p>
        ///     <p>
        ///         The stream created can be closed off by either calling Close()
        ///         on the stream or Close() on the generator. Closing the returned
        ///         stream does not close off the Stream parameter <c>outStr</c>.
        ///     </p>
        ///     <p>
        ///         <b>Note</b>: if the buffer is not a power of 2 in length only the largest power of 2
        ///         bytes worth of the buffer will be used.
        ///     </p>
        /// </summary>
        public Stream Open(
            Stream outStr,
            byte[] buffer)
        {
            return Open(outStr, 0, buffer);
        }

        private abstract class EncMethod : ContainedPacket
        {
            protected SymmetricKeyAlgorithmTag EncAlgorithm;
            protected KeyParameter Key;
            protected byte[] SessionInfo;

            public abstract void AddSessionInfo(byte[] si, SecureRandom random);
        }

        private class PbeMethod : EncMethod
        {
            private readonly S2k _s2K;

            internal PbeMethod(SymmetricKeyAlgorithmTag encAlgorithm, S2k s2K, KeyParameter key)
            {
                this.EncAlgorithm = encAlgorithm;
                this._s2K = s2K;
                this.Key = key;
            }

            public KeyParameter GetKey()
            {
                return Key;
            }

            public override void AddSessionInfo(byte[] si, SecureRandom random)
            {
                var cName = PgpUtilities.GetSymmetricCipherName(EncAlgorithm);
                var c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");

                var iv = new byte[c.GetBlockSize()];
                c.Init(true, new ParametersWithRandom(new ParametersWithIV(Key, iv), random));

                SessionInfo = c.DoFinal(si, 0, si.Length - 2);
            }

            public override void Encode(IBcpgOutputStream pOut)
            {
                var pk = new SymmetricKeyEncSessionPacket(
                    EncAlgorithm, _s2K, SessionInfo);

                pOut.WritePacket(pk);
            }
        }

        private class PubMethod : EncMethod
        {
            private readonly IPgpPublicKey _pubKey;
            private BigInteger[] _data;

            internal PubMethod(IPgpPublicKey pubKey)
            {
                _pubKey = pubKey;
            }

            public override void AddSessionInfo(byte[] si, SecureRandom random)
            {
                IBufferedCipher c;

                switch (_pubKey.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        c = CipherUtilities.GetCipher("RSA//PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        c = CipherUtilities.GetCipher("ElGamal/ECB/PKCS1Padding");
                        break;
                    case PublicKeyAlgorithmTag.Dsa:
                        throw new PgpException("Can't use DSA for encryption.");
                    case PublicKeyAlgorithmTag.Ecdsa:
                        throw new PgpException("Can't use ECDSA for encryption.");
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + _pubKey.Algorithm);
                }

                var akp = _pubKey.GetKey();

                c.Init(true, new ParametersWithRandom(akp, random));

                var encKey = c.DoFinal(si);
                switch (_pubKey.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaEncrypt:
                    case PublicKeyAlgorithmTag.RsaGeneral:
                        _data = new[] { new BigInteger(1, encKey) };
                        break;
                    case PublicKeyAlgorithmTag.ElGamalEncrypt:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        var halfLength = encKey.Length / 2;
                        _data = new[]
                                   {
                                       new BigInteger(1, encKey, 0, halfLength),
                                       new BigInteger(1, encKey, halfLength, halfLength)
                                   };
                        break;
                    default:
                        throw new PgpException("unknown asymmetric algorithm: " + EncAlgorithm);
                }
            }

            public override void Encode(IBcpgOutputStream pOut)
            {
                var pk = new PublicKeyEncSessionPacket(_pubKey.KeyId, _pubKey.Algorithm, _data);
                pOut.WritePacket(pk);
            }
        }
    }
}