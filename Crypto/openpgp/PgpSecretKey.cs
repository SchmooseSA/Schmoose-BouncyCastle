using System;
using System.Collections;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace Org.BouncyCastle.Bcpg.OpenPgp
{
    /// <remarks>General class to handle a PGP secret key object.</remarks>
    public class PgpSecretKey : IPgpSecretKey
    {
        private readonly ISecretKeyPacket _secret;
        private readonly IPgpPublicKey _pub;

        internal PgpSecretKey(ISecretKeyPacket secret, IPgpPublicKey pub)
        {
            _secret = secret;
            _pub = pub;
        }

        internal PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            ISecureRandom rand)
            : this(privKey, pubKey, encAlgorithm, passPhrase, useSha1, rand, false)
        {
        }

        internal PgpSecretKey(
            PgpPrivateKey privKey,
            PgpPublicKey pubKey,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            ISecureRandom rand,
            bool isMasterKey)
        {
            BcpgObject secKey;

            _pub = pubKey;

            switch (pubKey.Algorithm)
            {
                case PublicKeyAlgorithmTag.RsaEncrypt:
                case PublicKeyAlgorithmTag.RsaSign:
                case PublicKeyAlgorithmTag.RsaGeneral:
                    var rsK = (RsaPrivateCrtKeyParameters)privKey.Key;
                    secKey = new RsaSecretBcpgKey(rsK.Exponent, rsK.P, rsK.Q);
                    break;
                case PublicKeyAlgorithmTag.Dsa:
                    var dsK = (DsaPrivateKeyParameters)privKey.Key;
                    secKey = new DsaSecretBcpgKey(dsK.X);
                    break;
                case PublicKeyAlgorithmTag.ElGamalEncrypt:
                case PublicKeyAlgorithmTag.ElGamalGeneral:
                    var esK = (ElGamalPrivateKeyParameters)privKey.Key;
                    secKey = new ElGamalSecretBcpgKey(esK.X);
                    break;

                case PublicKeyAlgorithmTag.Ecdh:
                case PublicKeyAlgorithmTag.Ecdsa:
                    var ecK = (ECPrivateKeyParameters)privKey.Key;
                    secKey = new ECSecretBcpgKey(ecK.D);
                    break;

                default:
                    throw new PgpException("unknown key class");
            }

            try
            {
                using (var bOut = new MemoryStream())
                {

                    using (var pOut = new BcpgOutputStream(bOut))
                    {

                        pOut.WriteObject(secKey);

                        var keyData = bOut.ToArray();
                        var checksumBytes = Checksum(useSha1, keyData, keyData.Length);

                        pOut.Write(checksumBytes);

                        var bOutData = bOut.ToArray();

                        if (encAlgorithm == SymmetricKeyAlgorithmTag.Null)
                        {
                            this._secret = isMasterKey
                                ? new SecretKeyPacket(_pub.PublicKeyPacket, encAlgorithm, null, null, bOutData)
                                : new SecretSubkeyPacket(_pub.PublicKeyPacket, encAlgorithm, null, null, bOutData);
                        }
                        else
                        {
                            S2k s2K;
                            byte[] iv;
                            var encData = EncryptKeyData(bOutData, encAlgorithm, passPhrase, rand, out s2K, out iv);

                            var s2KUsage = useSha1 ? SecretKeyPacket.UsageSha1 : SecretKeyPacket.UsageChecksum;
                            this._secret = isMasterKey
                                ? new SecretKeyPacket(_pub.PublicKeyPacket, encAlgorithm, s2KUsage, s2K, iv, encData)
                                : new SecretSubkeyPacket(_pub.PublicKeyPacket, encAlgorithm, s2KUsage, s2K, iv, encData);
                        }
                    }
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception encrypting key", e);
            }
        }

        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            ISecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, passPhrase, false, hashedPackets, unhashedPackets, rand)
        {
        }

        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            ISecureRandom rand)
            : this(certificationLevel, keyPair, id, encAlgorithm, HashAlgorithmTag.Sha1, passPhrase, useSha1, hashedPackets, unhashedPackets, rand) { }

        public PgpSecretKey(
            int certificationLevel,
            PgpKeyPair keyPair,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            HashAlgorithmTag hashAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            ISecureRandom rand)
            : this(keyPair.PrivateKey, CertifiedPublicKey(certificationLevel, keyPair, id, hashedPackets, unhashedPackets, hashAlgorithm), encAlgorithm, passPhrase, useSha1, rand, true)
        {
        }

        private static PgpPublicKey CertifiedPublicKey(
            int certificationLevel, 
            PgpKeyPair keyPair, 
            string id, 
            PgpSignatureSubpacketVector hashedPackets, 
            PgpSignatureSubpacketVector unhashedPackets, 
            HashAlgorithmTag hashAlgorithm)
        {
            PgpSignatureGenerator sGen;
            try
            {
                sGen = new PgpSignatureGenerator(keyPair.PublicKey.Algorithm, hashAlgorithm);
            }
            catch (Exception e)
            {
                throw new PgpException("Creating signature generator: " + e.Message, e);
            }

            //
            // Generate the certification
            //
            sGen.InitSign(certificationLevel, keyPair.PrivateKey);

            sGen.SetHashedSubpackets(hashedPackets);
            sGen.SetUnhashedSubpackets(unhashedPackets);

            try
            {
                PgpSignature certification = sGen.GenerateCertification(id, keyPair.PublicKey);
                return PgpPublicKey.AddCertification(keyPair.PublicKey, id, certification);
            }
            catch (Exception e)
            {
                throw new PgpException("Exception doing certification: " + e.Message, e);
            }
        }

        public PgpSecretKey(
            int certificationLevel,
            PublicKeyAlgorithmTag algorithm,
            IAsymmetricKeyParameter pubKey,
            IAsymmetricKeyParameter privKey,
            DateTime time,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel,
                new PgpKeyPair(algorithm, pubKey, privKey, time),
                id, encAlgorithm, passPhrase, hashedPackets, unhashedPackets, rand)
        {
        }

        public PgpSecretKey(
            int certificationLevel,
            PublicKeyAlgorithmTag algorithm,
            IAsymmetricKeyParameter pubKey,
            IAsymmetricKeyParameter privKey,
            DateTime time,
            string id,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            bool useSha1,
            PgpSignatureSubpacketVector hashedPackets,
            PgpSignatureSubpacketVector unhashedPackets,
            SecureRandom rand)
            : this(certificationLevel, new PgpKeyPair(algorithm, pubKey, privKey, time), id, encAlgorithm, passPhrase, useSha1, hashedPackets, unhashedPackets, rand)
        {
        }

        /// <summary>
        /// Check if this key has an algorithm type that makes it suitable to use for signing.
        /// </summary>
        /// <remarks>
        /// Note: with version 4 keys KeyFlags subpackets should also be considered when present for
        /// determining the preferred use of the key.
        /// </remarks>
        /// <returns>
        /// <c>true</c> if this key algorithm is suitable for use with signing.
        /// </returns>
        public bool IsSigningKey
        {
            get
            {
                switch (_pub.Algorithm)
                {
                    case PublicKeyAlgorithmTag.RsaGeneral:
                    case PublicKeyAlgorithmTag.RsaSign:
                    case PublicKeyAlgorithmTag.Dsa:
                    case PublicKeyAlgorithmTag.Ecdsa:
                    case PublicKeyAlgorithmTag.ElGamalGeneral:
                        return true;
                    default:
                        return false;
                }
            }
        }

        /// <summary>True, if this is a master key.</summary>
        public bool IsMasterKey
        {
            get { return _pub.IsMasterKey; }
        }

        /// <summary>The algorithm the key is encrypted with.</summary>
        public SymmetricKeyAlgorithmTag KeyEncryptionAlgorithm
        {
            get { return _secret.EncAlgorithm; }
        }

        /// <summary>The key ID of the public key associated with this key.</summary>
        public long KeyId
        {
            get { return _pub.KeyId; }
        }

        /// <summary>The public key associated with this key.</summary>
        public IPgpPublicKey PublicKey
        {
            get { return _pub; }
        }

        public ISecretKeyPacket SecretPacket 
        {
            get { return _secret; }
        }

        /// <summary>Allows enumeration of any user IDs associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable UserIds
        {
            get { return _pub.GetUserIds(); }
        }

        /// <summary>Allows enumeration of any user attribute vectors associated with the key.</summary>
        /// <returns>An <c>IEnumerable</c> of <c>string</c> objects.</returns>
        public IEnumerable UserAttributes
        {
            get { return _pub.GetUserAttributes(); }
        }

        public byte[] ExtractKeyData(char[] passPhrase)
        {
            var alg = _secret.EncAlgorithm;
            var encData = _secret.GetSecretKeyData();

            if (alg == SymmetricKeyAlgorithmTag.Null)
                return encData;

            IBufferedCipher c;
            try
            {
                var cName = PgpUtilities.GetSymmetricCipherName(alg);
                c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

            // TODO Factor this block out as 'encryptData'
            try
            {
                var key = PgpUtilities.MakeKeyFromPassPhrase(_secret.EncAlgorithm, _secret.S2K, passPhrase);
                var iv = _secret.GetIV();

                byte[] data;
                if (_secret.PublicKeyPacket.Version == 4)
                {
                    c.Init(false, new ParametersWithIV(key, iv));

                    data = c.DoFinal(encData);

                    var useSha1 = _secret.S2KUsage == SecretKeyPacket.UsageSha1;
                    var check = Checksum(useSha1, data, (useSha1) ? data.Length - 20 : data.Length - 2);

                    for (var i = 0; i != check.Length; i++)
                    {
                        if (check[i] != data[data.Length - check.Length + i])
                        {
                            throw new PgpException("Checksum mismatch at " + i + " of " + check.Length);
                        }
                    }
                }
                else // version 2 or 3, RSA only.
                {
                    data = new byte[encData.Length];

                    //
                    // read in the four numbers
                    //
                    var pos = 0;

                    for (var i = 0; i != 4; i++)
                    {
                        c.Init(false, new ParametersWithIV(key, iv));

                        var encLen = (((encData[pos] << 8) | (encData[pos + 1] & 0xff)) + 7) / 8;

                        data[pos] = encData[pos];
                        data[pos + 1] = encData[pos + 1];
                        pos += 2;

                        c.DoFinal(encData, pos, encLen, data, pos);
                        pos += encLen;

                        if (i != 3)
                        {
                            Array.Copy(encData, pos - iv.Length, iv, 0, iv.Length);
                        }
                    }

                    //
                    // verify Checksum
                    //
                    var cs = ((encData[pos] << 8) & 0xff00) | (encData[pos + 1] & 0xff);
                    var calcCs = 0;
                    for (var j = 0; j < data.Length - 2; j++)
                    {
                        calcCs += data[j] & 0xff;
                    }

                    calcCs &= 0xffff;
                    if (calcCs != cs)
                    {
                        throw new PgpException("Checksum mismatch: passphrase wrong, expected "
                            + cs.ToString("X")
                            + " found " + calcCs.ToString("X"));
                    }
                }

                return data;
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception decrypting key", e);
            }
        }

        /// <summary>
        /// Extract a <c>PgpPrivateKey</c> from this secret key's encrypted contents.
        /// </summary>
        /// <param name="passPhrase"></param>
        /// <returns></returns>
        /// <exception cref="PgpException">
        /// unknown public key algorithm encountered
        /// or
        /// Exception constructing key
        /// </exception>
        public IPgpPrivateKey ExtractPrivateKey(char[] passPhrase)
        {
            var secKeyData = _secret.GetSecretKeyData();
            if (secKeyData == null || secKeyData.Length < 1)
                return null;

            var pubPk = _secret.PublicKeyPacket;
            try
            {
                var data = ExtractKeyData(passPhrase);
                using (var memory = new MemoryStream(data, false))
                {
                    using (var bcpgIn = BcpgInputStream.Wrap(memory))
                    {
                        IAsymmetricKeyParameter privateKey;
                        switch (pubPk.Algorithm)
                        {
                            case PublicKeyAlgorithmTag.RsaEncrypt:
                            case PublicKeyAlgorithmTag.RsaGeneral:
                            case PublicKeyAlgorithmTag.RsaSign:
                                var rsaPub = (RsaPublicBcpgKey)pubPk.Key;
                                var rsaPriv = new RsaSecretBcpgKey(bcpgIn);
                                var rsaPrivSpec = new RsaPrivateCrtKeyParameters(
                                    rsaPriv.Modulus,
                                    rsaPub.PublicExponent,
                                    rsaPriv.PrivateExponent,
                                    rsaPriv.PrimeP,
                                    rsaPriv.PrimeQ,
                                    rsaPriv.PrimeExponentP,
                                    rsaPriv.PrimeExponentQ,
                                    rsaPriv.CrtCoefficient);
                                privateKey = rsaPrivSpec;
                                break;
                            case PublicKeyAlgorithmTag.Dsa:
                                var dsaPub = (DsaPublicBcpgKey)pubPk.Key;
                                var dsaPriv = new DsaSecretBcpgKey(bcpgIn);
                                var dsaParams = new DsaParameters(dsaPub.P, dsaPub.Q, dsaPub.G);
                                privateKey = new DsaPrivateKeyParameters(dsaPriv.X, dsaParams);
                                break;
                            case PublicKeyAlgorithmTag.ElGamalEncrypt:
                            case PublicKeyAlgorithmTag.ElGamalGeneral:
                                var elPub = (ElGamalPublicBcpgKey)pubPk.Key;
                                var elPriv = new ElGamalSecretBcpgKey(bcpgIn);
                                var elParams = new ElGamalParameters(elPub.P, elPub.G);
                                privateKey = new ElGamalPrivateKeyParameters(elPriv.X, elParams);
                                break;
                            case PublicKeyAlgorithmTag.Ecdh:
                                var ecdhPub = (ECDHPublicBcpgKey)pubPk.Key;
                                var ecdhPriv = new ECSecretBcpgKey(bcpgIn);
                                privateKey = new ECDHPrivateKeyParameters(ecdhPriv.X,
                                    new ECDHPublicKeyParameters(ecdhPub.Point, ecdhPub.Oid, ecdhPub.HashAlgorithm, ecdhPub.SymmetricKeyAlgorithm), 
                                    PgpPublicKey.BuildFingerprint(pubPk));
                                break;
                            case PublicKeyAlgorithmTag.Ecdsa:
                                var ecdsaPub = (ECPublicBcpgKey)pubPk.Key;
                                var ecdsaPriv = new ECSecretBcpgKey(bcpgIn);
                                privateKey = new ECPrivateKeyParameters(pubPk.Algorithm.ToString(), ecdsaPriv.X, ecdsaPub.Oid);
                                break;
                            default:
                                throw new PgpException("unknown public key algorithm encountered");
                        }

                        return new PgpPrivateKey(privateKey, KeyId);
                    }
                }
            }
            catch (PgpException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new PgpException("Exception constructing key", e);
            }
        }

        /// <summary>
        /// Calculates a checksum over the input bytes.
        /// </summary>
        /// <param name="useSha1">if set to <c>true</c> [use sha1].</param>
        /// <param name="bytes">The bytes.</param>
        /// <param name="length">The length.</param>
        /// <returns></returns>
        /// <exception cref="PgpException">Can't find SHA-1</exception>
        private static byte[] Checksum(bool useSha1, byte[] bytes, int length)
        {
            if (useSha1)
            {
                try
                {
                    var dig = DigestUtilities.GetDigest("SHA1");
                    dig.BlockUpdate(bytes, 0, length);
                    return DigestUtilities.DoFinal(dig);
                }
                //catch (NoSuchAlgorithmException e)
                catch (Exception e)
                {
                    throw new PgpException("Can't find SHA-1", e);
                }
            }
            var checksum = 0;
            for (var i = 0; i != length; i++)
            {
                checksum += bytes[i];
            }

            return new[] { (byte)(checksum >> 8), (byte)checksum };
        }

        public byte[] GetEncoded()
        {
            using (var bOut = new MemoryStream())
            {
                Encode(bOut);
                return bOut.ToArray();
            }
        }

        public void Encode(Stream outStr)
        {
            var bcpgOut = BcpgOutputStream.Wrap(outStr);


            bcpgOut.WritePacket(_secret);
            if (_pub.TrustPaket != null)
            {
                bcpgOut.WritePacket(_pub.TrustPaket);
            }

            if (_pub.SubSigs == null) // is not a sub key
            {
                foreach (PgpSignature keySig in _pub.KeySigs)
                {
                    keySig.Encode(bcpgOut);
                }

                for (var i = 0; i != _pub.Ids.Count; i++)
                {
                    var pubId = _pub.Ids[i];

                    if (pubId is string)
                    {
                        var id = (string)pubId;
                        bcpgOut.WritePacket(new UserIdPacket(id));
                    }
                    else
                    {
                        var v = (PgpUserAttributeSubpacketVector)pubId;
                        bcpgOut.WritePacket(new UserAttributePacket(v.ToSubpacketArray()));
                    }

                    if (_pub.IdTrusts[i] != null)
                    {
                        bcpgOut.WritePacket((ContainedPacket)_pub.IdTrusts[i]);
                    }

                    foreach (PgpSignature sig in (IList)_pub.IdSigs[i])
                    {
                        sig.Encode(bcpgOut);
                    }
                }
            }
            else
            {
                foreach (PgpSignature subSig in _pub.SubSigs)
                {
                    subSig.Encode(bcpgOut);
                }
            }
        }

        /// <summary>
        /// Return a copy of the passed in secret key, encrypted using a new password
        /// and the passed in algorithm.
        /// </summary>
        /// <param name="key">The PgpSecretKey to be copied.</param>
        /// <param name="oldPassPhrase">The current password for the key.</param>
        /// <param name="newPassPhrase">The new password for the key.</param>
        /// <param name="newEncAlgorithm">The algorithm to be used for the encryption.</param>
        /// <param name="rand">Source of randomness.</param>
        public static PgpSecretKey CopyWithNewPassword(
            IPgpSecretKey key,
            char[] oldPassPhrase,
            char[] newPassPhrase,
            SymmetricKeyAlgorithmTag newEncAlgorithm,
            SecureRandom rand)
        {
            var rawKeyData = key.ExtractKeyData(oldPassPhrase);
            var s2KUsage = key.SecretPacket.S2KUsage;
            byte[] iv = null;
            S2k s2K = null;
            byte[] keyData;

            if (newEncAlgorithm == SymmetricKeyAlgorithmTag.Null)
            {
                s2KUsage = SecretKeyPacket.UsageNone;
                if (key.SecretPacket.S2KUsage == SecretKeyPacket.UsageSha1)   // SHA-1 hash, need to rewrite Checksum
                {
                    keyData = new byte[rawKeyData.Length - 18];

                    Array.Copy(rawKeyData, 0, keyData, 0, keyData.Length - 2);

                    var check = Checksum(false, keyData, keyData.Length - 2);

                    keyData[keyData.Length - 2] = check[0];
                    keyData[keyData.Length - 1] = check[1];
                }
                else
                {
                    keyData = rawKeyData;
                }
            }
            else
            {
                try
                {
                    keyData = EncryptKeyData(rawKeyData, newEncAlgorithm, newPassPhrase, rand, out s2K, out iv);
                }
                catch (PgpException)
                {
                    throw;
                }
                catch (Exception e)
                {
                    throw new PgpException("Exception encrypting key", e);
                }
            }

            SecretKeyPacket secret;
            if (key.SecretPacket is SecretSubkeyPacket)
            {
                secret = new SecretSubkeyPacket(key.SecretPacket.PublicKeyPacket,
                    newEncAlgorithm, s2KUsage, s2K, iv, keyData);
            }
            else
            {
                secret = new SecretKeyPacket(key.SecretPacket.PublicKeyPacket,
                    newEncAlgorithm, s2KUsage, s2K, iv, keyData);
            }

            return new PgpSecretKey(secret, key.PublicKey);
        }

        /// <summary>Replace the passed public key on the passed in secret key.</summary>
        /// <param name="secretKey">Secret key to change.</param>
        /// <param name="publicKey">New public key.</param>
        /// <returns>A new secret key.</returns>
        /// <exception cref="ArgumentException">If KeyId's do not match.</exception>
        public static PgpSecretKey ReplacePublicKey(PgpSecretKey secretKey, IPgpPublicKey publicKey)
        {
            if (publicKey.KeyId != secretKey.KeyId)
                throw new ArgumentException("KeyId's do not match");

            return new PgpSecretKey(secretKey.SecretPacket, publicKey);
        }

        private static byte[] EncryptKeyData(
            byte[] rawKeyData,
            SymmetricKeyAlgorithmTag encAlgorithm,
            char[] passPhrase,
            ISecureRandom random,
            out S2k s2K,
            out byte[] iv)
        {
            IBufferedCipher c;
            try
            {
                var cName = PgpUtilities.GetSymmetricCipherName(encAlgorithm);
                c = CipherUtilities.GetCipher(cName + "/CFB/NoPadding");
            }
            catch (Exception e)
            {
                throw new PgpException("Exception creating cipher", e);
            }

            var s2KIv = new byte[8];
            random.NextBytes(s2KIv);
            s2K = new S2k(HashAlgorithmTag.Sha1, s2KIv, 0x60);

            var kp = PgpUtilities.MakeKeyFromPassPhrase(encAlgorithm, s2K, passPhrase);

            iv = new byte[c.GetBlockSize()];
            random.NextBytes(iv);

            c.Init(true, new ParametersWithRandom(new ParametersWithIV(kp, iv), random));

            return c.DoFinal(rawKeyData);
        }
    }
}
