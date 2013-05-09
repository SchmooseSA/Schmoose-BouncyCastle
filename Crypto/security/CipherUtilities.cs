using System;
using System.Collections;
using System.Globalization;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.CryptoPro;
using Org.BouncyCastle.Asn1.Kisa;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Ntt;
using Org.BouncyCastle.Asn1.Oiw;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Utilities;

namespace Org.BouncyCastle.Security
{
    /// <remarks>
    ///     Cipher Utility class contains methods that can not be specifically grouped into other classes.
    /// </remarks>
    public static class CipherUtilities
    {
        private static readonly IDictionary _algorithms = Platform.CreateHashtable();
        private static readonly IDictionary _oids = Platform.CreateHashtable();

        static CipherUtilities()
        {
            // Signal to obfuscation tools not to change enum constants
            ((CipherAlgorithm) Enums.GetArbitraryValue(typeof (CipherAlgorithm))).ToString();
            ((CipherMode) Enums.GetArbitraryValue(typeof (CipherMode))).ToString();
            ((CipherPadding) Enums.GetArbitraryValue(typeof (CipherPadding))).ToString();

            // TODO Flesh out the list of aliases

            _algorithms[NistObjectIdentifiers.IdAes128Ecb.Id] = "AES/ECB/PKCS7PADDING";
            _algorithms[NistObjectIdentifiers.IdAes192Ecb.Id] = "AES/ECB/PKCS7PADDING";
            _algorithms[NistObjectIdentifiers.IdAes256Ecb.Id] = "AES/ECB/PKCS7PADDING";
            _algorithms["AES//PKCS7"] = "AES/ECB/PKCS7PADDING";
            _algorithms["AES//PKCS7PADDING"] = "AES/ECB/PKCS7PADDING";
            _algorithms["AES//PKCS5"] = "AES/ECB/PKCS7PADDING";
            _algorithms["AES//PKCS5PADDING"] = "AES/ECB/PKCS7PADDING";

            _algorithms[NistObjectIdentifiers.IdAes128Cbc.Id] = "AES/CBC/PKCS7PADDING";
            _algorithms[NistObjectIdentifiers.IdAes192Cbc.Id] = "AES/CBC/PKCS7PADDING";
            _algorithms[NistObjectIdentifiers.IdAes256Cbc.Id] = "AES/CBC/PKCS7PADDING";

            _algorithms[NistObjectIdentifiers.IdAes128Ofb.Id] = "AES/OFB/NOPADDING";
            _algorithms[NistObjectIdentifiers.IdAes192Ofb.Id] = "AES/OFB/NOPADDING";
            _algorithms[NistObjectIdentifiers.IdAes256Ofb.Id] = "AES/OFB/NOPADDING";

            _algorithms[NistObjectIdentifiers.IdAes128Cfb.Id] = "AES/CFB/NOPADDING";
            _algorithms[NistObjectIdentifiers.IdAes192Cfb.Id] = "AES/CFB/NOPADDING";
            _algorithms[NistObjectIdentifiers.IdAes256Cfb.Id] = "AES/CFB/NOPADDING";

            _algorithms["RSA/ECB/PKCS1"] = "RSA//PKCS1PADDING";
            _algorithms["RSA/ECB/PKCS1PADDING"] = "RSA//PKCS1PADDING";
            _algorithms[PkcsObjectIdentifiers.RsaEncryption.Id] = "RSA//PKCS1PADDING";
            _algorithms[PkcsObjectIdentifiers.IdRsaesOaep.Id] = "RSA//OAEPPADDING";

            _algorithms[OiwObjectIdentifiers.DesCbc.Id] = "DES/CBC";
            _algorithms[OiwObjectIdentifiers.DesCfb.Id] = "DES/CFB";
            _algorithms[OiwObjectIdentifiers.DesEcb.Id] = "DES/ECB";
            _algorithms[OiwObjectIdentifiers.DesOfb.Id] = "DES/OFB";
            _algorithms[OiwObjectIdentifiers.DesEde.Id] = "DESEDE";
            _algorithms[PkcsObjectIdentifiers.DesEde3Cbc.Id] = "DESEDE/CBC";
            _algorithms[PkcsObjectIdentifiers.RC2Cbc.Id] = "RC2/CBC";
            _algorithms["1.3.6.1.4.1.188.7.1.1.2"] = "IDEA/CBC";
            _algorithms["1.2.840.113533.7.66.10"] = "CAST5/CBC";

            _algorithms["RC4"] = "ARC4";
            _algorithms["ARCFOUR"] = "ARC4";
            _algorithms["1.2.840.113549.3.4"] = "ARC4";


            _algorithms["PBEWITHSHA1AND128BITRC4"] = "PBEWITHSHAAND128BITRC4";
            _algorithms[PkcsObjectIdentifiers.PbeWithShaAnd128BitRC4.Id] = "PBEWITHSHAAND128BITRC4";
            _algorithms["PBEWITHSHA1AND40BITRC4"] = "PBEWITHSHAAND40BITRC4";
            _algorithms[PkcsObjectIdentifiers.PbeWithShaAnd40BitRC4.Id] = "PBEWITHSHAAND40BITRC4";

            _algorithms["PBEWITHSHA1ANDDES"] = "PBEWITHSHA1ANDDES-CBC";
            _algorithms[PkcsObjectIdentifiers.PbeWithSha1AndDesCbc.Id] = "PBEWITHSHA1ANDDES-CBC";
            _algorithms["PBEWITHSHA1ANDRC2"] = "PBEWITHSHA1ANDRC2-CBC";
            _algorithms[PkcsObjectIdentifiers.PbeWithSha1AndRC2Cbc.Id] = "PBEWITHSHA1ANDRC2-CBC";

            _algorithms["PBEWITHSHA1AND3-KEYTRIPLEDES-CBC"] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
            _algorithms["PBEWITHSHAAND3KEYTRIPLEDES"] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
            _algorithms[PkcsObjectIdentifiers.PbeWithShaAnd3KeyTripleDesCbc.Id] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";
            _algorithms["PBEWITHSHA1ANDDESEDE"] = "PBEWITHSHAAND3-KEYTRIPLEDES-CBC";

            _algorithms["PBEWITHSHA1AND2-KEYTRIPLEDES-CBC"] = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";
            _algorithms[PkcsObjectIdentifiers.PbeWithShaAnd2KeyTripleDesCbc.Id] = "PBEWITHSHAAND2-KEYTRIPLEDES-CBC";

            _algorithms["PBEWITHSHA1AND128BITRC2-CBC"] = "PBEWITHSHAAND128BITRC2-CBC";
            _algorithms[PkcsObjectIdentifiers.PbeWithShaAnd128BitRC2Cbc.Id] = "PBEWITHSHAAND128BITRC2-CBC";

            _algorithms["PBEWITHSHA1AND40BITRC2-CBC"] = "PBEWITHSHAAND40BITRC2-CBC";
            _algorithms[PkcsObjectIdentifiers.PbewithShaAnd40BitRC2Cbc.Id] = "PBEWITHSHAAND40BITRC2-CBC";

            _algorithms["PBEWITHSHA1AND128BITAES-CBC-BC"] = "PBEWITHSHAAND128BITAES-CBC-BC";
            _algorithms["PBEWITHSHA-1AND128BITAES-CBC-BC"] = "PBEWITHSHAAND128BITAES-CBC-BC";

            _algorithms["PBEWITHSHA1AND192BITAES-CBC-BC"] = "PBEWITHSHAAND192BITAES-CBC-BC";
            _algorithms["PBEWITHSHA-1AND192BITAES-CBC-BC"] = "PBEWITHSHAAND192BITAES-CBC-BC";

            _algorithms["PBEWITHSHA1AND256BITAES-CBC-BC"] = "PBEWITHSHAAND256BITAES-CBC-BC";
            _algorithms["PBEWITHSHA-1AND256BITAES-CBC-BC"] = "PBEWITHSHAAND256BITAES-CBC-BC";

            _algorithms["PBEWITHSHA-256AND128BITAES-CBC-BC"] = "PBEWITHSHA256AND128BITAES-CBC-BC";
            _algorithms["PBEWITHSHA-256AND192BITAES-CBC-BC"] = "PBEWITHSHA256AND192BITAES-CBC-BC";
            _algorithms["PBEWITHSHA-256AND256BITAES-CBC-BC"] = "PBEWITHSHA256AND256BITAES-CBC-BC";


            _algorithms["GOST"] = "GOST28147";
            _algorithms["GOST-28147"] = "GOST28147";
            _algorithms[CryptoProObjectIdentifiers.GostR28147Cbc.Id] = "GOST28147/CBC/PKCS7PADDING";

            _algorithms["RC5-32"] = "RC5";

            _algorithms[NttObjectIdentifiers.IdCamellia128Cbc.Id] = "CAMELLIA/CBC/PKCS7PADDING";
            _algorithms[NttObjectIdentifiers.IdCamellia192Cbc.Id] = "CAMELLIA/CBC/PKCS7PADDING";
            _algorithms[NttObjectIdentifiers.IdCamellia256Cbc.Id] = "CAMELLIA/CBC/PKCS7PADDING";

            _algorithms[KisaObjectIdentifiers.IdSeedCbc.Id] = "SEED/CBC/PKCS7PADDING";

            _algorithms["1.3.6.1.4.1.3029.1.2"] = "BLOWFISH/CBC";
        }

        public static ICollection Algorithms
        {
            get { return _oids.Keys; }
        }

        /// <summary>
        ///     Returns a ObjectIdentifier for a give encoding.
        /// </summary>
        /// <param name="mechanism">A string representation of the encoding.</param>
        /// <returns>A DerObjectIdentifier, null if the Oid is not available.</returns>
        // TODO Don't really want to support this
        public static DerObjectIdentifier GetObjectIdentifier(string mechanism)
        {
            if (mechanism == null)
                throw new ArgumentNullException("mechanism");

            mechanism = mechanism.ToUpper(CultureInfo.InvariantCulture);
            var aliased = (string) _algorithms[mechanism];

            if (aliased != null)
                mechanism = aliased;

            return (DerObjectIdentifier) _oids[mechanism];
        }

        public static IBufferedCipher GetCipher(DerObjectIdentifier oid)
        {
            return GetCipher(oid.Id);
        }

        public static IBufferedCipher GetCipher(string algorithm)
        {
            if (algorithm == null)
                throw new ArgumentNullException("algorithm");

            algorithm = algorithm.ToUpper(CultureInfo.InvariantCulture);

            var aliased = (string) _algorithms[algorithm];

            if (aliased != null)
                algorithm = aliased;


            IBasicAgreement iesAgreement = null;
            switch (algorithm)
            {
                case "IES":
                    iesAgreement = new DHBasicAgreement();
                    break;
                case "ECIES":
                    iesAgreement = new EcdhBasicAgreement();
                    break;
            }

            if (iesAgreement != null)
            {
                return new BufferedIesCipher(
                    new IesEngine(
                        iesAgreement,
                        new Kdf2BytesGenerator(
                            new Sha1Digest()),
                        new HMac(
                            new Sha1Digest())));
            }


            if (algorithm.StartsWith("PBE"))
            {
                if (algorithm.EndsWith("-CBC"))
                {
                    if (algorithm == "PBEWITHSHA1ANDDES-CBC")
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new DesEngine()));
                    }
                    if (algorithm == "PBEWITHSHA1ANDRC2-CBC")
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new RC2Engine()));
                    }
                    if (Strings.IsOneOf(algorithm,
                                        "PBEWITHSHAAND2-KEYTRIPLEDES-CBC", "PBEWITHSHAAND3-KEYTRIPLEDES-CBC"))
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new DesEdeEngine()));
                    }
                    if (Strings.IsOneOf(algorithm,
                                        "PBEWITHSHAAND128BITRC2-CBC", "PBEWITHSHAAND40BITRC2-CBC"))
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new RC2Engine()));
                    }
                }
                else if (algorithm.EndsWith("-BC") || algorithm.EndsWith("-OPENSSL"))
                {
                    if (Strings.IsOneOf(algorithm,
                                        "PBEWITHSHAAND128BITAES-CBC-BC",
                                        "PBEWITHSHAAND192BITAES-CBC-BC",
                                        "PBEWITHSHAAND256BITAES-CBC-BC",
                                        "PBEWITHSHA256AND128BITAES-CBC-BC",
                                        "PBEWITHSHA256AND192BITAES-CBC-BC",
                                        "PBEWITHSHA256AND256BITAES-CBC-BC",
                                        "PBEWITHMD5AND128BITAES-CBC-OPENSSL",
                                        "PBEWITHMD5AND192BITAES-CBC-OPENSSL",
                                        "PBEWITHMD5AND256BITAES-CBC-OPENSSL"))
                    {
                        return new PaddedBufferedBlockCipher(
                            new CbcBlockCipher(new AesFastEngine()));
                    }
                }
            }


            var parts = algorithm.Split('/');

            IBlockCipher blockCipher = null;
            IAsymmetricBlockCipher asymBlockCipher = null;
            IStreamCipher streamCipher = null;

            var algorithmName = parts[0];
            CipherAlgorithm cipherAlgorithm;
            try
            {
                cipherAlgorithm = (CipherAlgorithm) Enums.GetEnumValue(typeof (CipherAlgorithm), algorithmName);
            }
            catch (ArgumentException)
            {
                throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
            }

            switch (cipherAlgorithm)
            {
                case CipherAlgorithm.AES:
                    blockCipher = new AesFastEngine();
                    break;
                case CipherAlgorithm.ARC4:
                    streamCipher = new RC4Engine();
                    break;
                case CipherAlgorithm.BLOWFISH:
                    blockCipher = new BlowfishEngine();
                    break;
                case CipherAlgorithm.CAMELLIA:
                    blockCipher = new CamelliaEngine();
                    break;
                case CipherAlgorithm.CAST5:
                    blockCipher = new Cast5Engine();
                    break;
                case CipherAlgorithm.CAST6:
                    blockCipher = new Cast6Engine();
                    break;
                case CipherAlgorithm.DES:
                    blockCipher = new DesEngine();
                    break;
                case CipherAlgorithm.DESEDE:
                    blockCipher = new DesEdeEngine();
                    break;
                case CipherAlgorithm.ELGAMAL:
                    asymBlockCipher = new ElGamalEngine();
                    break;
                case CipherAlgorithm.GOST28147:
                    blockCipher = new Gost28147Engine();
                    break;
                case CipherAlgorithm.HC128:
                    streamCipher = new HC128Engine();
                    break;
                case CipherAlgorithm.HC256:
                    streamCipher = new HC256Engine();
                    break;

                case CipherAlgorithm.IDEA:
#if INCLUDE_IDEA				
					blockCipher = new IdeaEngine();
                    break;
#else
                    throw new SecurityUtilityException("Cipher " + algorithm + " not included.");
#endif                    
                case CipherAlgorithm.NOEKEON:
                    blockCipher = new NoekeonEngine();
                    break;
                case CipherAlgorithm.PBEWITHSHAAND128BITRC4:
                case CipherAlgorithm.PBEWITHSHAAND40BITRC4:
                    streamCipher = new RC4Engine();
                    break;
                case CipherAlgorithm.RC2:
                    blockCipher = new RC2Engine();
                    break;
                case CipherAlgorithm.RC5:
                    blockCipher = new RC532Engine();
                    break;
                case CipherAlgorithm.RC5_64:
                    blockCipher = new RC564Engine();
                    break;
                case CipherAlgorithm.RC6:
                    blockCipher = new RC6Engine();
                    break;
                case CipherAlgorithm.RIJNDAEL:
                    blockCipher = new RijndaelEngine();
                    break;
                case CipherAlgorithm.RSA:
                    asymBlockCipher = new RsaBlindedEngine();
                    break;
                case CipherAlgorithm.SALSA20:
                    streamCipher = new Salsa20Engine();
                    break;
                case CipherAlgorithm.SEED:
                    blockCipher = new SeedEngine();
                    break;
                case CipherAlgorithm.SERPENT:
                    blockCipher = new SerpentEngine();
                    break;
                case CipherAlgorithm.SKIPJACK:
                    blockCipher = new SkipjackEngine();
                    break;
                case CipherAlgorithm.TEA:
                    blockCipher = new TeaEngine();
                    break;
                case CipherAlgorithm.TWOFISH:
                    blockCipher = new TwofishEngine();
                    break;
                case CipherAlgorithm.VMPC:
                    streamCipher = new VmpcEngine();
                    break;
                case CipherAlgorithm.VMPC_KSA3:
                    streamCipher = new VmpcKsa3Engine();
                    break;
                case CipherAlgorithm.XTEA:
                    blockCipher = new XteaEngine();
                    break;
                default:
                    throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
            }

            if (streamCipher != null)
            {
                if (parts.Length > 1)
                    throw new ArgumentException("Modes and paddings not used for stream ciphers");

                return new BufferedStreamCipher(streamCipher);
            }


            var cts = false;
            var padded = true;
            IBlockCipherPadding padding = null;
            IAeadBlockCipher aeadBlockCipher = null;

            if (parts.Length > 2)
            {
                var paddingName = parts[2];

                CipherPadding cipherPadding;
                switch (paddingName)
                {
                    case "":
                        cipherPadding = CipherPadding.RAW;
                        break;
                    case "X9.23PADDING":
                        cipherPadding = CipherPadding.X923PADDING;
                        break;
                    default:
                        try
                        {
                            cipherPadding = (CipherPadding) Enums.GetEnumValue(typeof (CipherPadding), paddingName);
                        }
                        catch (ArgumentException)
                        {
                            throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
                        }
                        break;                        
                }

                switch (cipherPadding)
                {
                    case CipherPadding.NOPADDING:
                        padded = false;
                        break;
                    case CipherPadding.RAW:
                        break;
                    case CipherPadding.ISO10126PADDING:
                    case CipherPadding.ISO10126D2PADDING:
                    case CipherPadding.ISO10126_2PADDING:
                        padding = new ISO10126d2Padding();
                        break;
                    case CipherPadding.ISO7816_4PADDING:
                    case CipherPadding.ISO9797_1PADDING:
                        padding = new ISO7816d4Padding();
                        break;
                    case CipherPadding.ISO9796_1:
                    case CipherPadding.ISO9796_1PADDING:
                        asymBlockCipher = new ISO9796d1Encoding(asymBlockCipher);
                        break;
                    case CipherPadding.OAEP:
                    case CipherPadding.OAEPPADDING:
                        asymBlockCipher = new OaepEncoding(asymBlockCipher);
                        break;
                    case CipherPadding.OAEPWITHMD5ANDMGF1PADDING:
                        asymBlockCipher = new OaepEncoding(asymBlockCipher, new MD5Digest());
                        break;
                    case CipherPadding.OAEPWITHSHA1ANDMGF1PADDING:
                    case CipherPadding.OAEPWITHSHA_1ANDMGF1PADDING:
                        asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha1Digest());
                        break;
                    case CipherPadding.OAEPWITHSHA224ANDMGF1PADDING:
                    case CipherPadding.OAEPWITHSHA_224ANDMGF1PADDING:
                        asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha224Digest());
                        break;
                    case CipherPadding.OAEPWITHSHA256ANDMGF1PADDING:
                    case CipherPadding.OAEPWITHSHA_256ANDMGF1PADDING:
                        asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha256Digest());
                        break;
                    case CipherPadding.OAEPWITHSHA384ANDMGF1PADDING:
                    case CipherPadding.OAEPWITHSHA_384ANDMGF1PADDING:
                        asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha384Digest());
                        break;
                    case CipherPadding.OAEPWITHSHA512ANDMGF1PADDING:
                    case CipherPadding.OAEPWITHSHA_512ANDMGF1PADDING:
                        asymBlockCipher = new OaepEncoding(asymBlockCipher, new Sha512Digest());
                        break;
                    case CipherPadding.PKCS1:
                    case CipherPadding.PKCS1PADDING:
                        asymBlockCipher = new Pkcs1Encoding(asymBlockCipher);
                        break;
                    case CipherPadding.PKCS5:
                    case CipherPadding.PKCS5PADDING:
                    case CipherPadding.PKCS7:
                    case CipherPadding.PKCS7PADDING:
                        padding = new Pkcs7Padding();
                        break;
                    case CipherPadding.TBCPADDING:
                        padding = new TbcPadding();
                        break;
                    case CipherPadding.WITHCTS:
                        cts = true;
                        break;
                    case CipherPadding.X923PADDING:
                        padding = new X923Padding();
                        break;
                    case CipherPadding.ZEROBYTEPADDING:
                        padding = new ZeroBytePadding();
                        break;
                    default:
                        throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
                }
            }

            if (parts.Length > 1)
            {
                var mode = parts[1];

                var di = GetDigitIndex(mode);
                var modeName = di >= 0 ? mode.Substring(0, di) : mode;

                try
                {
                    var cipherMode = modeName == ""
                        ? CipherMode.NONE
                        : (CipherMode) Enums.GetEnumValue(typeof (CipherMode), modeName);

                    switch (cipherMode)
                    {
                        case CipherMode.ECB:
                        case CipherMode.NONE:
                            break;
                        case CipherMode.CBC:
                            blockCipher = new CbcBlockCipher(blockCipher);
                            break;
                        case CipherMode.CCM:
                            aeadBlockCipher = new CcmBlockCipher(blockCipher);
                            break;
                        case CipherMode.CFB:
                            {
                                var bits = (di < 0)
                                               ? 8*blockCipher.GetBlockSize()
                                               : int.Parse(mode.Substring(di));

                                blockCipher = new CfbBlockCipher(blockCipher, bits);
                                break;
                            }
                        case CipherMode.CTR:
                            blockCipher = new SicBlockCipher(blockCipher);
                            break;
                        case CipherMode.CTS:
                            cts = true;
                            blockCipher = new CbcBlockCipher(blockCipher);
                            break;
                        case CipherMode.EAX:
                            aeadBlockCipher = new EaxBlockCipher(blockCipher);
                            break;
                        case CipherMode.GCM:
                            aeadBlockCipher = new GcmBlockCipher(blockCipher);
                            break;
                        case CipherMode.GOFB:
                            blockCipher = new GOfbBlockCipher(blockCipher);
                            break;
                        case CipherMode.OFB:
                            {
                                var bits = (di < 0)
                                               ? 8*blockCipher.GetBlockSize()
                                               : int.Parse(mode.Substring(di));

                                blockCipher = new OfbBlockCipher(blockCipher, bits);
                                break;
                            }
                        case CipherMode.OPENPGPCFB:
                            blockCipher = new OpenPgpCfbBlockCipher(blockCipher);
                            break;
                        case CipherMode.SIC:
                            if (blockCipher.GetBlockSize() < 16)
                            {
                                throw new ArgumentException(
                                    "Warning: SIC-Mode can become a twotime-pad if the blocksize of the cipher is too small. Use a cipher with a block size of at least 128 bits (e.g. AES)");
                            }
                            blockCipher = new SicBlockCipher(blockCipher);
                            break;
                        default:
                            throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
                    }
                }
                catch (ArgumentException)
                {
                    throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
                }
            }

            if (aeadBlockCipher != null)
            {
                if (cts)
                    throw new SecurityUtilityException("CTS mode not valid for AEAD ciphers.");
                if (padded && parts.Length > 2 && parts[2] != "")
                    throw new SecurityUtilityException("Bad padding specified for AEAD cipher.");

                return new BufferedAeadBlockCipher(aeadBlockCipher);
            }

            if (blockCipher != null)
            {
                if (cts)
                {
                    return new CtsBlockCipher(blockCipher);
                }

                if (padding != null)
                {
                    return new PaddedBufferedBlockCipher(blockCipher, padding);
                }

                if (!padded || blockCipher.IsPartialBlockOkay)
                {
                    return new BufferedBlockCipher(blockCipher);
                }

                return new PaddedBufferedBlockCipher(blockCipher);
            }

            if (asymBlockCipher != null)
            {
                return new BufferedAsymmetricBlockCipher(asymBlockCipher);
            }

            throw new SecurityUtilityException("Cipher " + algorithm + " not recognised.");
        }

        public static string GetAlgorithmName(DerObjectIdentifier oid)
        {
            return (string) _algorithms[oid.Id];
        }

        private static int GetDigitIndex(string s)
        {
            for (var i = 0; i < s.Length; ++i)
            {
                if (char.IsDigit(s[i]))
                    return i;
            }

            return -1;
        }

        // ReSharper disable InconsistentNaming
        private enum CipherAlgorithm
        {
            AES,
            ARC4,
            BLOWFISH,
            CAMELLIA,
            CAST5,
            CAST6,
            DES,
            DESEDE,
            ELGAMAL,
            GOST28147,
            HC128,
            HC256,
            IDEA,
            NOEKEON,
            PBEWITHSHAAND128BITRC4,
            PBEWITHSHAAND40BITRC4,
            RC2,
            RC5,
            RC5_64,
            RC6,
            RIJNDAEL,
            RSA,
            SALSA20,
            SEED,
            SERPENT,
            SKIPJACK,
            TEA,
            TWOFISH,
            VMPC,
            VMPC_KSA3,
            XTEA,
        };

        private enum CipherMode
        {
            ECB,
            NONE,
            CBC,
            CCM,
            CFB,
            CTR,
            CTS,
            EAX,
            GCM,
            GOFB,
            OFB,
            OPENPGPCFB,
            SIC
        };

        private enum CipherPadding
        {
            NOPADDING,
            RAW,
            ISO10126PADDING,
            ISO10126D2PADDING,
            ISO10126_2PADDING,
            ISO7816_4PADDING,
            ISO9797_1PADDING,
            ISO9796_1,
            ISO9796_1PADDING,
            OAEP,
            OAEPPADDING,
            OAEPWITHMD5ANDMGF1PADDING,
            OAEPWITHSHA1ANDMGF1PADDING,
            OAEPWITHSHA_1ANDMGF1PADDING,
            OAEPWITHSHA224ANDMGF1PADDING,
            OAEPWITHSHA_224ANDMGF1PADDING,
            OAEPWITHSHA256ANDMGF1PADDING,
            OAEPWITHSHA_256ANDMGF1PADDING,
            OAEPWITHSHA384ANDMGF1PADDING,
            OAEPWITHSHA_384ANDMGF1PADDING,
            OAEPWITHSHA512ANDMGF1PADDING,
            OAEPWITHSHA_512ANDMGF1PADDING,
            PKCS1,
            PKCS1PADDING,
            PKCS5,
            PKCS5PADDING,
            PKCS7,
            PKCS7PADDING,
            TBCPADDING,
            WITHCTS,
            X923PADDING,
            ZEROBYTEPADDING,
        };
        // ReSharper restore InconsistentNaming
    }
}